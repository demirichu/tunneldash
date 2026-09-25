using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

// --- AUTOMATED TEST RUNNER (CLI) ---
if (args.Contains("--test"))
{
    var exitCode = IptablesTestRunner.RunAllTests();
    Environment.Exit(exitCode);
}

var builder = WebApplication.CreateSlimBuilder(args);

// --- STARTUP CONFIG & VALIDATION ---
const long SESSION_TTL_SEC = 365 * 24 * 3600; // 1 year
var passPhrase = Environment.GetEnvironmentVariable("PASS_PHRASE");
if (string.IsNullOrWhiteSpace(passPhrase) || passPhrase.Length < 12)
{
    Console.WriteLine("[FATAL ERROR] PASS_PHRASE must be set and contain at least 12 characters.");
    Environment.Exit(1);
}

var targetIpParam = Environment.GetEnvironmentVariable("TARGET_IP") ?? "10.0.0.2";
if (!IPAddress.TryParse(targetIpParam, out var parsedTarget) || parsedTarget.AddressFamily != AddressFamily.InterNetwork)
{
    Console.WriteLine($"[FATAL ERROR] TARGET_IP '{targetIpParam}' is not a valid IPv4 address.");
    Environment.Exit(1);
}

var portRangeParam = Environment.GetEnvironmentVariable("PORT_RANGE") ?? "4402-4420";
var allowedPorts = Iptables.ParseAllowedPorts(portRangeParam, Iptables.MaxPortLimit);
if (allowedPorts.Length == 0)
{
    Console.WriteLine($"[FATAL ERROR] PORT_RANGE '{portRangeParam}' contains no valid ports.");
    Environment.Exit(1);
}
if (allowedPorts.Length > Iptables.MaxPortLimit)
{
    Console.WriteLine($"[FATAL ERROR] PORT_RANGE '{portRangeParam}' exceeds maximum allowed limit of {Iptables.MaxPortLimit} ports.");
    Environment.Exit(1);
}

var preserveClientIpParam = Environment.GetEnvironmentVariable("PRESERVE_CLIENT_IP") ?? "true";
bool preserveClientIp = preserveClientIpParam.Trim().ToLowerInvariant() is not ("false" or "0");
string defaultNatMode = preserveClientIp ? "preserve" : "masq";

var privateInterface = Environment.GetEnvironmentVariable("PRIVATE_INTERFACE") ?? "wg0";
if (string.IsNullOrWhiteSpace(privateInterface) || privateInterface.Length > 16 || !privateInterface.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '+'))
{
    Console.WriteLine($"[FATAL ERROR] PRIVATE_INTERFACE '{privateInterface}' is not a valid network interface name.");
    Environment.Exit(1);
}

builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        
        if (context.Request.Path == "/api/login")
        {
            return RateLimitPartition.GetFixedWindowLimiter($"{ip}-login", _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromSeconds(10),
                PermitLimit = 5,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            });
        }
        
        return RateLimitPartition.GetFixedWindowLimiter($"{ip}-action", _ => new FixedWindowRateLimiterOptions
        {
            Window = TimeSpan.FromSeconds(10),
            PermitLimit = 30,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    });
    options.RejectionStatusCode = 429;
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var app = builder.Build();
app.UseRateLimiter();

await Iptables.EnsureBaseRules(targetIpParam, privateInterface);

var iptablesLock = new SemaphoreSlim(1, 1);
var masterKeyBytes = Encoding.UTF8.GetBytes(passPhrase);

var authEpochFile = Path.Combine(AppContext.BaseDirectory, ".auth_generation");
long authEpoch = LoadAuthGeneration(authEpochFile);
var authFileLock = new object();

// --- CSRF & AUTH MIDDLEWARE ---
app.Use(async (context, next) =>
{
    if ((HttpMethods.IsPost(context.Request.Method) || HttpMethods.IsPut(context.Request.Method)) && context.Request.Path.StartsWithSegments("/api"))
    {
        if (context.Request.Headers.TryGetValue("Sec-Fetch-Site", out var secFetchSite) && secFetchSite == "cross-site")
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new ErrorResponse("Cross-site request forbidden."), AppJsonSerializerContext.Default.ErrorResponse);
            return;
        }

        if (context.Request.Headers.TryGetValue("Origin", out var originHeader) && !string.IsNullOrEmpty(originHeader))
        {
            if (!Uri.TryCreate(originHeader.ToString(), UriKind.Absolute, out var originUri))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new ErrorResponse("Malformed Origin header."), AppJsonSerializerContext.Default.ErrorResponse);
                return;
            }

            var requestAuthority = context.Request.Host.Value;
            var originAuthority = originUri.Authority;

            if (!string.Equals(originAuthority, requestAuthority, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new ErrorResponse("Origin mismatch forbidden."), AppJsonSerializerContext.Default.ErrorResponse);
                return;
            }
        }
    }

    if (context.Request.Path.StartsWithSegments("/api") && context.Request.Path != "/api/login")
    {
        bool isAuthorized = false;

        if (context.Request.Cookies.TryGetValue("TunnelSession", out var token) && !string.IsNullOrWhiteSpace(token))
        {
            var parts = token.Split('.');
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (parts.Length == 5 && 
                long.TryParse(parts[0], out long exp) && 
                long.TryParse(parts[1], out long iat) && 
                long.TryParse(parts[2], out long tokenEpoch) &&
                tokenEpoch >= Interlocked.Read(ref authEpoch) &&
                exp > now)
            {
                string nonce = parts[3];
                string payload = $"{exp}.{iat}.{tokenEpoch}.{nonce}";

                var expectedHash = HMACSHA256.HashData(masterKeyBytes, Encoding.UTF8.GetBytes(payload));
                Span<byte> actualHash = stackalloc byte[64];

                if (Convert.TryFromBase64String(parts[4], actualHash, out int bytesParsed) &&
                    CryptographicOperations.FixedTimeEquals(expectedHash, actualHash.Slice(0, bytesParsed)))
                {
                    isAuthorized = true;
                }
            }
        }

        if (!isAuthorized)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new ErrorResponse("Unauthorized session."), AppJsonSerializerContext.Default.ErrorResponse);
            return;
        }
    }

    await next(context);
});

app.MapGet("/", (HttpContext _) =>
{
    var htmlPath = Path.Combine(Directory.GetCurrentDirectory(), "index.html");
    if (!File.Exists(htmlPath)) return Results.NotFound("index.html not found.");
    return Results.File(htmlPath, "text/html");
});

app.MapPost("/api/login", (HttpContext ctx, LoginRequest req) =>
{
    if (string.IsNullOrEmpty(req.passphrase)) return Results.Unauthorized();

    var inputHash = CryptographicOperations.HashData(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(req.passphrase));
    var realHash = CryptographicOperations.HashData(HashAlgorithmName.SHA256, masterKeyBytes);
    
    if (CryptographicOperations.FixedTimeEquals(inputHash, realHash))
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long expiresUnix = now + SESSION_TTL_SEC;
        long currentEpoch = Interlocked.Read(ref authEpoch);
        string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        
        string payload = $"{expiresUnix}.{now}.{currentEpoch}.{nonce}";
        var signature = HMACSHA256.HashData(masterKeyBytes, Encoding.UTF8.GetBytes(payload));
        string sessionToken = $"{payload}.{Convert.ToBase64String(signature)}";

        ctx.Response.Cookies.Append("TunnelSession", sessionToken, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = ctx.Request.IsHttps, 
            Expires = DateTimeOffset.UtcNow.AddSeconds(SESSION_TTL_SEC)
        });

        return Results.Ok(new ActionResponse("Authenticated"));
    }

    return Results.Unauthorized();
});

app.MapPost("/api/logout", (HttpContext ctx) =>
{
    lock (authFileLock)
    {
        long targetEpoch = Interlocked.Read(ref authEpoch) + 1;

        if (!TrySaveAuthGeneration(authEpochFile, targetEpoch))
        {
            return Results.Problem(
                "Session revocation could not be persisted.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        Interlocked.Exchange(ref authEpoch, targetEpoch);
    }

    ctx.Response.Cookies.Delete("TunnelSession");
    return Results.Ok(new ActionResponse("Logged out"));
});

app.MapGet("/api/status", async (HttpContext _) => 
{
    var publicIp = await Iptables.ResolvePublicIpAsync();
    var natDisplay = defaultNatMode.ToUpperInvariant();
    return Results.Ok(new StatusResponse("ONLINE", $"GATEWAY // TARGET: {targetIpParam} ({privateInterface}) // DEFAULT_NAT: {natDisplay}", publicIp, allowedPorts, defaultNatMode));
});

app.MapGet("/api/rules", async (HttpContext _) => 
{
    var preResult = await Iptables.Run(new List<string> { "-w", "5", "-t", "nat", "-S", "PREROUTING" });
    if (!preResult.Success) return Results.Problem("Failed to read PREROUTING routing rules.", statusCode: 500);

    var postResult = await Iptables.Run(new List<string> { "-w", "5", "-t", "nat", "-S", "POSTROUTING" });
    string postOutput = postResult.Success ? postResult.Output : "";

    var rules = Iptables.ParseRules(preResult.Output, postOutput, targetIpParam);
    return Results.Ok(new RulesResponse(rules));
});

app.MapPost("/api/forward", async (PortRequest req) =>
{
    if (!Iptables.ValidatePorts(req.inPort, req.outPort, allowedPorts))
        return Results.BadRequest(new ErrorResponse("Invalid port or port outside allowed pool."));

    var protocols = Iptables.ResolveProtocols(req.protocol);
    if (protocols is null or { Length: 0 }) return Results.BadRequest(new ErrorResponse("Invalid protocol."));

    if (!Iptables.TryResolveNatMode(req.natMode, preserveClientIp, out var ruleNatMode))
        return Results.BadRequest(new ErrorResponse("Invalid NAT mode. Supported values: preserve, masq."));

    if (!await iptablesLock.WaitAsync(TimeSpan.FromSeconds(5)))
        return Results.Problem("System busy.", statusCode: 503);

    int addedCount = 0;
    var addedDnat = new List<string>();
    var addedFwd = new List<string>();
    var addedMasq = new List<string>();
    bool hasFailure = false;

    try
    {
        foreach (var proto in protocols)
        {
            var checkDnat = new List<string> { "-t", "nat", "-w", "-C", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
            if ((await Iptables.Run(checkDnat)).ExitCode != 0) 
            {
                var addDnat = new List<string> { "-t", "nat", "-w", "-A", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
                var dnatRes = await Iptables.Run(addDnat);
                if (!dnatRes.Success)
                {
                    hasFailure = true;
                    break;
                }
                addedDnat.Add(proto);
                addedCount++;
            }

            var checkFwd = new List<string> { "-w", "-C", "FORWARD", "-p", proto, "-d", targetIpParam, "--dport", req.outPort.ToString(), "-j", "ACCEPT" };
            if ((await Iptables.Run(checkFwd)).ExitCode != 0)
            {
                var addFwd = new List<string> { "-w", "-A", "FORWARD", "-p", proto, "-d", targetIpParam, "--dport", req.outPort.ToString(), "-j", "ACCEPT" };
                var fwdRes = await Iptables.Run(addFwd);
                if (!fwdRes.Success)
                {
                    hasFailure = true;
                    break;
                }
                addedFwd.Add(proto);
            }

            if (ruleNatMode == "masq")
            {
                var checkMasq = Iptables.BuildMasqArgs("-C", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                if ((await Iptables.Run(checkMasq)).ExitCode != 0)
                {
                    var addMasq = Iptables.BuildMasqArgs("-A", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                    var masqRes = await Iptables.Run(addMasq);
                    if (!masqRes.Success)
                    {
                        hasFailure = true;
                        break;
                    }
                    addedMasq.Add(proto);
                }
            }
        }

        if (hasFailure)
        {
            // Transaction rollback: remove any rules applied during this request
            foreach (var proto in addedMasq)
            {
                var delMasq = Iptables.BuildMasqArgs("-D", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                await Iptables.Run(delMasq);
            }
            foreach (var proto in addedDnat)
            {
                var delDnat = new List<string> { "-t", "nat", "-w", "-D", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
                await Iptables.Run(delDnat);
            }
            foreach (var proto in addedFwd)
            {
                await Iptables.DeleteForwardIfOrphanAsync(proto, targetIpParam, req.outPort);
            }
            return Results.Problem("Failed to apply firewall rules. Transaction rolled back.", statusCode: 500);
        }
    }
    finally { iptablesLock.Release(); }
    
    if (addedCount > 0)
    {
        bool saved = await Iptables.SaveRulesAsync();
        if (!saved)
        {
            Console.WriteLine("[WARNING] Route was applied to kernel, but atomic persistence to rules.v4 failed.");
        }
        return Results.Ok(new ActionResponse("Route successfully added."));
    }

    return Results.BadRequest(new ErrorResponse("Rule already exists."));
});

app.MapPut("/api/forward", async (UpdateRuleRequest req) =>
{
    // 1. Validate new ports
    if (!Iptables.ValidatePorts(req.inPort, req.outPort, allowedPorts))
        return Results.BadRequest(new ErrorResponse("Invalid port or port outside allowed pool."));

    // 2. Validate protocols
    var oldProtocols = Iptables.ResolveProtocols(req.oldProtocol);
    if (oldProtocols is null or { Length: 0 })
        return Results.BadRequest(new ErrorResponse("Invalid old protocol."));

    var newProtocols = Iptables.ResolveProtocols(req.protocol);
    if (newProtocols is null or { Length: 0 })
        return Results.BadRequest(new ErrorResponse("Invalid new protocol."));

    // 3. Resolve natMode
    if (!Iptables.TryResolveNatMode(req.natMode, preserveClientIp, out var newNatMode))
        return Results.BadRequest(new ErrorResponse("Invalid NAT mode. Supported values: preserve, masq."));

    if (!await iptablesLock.WaitAsync(TimeSpan.FromSeconds(5)))
        return Results.Problem("System busy.", statusCode: 503);

    try
    {
        // 4. Verify existing state in iptables
        var preCheck = await Iptables.Run(new List<string> { "-w", "5", "-t", "nat", "-S", "PREROUTING" });
        if (!preCheck.Success) return Results.Problem("Failed to read routing state.", statusCode: 500);

        var existingRules = Iptables.ParseRules(preCheck.Output, "", targetIpParam);
        
        bool oldExists = existingRules.Any(r => 
            r.InPort == req.oldInPort.ToString() && 
            r.OutPort == req.oldOutPort.ToString() &&
            ((r.Tcp && oldProtocols.Contains("tcp")) || (r.Udp && oldProtocols.Contains("udp"))));

        if (!oldExists && !OperatingSystem.IsWindows())
            return Results.BadRequest(new ErrorResponse("Target rule to edit was not found in routing tables."));

        // 5. Conflict check: make sure new (inPort, protocol) is not taken by another rule
        if (Iptables.HasConflict(existingRules, req.oldInPort, req.oldOutPort, req.inPort, newProtocols))
        {
            return Results.BadRequest(new ErrorResponse($"Public port {req.inPort} is already in use by another forwarding route."));
        }

        // 6. Check which old protocols had MASQ active
        var oldMasqProtocols = new List<string>();
        foreach (var proto in oldProtocols)
        {
            var checkOldMasq = Iptables.BuildMasqArgs("-C", privateInterface, proto, targetIpParam, req.oldOutPort, req.oldInPort);
            if ((await Iptables.Run(checkOldMasq)).ExitCode == 0)
            {
                oldMasqProtocols.Add(proto);
            }
        }

        // 7. Atomic transaction: remove old, add new; if add fails, restore old completely!
        var removedOldDnat = new List<string>();
        var removedOldFwd = new List<string>();
        var removedOldMasq = new List<string>();

        foreach (var proto in oldProtocols)
        {
            var checkDnat = new List<string> { "-t", "nat", "-w", "-C", "PREROUTING", "-p", proto, "--dport", req.oldInPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.oldOutPort}" };
            if ((await Iptables.Run(checkDnat)).ExitCode == 0)
            {
                var delDnat = new List<string> { "-t", "nat", "-w", "-D", "PREROUTING", "-p", proto, "--dport", req.oldInPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.oldOutPort}" };
                if ((await Iptables.Run(delDnat)).Success)
                {
                    removedOldDnat.Add(proto);
                    if (oldMasqProtocols.Contains(proto))
                    {
                        var delMasq = Iptables.BuildMasqArgs("-D", privateInterface, proto, targetIpParam, req.oldOutPort, req.oldInPort);
                        if ((await Iptables.Run(delMasq)).Success)
                        {
                            removedOldMasq.Add(proto);
                        }
                    }
                    await Iptables.DeleteForwardIfOrphanAsync(proto, targetIpParam, req.oldOutPort);
                    removedOldFwd.Add(proto);
                }
            }
        }

        // Add new rules
        var addedNewDnat = new List<string>();
        var addedNewFwd = new List<string>();
        var addedNewMasq = new List<string>();
        bool addFailed = false;

        foreach (var proto in newProtocols)
        {
            var addDnat = new List<string> { "-t", "nat", "-w", "-A", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
            var dnatRes = await Iptables.Run(addDnat);
            if (!dnatRes.Success) { addFailed = true; break; }
            addedNewDnat.Add(proto);

            var checkFwd = new List<string> { "-w", "-C", "FORWARD", "-p", proto, "-d", targetIpParam, "--dport", req.outPort.ToString(), "-j", "ACCEPT" };
            if ((await Iptables.Run(checkFwd)).ExitCode != 0)
            {
                var addFwd = new List<string> { "-w", "-A", "FORWARD", "-p", proto, "-d", targetIpParam, "--dport", req.outPort.ToString(), "-j", "ACCEPT" };
                var fwdRes = await Iptables.Run(addFwd);
                if (!fwdRes.Success) { addFailed = true; break; }
                addedNewFwd.Add(proto);
            }

            if (newNatMode == "masq")
            {
                var checkMasq = Iptables.BuildMasqArgs("-C", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                if ((await Iptables.Run(checkMasq)).ExitCode != 0)
                {
                    var addMasq = Iptables.BuildMasqArgs("-A", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                    var masqRes = await Iptables.Run(addMasq);
                    if (!masqRes.Success) { addFailed = true; break; }
                    addedNewMasq.Add(proto);
                }
            }
        }

        if (addFailed)
        {
            // Rollback new rules
            foreach (var proto in addedNewMasq)
            {
                var delMasq = Iptables.BuildMasqArgs("-D", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                await Iptables.Run(delMasq);
            }
            foreach (var proto in addedNewDnat)
            {
                var delDnat = new List<string> { "-t", "nat", "-w", "-D", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
                await Iptables.Run(delDnat);
            }
            foreach (var proto in addedNewFwd)
            {
                await Iptables.DeleteForwardIfOrphanAsync(proto, targetIpParam, req.outPort);
            }

            // Restore old rules completely
            foreach (var proto in removedOldDnat)
            {
                var restoreDnat = new List<string> { "-t", "nat", "-w", "-A", "PREROUTING", "-p", proto, "--dport", req.oldInPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.oldOutPort}" };
                await Iptables.Run(restoreDnat);

                var checkFwd = new List<string> { "-w", "-C", "FORWARD", "-p", proto, "-d", targetIpParam, "--dport", req.oldOutPort.ToString(), "-j", "ACCEPT" };
                if ((await Iptables.Run(checkFwd)).ExitCode != 0)
                {
                    var addFwd = new List<string> { "-w", "-A", "FORWARD", "-p", proto, "-d", targetIpParam, "--dport", req.oldOutPort.ToString(), "-j", "ACCEPT" };
                    await Iptables.Run(addFwd);
                }

                if (removedOldMasq.Contains(proto))
                {
                    var restoreMasq = Iptables.BuildMasqArgs("-A", privateInterface, proto, targetIpParam, req.oldOutPort, req.oldInPort);
                    await Iptables.Run(restoreMasq);
                }
            }

            return Results.Problem("Failed to update firewall rule. State was rolled back.", statusCode: 500);
        }

        await Iptables.SaveRulesAsync();
        return Results.Ok(new ActionResponse("Route successfully updated."));
    }
    finally
    {
        iptablesLock.Release();
    }
});

app.MapPost("/api/delete", async (PortRequest req) =>
{
    var protocols = Iptables.ResolveProtocols(req.protocol);
    if (protocols == null) return Results.BadRequest(new ErrorResponse("Invalid protocol."));

    if (!await iptablesLock.WaitAsync(TimeSpan.FromSeconds(5)))
        return Results.Problem("System busy.", statusCode: 503);

    int deletedCount = 0;
    try
    {
        foreach (var proto in protocols)
        {
            var checkDnat = new List<string> { "-t", "nat", "-w", "-C", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
            if ((await Iptables.Run(checkDnat)).ExitCode == 0) 
            {
                var delDnat = new List<string> { "-t", "nat", "-w", "-D", "PREROUTING", "-p", proto, "--dport", req.inPort.ToString(), "-j", "DNAT", "--to-destination", $"{targetIpParam}:{req.outPort}" };
                if ((await Iptables.Run(delDnat)).Success)
                {
                    deletedCount++;

                    // Also remove specific conntrack MASQUERADE if present
                    var checkMasq = Iptables.BuildMasqArgs("-C", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                    if ((await Iptables.Run(checkMasq)).ExitCode == 0)
                    {
                        var delMasq = Iptables.BuildMasqArgs("-D", privateInterface, proto, targetIpParam, req.outPort, req.inPort);
                        await Iptables.Run(delMasq);
                    }

                    // Only delete FORWARD rule if no other PREROUTING rule still points to targetIp:outPort
                    await Iptables.DeleteForwardIfOrphanAsync(proto, targetIpParam, req.outPort);
                }
            }
        }
    }
    finally { iptablesLock.Release(); }
    
    if (deletedCount > 0)
    {
        await Iptables.SaveRulesAsync();
        return Results.Ok(new ActionResponse("Route revoked."));
    }

    return Results.BadRequest(new ErrorResponse("Rule not found."));
});

static long LoadAuthGeneration(string filePath)
{
    if (!File.Exists(filePath))
    {
        if (!TrySaveAuthGeneration(filePath, 1))
        {
            Console.WriteLine($"[FATAL ERROR] Unable to initialize auth generation file at '{filePath}'.");
            Environment.Exit(1);
        }
        return 1;
    }

    try
    {
        var text = File.ReadAllText(filePath).Trim();
        if (long.TryParse(text, out long gen) && gen > 0)
            return gen;

        Console.WriteLine($"[FATAL ERROR] Invalid auth generation value in '{filePath}'. Content: '{text}'");
        Environment.Exit(1);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[FATAL ERROR] Failed to read auth generation file: {ex.Message}");
        Environment.Exit(1);
    }

    return 1;
}

static bool TrySaveAuthGeneration(string filePath, long generation)
{
    try
    {
        var tempPath = filePath + ".tmp";
        File.WriteAllText(tempPath, generation.ToString());
        File.Move(tempPath, filePath, overwrite: true);
        return true;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[ERROR] Failed to save auth generation file: {ex.Message}");
        return false;
    }
}

app.Run();

// ---------------- IPTABLES HELPER ----------------
internal partial class Iptables
{
    [GeneratedRegex(@"-A\s+PREROUTING\s+.*?-p\s+(?<proto>tcp|udp)\s+.*?--dport\s+(?<inPort>\d+)\s+.*?-j\s+DNAT\s+--to-destination\s+(?<targetIp>[\d\.]+):(?<outPort>\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex RulePattern();

    private static readonly Regex PostroutingProtoRegex = new(@"-p\s+(?<proto>tcp|udp)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PostroutingInPortRegex = new(@"--ctorigdstport\s+(?<inPort>\d+)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PostroutingOutPortRegex = new(@"--dport\s+(?<outPort>\d+)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PostroutingTargetIpRegex = new(@"-d\s+(?<targetIp>[\d\.]+)(?:/32)?\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public const int MaxPortLimit = 512;

    public static int[] ParseAllowedPorts(string config, int maxLimit = MaxPortLimit)
    {
        var list = new List<int>();
        var segments = config.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        foreach (var seg in segments)
        {
            if (seg.Contains('-'))
            {
                var parts = seg.Split('-');
                if (parts.Length == 2 && int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                {
                    int min = Math.Clamp(Math.Min(start, end), 1, 65535);
                    int max = Math.Clamp(Math.Max(start, end), 1, 65535);
                    for (int p = min; p <= max; p++)
                    {
                        list.Add(p);
                        if (list.Count > maxLimit) break;
                    }
                }
            }
            else if (int.TryParse(seg, out int singlePort) && singlePort is >= 1 and <= 65535)
            {
                list.Add(singlePort);
            }
            if (list.Count > maxLimit) break;
        }
        return list.Distinct().OrderBy(p => p).ToArray();
    }

    public static async Task<string?> ResolvePublicIpAsync(CancellationToken ct = default)
    {
        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = 2000;
        udp.Client.SendTimeout = 2000;

        // RFC 1035: whoami.cloudflare TXT CH query (35 bytes)
        ReadOnlySpan<byte> query =
        [
            0x13, 0x37,             // Transaction ID
            0x01, 0x00,             // Flags: Standard query, RD = 1
            0x00, 0x01,             // QDCOUNT: 1
            0x00, 0x00,             // ANCOUNT: 0
            0x00, 0x00,             // NSCOUNT: 0
            0x00, 0x00,             // ARCOUNT: 0
            // QNAME: 6'whoami' 10'cloudflare' 0
            0x06, 0x77, 0x68, 0x6F, 0x61, 0x6D, 0x69,
            0x0A, 0x63, 0x6C, 0x6F, 0x75, 0x64, 0x66, 0x6C, 0x61, 0x72, 0x65,
            0x00,
            0x00, 0x10,             // QTYPE: TXT (16)
            0x00, 0x03              // QCLASS: CH (Chaos = 3)
        ];

        try
        {
            await udp.SendAsync(query.ToArray(), "1.1.1.1", 53, ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));

            var response = await udp.ReceiveAsync(cts.Token);
            byte[] buffer = response.Buffer;

            if (buffer.Length < 12) return null;

            ushort ancount = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6, 2));
            if (ancount == 0) return null;

            int pos = 12;
            while (pos < buffer.Length && buffer[pos] != 0)
                pos += 1 + buffer[pos];
            pos += 5;

            if (pos >= buffer.Length) return null;

            if ((buffer[pos] & 0xC0) == 0xC0)
                pos += 2;
            else
            {
                while (pos < buffer.Length && buffer[pos] != 0)
                    pos += 1 + buffer[pos];
                pos++;
            }

            // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 byte
            if (pos + 10 > buffer.Length) return null;

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos, 2));
            pos += 8; // TYPE, CLASS, TTL skip
            ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos, 2));
            pos += 2;

            // 0x0010 = TXT record
            if (type == 0x0010 && rdLength > 1 && pos + rdLength <= buffer.Length)
            {
                byte textLen = buffer[pos];
                return Encoding.ASCII.GetString(buffer, pos + 1, textLen);
            }
        }
        catch
        {
            // Timeout or UDP fail
        }

        return null;
    }

    public static async Task<bool> SaveRulesAsync()
    {
        if (OperatingSystem.IsWindows()) return true;

        const string targetPath = "/etc/iptables/rules.v4";
        const string tempPath = "/etc/iptables/rules.v4.tmp";

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "iptables-save",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            {
                Console.WriteLine($"[ERROR] iptables-save failed (ExitCode {process.ExitCode}): {error}");
                return false;
            }

            var dir = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllTextAsync(tempPath, output);
            File.Move(tempPath, targetPath, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] SaveRulesAsync failed: {ex.Message}");
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
            return false;
        }
    }

    public static async Task DeleteForwardIfOrphanAsync(string proto, string targetIp, int outPort)
    {
        var readPrerouting = await Run(new List<string> { "-w", "5", "-t", "nat", "-S", "PREROUTING" });
        if (!readPrerouting.Success) return;

        var activeRules = ParseRules(readPrerouting.Output, "", targetIp);
        bool hasOtherRef = activeRules.Any(r => 
            r.OutPort == outPort.ToString() && 
            ((proto.Equals("tcp", StringComparison.OrdinalIgnoreCase) && r.Tcp) || 
             (proto.Equals("udp", StringComparison.OrdinalIgnoreCase) && r.Udp)));

        if (!hasOtherRef)
        {
            var checkFwd = new List<string> { "-w", "-C", "FORWARD", "-p", proto, "-d", targetIp, "--dport", outPort.ToString(), "-j", "ACCEPT" };
            if ((await Run(checkFwd)).ExitCode == 0)
            {
                var delFwd = new List<string> { "-w", "-D", "FORWARD", "-p", proto, "-d", targetIp, "--dport", outPort.ToString(), "-j", "ACCEPT" };
                await Run(delFwd);
            }
        }
    }

    public static List<string> BuildMasqArgs(string action, string privateInterface, string proto, string targetIp, int outPort, int inPort)
    {
        return new List<string>
        {
            "-t", "nat",
            "-w", action, "POSTROUTING",
            "-o", privateInterface,
            "-p", proto.ToLowerInvariant(),
            "-d", targetIp,
            "--dport", outPort.ToString(),
            "-m", "conntrack",
            "--ctstate", "NEW",
            "--ctorigdstport", inPort.ToString(),
            "-j", "MASQUERADE"
        };
    }

    public static async Task EnsureBaseRules(string targetIp, string privateInterface = "wg0")
    {
        if (OperatingSystem.IsWindows()) return;

        // Clean up legacy broad global MASQUERADE rule if present (do not touch specific conntrack rules)
        var checkBroadMasq = new List<string> { "-t", "nat", "-w", "-C", "POSTROUTING", "-o", privateInterface, "-j", "MASQUERADE" };
        if ((await Run(checkBroadMasq)).ExitCode == 0)
        {
            await Run(new List<string> { "-t", "nat", "-w", "-D", "POSTROUTING", "-o", privateInterface, "-j", "MASQUERADE" });
        }

        if (privateInterface != "wg0")
        {
            var checkBroadMasqWg = new List<string> { "-t", "nat", "-w", "-C", "POSTROUTING", "-o", "wg0", "-j", "MASQUERADE" };
            if ((await Run(checkBroadMasqWg)).ExitCode == 0)
            {
                await Run(new List<string> { "-t", "nat", "-w", "-D", "POSTROUTING", "-o", "wg0", "-j", "MASQUERADE" });
            }
        }

        // Allow return packets for established connections
        var checkFwd1 = new List<string> { "-w", "-C", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT" };
        if ((await Run(checkFwd1)).ExitCode != 0)
            await Run(new List<string> { "-w", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT" });

        // Clean up overly broad legacy base rule if present
        var checkFwd2 = new List<string> { "-w", "-C", "FORWARD", "-d", targetIp, "-o", privateInterface, "-j", "ACCEPT" };
        if ((await Run(checkFwd2)).ExitCode == 0)
            await Run(new List<string> { "-w", "-D", "FORWARD", "-d", targetIp, "-o", privateInterface, "-j", "ACCEPT" });

        if (privateInterface != "wg0")
        {
            var checkFwdLegacy = new List<string> { "-w", "-C", "FORWARD", "-d", targetIp, "-o", "wg0", "-j", "ACCEPT" };
            if ((await Run(checkFwdLegacy)).ExitCode == 0)
                await Run(new List<string> { "-w", "-D", "FORWARD", "-d", targetIp, "-o", "wg0", "-j", "ACCEPT" });
        }
    }

    public static bool ValidatePorts(int inPort, int outPort, int[] allowedPorts)
    {
        if (!allowedPorts.Contains(inPort)) return false;
        if (outPort is <= 0 or > 65535) return false;
        return true;
    }

    public static string[]? ResolveProtocols(string protocol) => protocol.ToLowerInvariant() switch
    {
        "tcp" => ["tcp"],
        "udp" => ["udp"],
        "both" => ["tcp", "udp"],
        _ => null
    };

    public static bool TryResolveNatMode(string? requestedMode, bool defaultPreserve, out string normalizedMode)
    {
        if (string.IsNullOrWhiteSpace(requestedMode))
        {
            normalizedMode = defaultPreserve ? "preserve" : "masq";
            return true;
        }

        var clean = requestedMode.Trim().ToLowerInvariant();
        if (clean is "preserve" or "masq")
        {
            normalizedMode = clean;
            return true;
        }

        normalizedMode = "";
        return false;
    }

    public static bool HasConflict(List<RuleDto> existingRules, int oldInPort, int oldOutPort, int newInPort, string[] newProtocols)
    {
        foreach (var rule in existingRules)
        {
            if (rule.InPort == newInPort.ToString())
            {
                bool isSameRule = (newInPort == oldInPort && rule.OutPort == oldOutPort.ToString());
                if (!isSameRule)
                {
                    bool conflictTcp = rule.Tcp && newProtocols.Contains("tcp", StringComparer.OrdinalIgnoreCase);
                    bool conflictUdp = rule.Udp && newProtocols.Contains("udp", StringComparer.OrdinalIgnoreCase);
                    if (conflictTcp || conflictUdp)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static List<RuleDto> ParseRules(string preroutingOutput, string postroutingOutput, string activeTargetIp)
    {
        var rules = new List<RuleDto>();
        var preLines = preroutingOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var regex = RulePattern();

        foreach (var line in preLines)
        {
            if (!line.Contains("-A PREROUTING", StringComparison.Ordinal)) continue;

            var match = regex.Match(line);
            if (match.Success)
            {
                string targetIp = match.Groups["targetIp"].Value;
                if (!string.Equals(targetIp, activeTargetIp, StringComparison.Ordinal)) continue;

                string proto = match.Groups["proto"].Value.ToUpperInvariant();
                string inPort = match.Groups["inPort"].Value;
                string outPort = match.Groups["outPort"].Value;

                var existing = rules.FirstOrDefault(r => r.InPort == inPort && r.OutPort == outPort && r.TargetIp == targetIp);
                if (existing != null)
                {
                    if (proto == "TCP") existing.Tcp = true;
                    if (proto == "UDP") existing.Udp = true;
                }
                else
                {
                    rules.Add(new RuleDto
                    {
                        InPort = inPort,
                        OutPort = outPort,
                        TargetIp = targetIp,
                        Tcp = (proto == "TCP"),
                        Udp = (proto == "UDP")
                    });
                }
            }
        }

        // Parse per-rule conntrack MASQUERADE entries from POSTROUTING
        // Store as (proto, inPort, outPort)
        var masqRules = new HashSet<(string proto, string inPort, string outPort)>();
        if (!string.IsNullOrWhiteSpace(postroutingOutput))
        {
            var postLines = postroutingOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in postLines)
            {
                if (!line.Contains("-A POSTROUTING", StringComparison.Ordinal) || !line.Contains("-j MASQUERADE", StringComparison.Ordinal))
                    continue;

                var inPortMatch = PostroutingInPortRegex.Match(line);
                var outPortMatch = PostroutingOutPortRegex.Match(line);
                var protoMatch = PostroutingProtoRegex.Match(line);
                var ipMatch = PostroutingTargetIpRegex.Match(line);

                if (inPortMatch.Success && outPortMatch.Success && protoMatch.Success)
                {
                    if (ipMatch.Success && !string.Equals(ipMatch.Groups["targetIp"].Value, activeTargetIp, StringComparison.Ordinal))
                        continue;

                    string proto = protoMatch.Groups["proto"].Value.ToLowerInvariant();
                    string inPort = inPortMatch.Groups["inPort"].Value;
                    string outPort = outPortMatch.Groups["outPort"].Value;
                    masqRules.Add((proto, inPort, outPort));
                }
            }
        }

        // Assign stable Id and NatMode
        foreach (var rule in rules)
        {
            string protoStr = (rule.Tcp && rule.Udp) ? "both" : (rule.Tcp ? "tcp" : "udp");
            rule.Id = $"{rule.InPort}_{rule.OutPort}_{protoStr}";

            bool tcpMasq = masqRules.Contains(("tcp", rule.InPort, rule.OutPort));
            bool udpMasq = masqRules.Contains(("udp", rule.InPort, rule.OutPort));

            if (rule.Tcp && rule.Udp)
            {
                rule.NatMode = (tcpMasq || udpMasq) ? "masq" : "preserve";
            }
            else if (rule.Tcp)
            {
                rule.NatMode = tcpMasq ? "masq" : "preserve";
            }
            else
            {
                rule.NatMode = udpMasq ? "masq" : "preserve";
            }
        }

        return rules;
    }

    public static async Task<CmdResult> Run(List<string> args)
    {
        if (OperatingSystem.IsWindows()) return new CmdResult(true, 0, "", "");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "iptables",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);

        process.Start();
        string output = await process.StandardOutput.ReadToEndAsync();
        string error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return new CmdResult(process.ExitCode == 0, process.ExitCode, output.Trim(), error.Trim());
    }
}

// ---------------- AUTOMATED TESTS ----------------
internal static class IptablesTestRunner
{
    public static int RunAllTests()
    {
        Console.WriteLine("[TEST SUITE] Starting TunnelDash Automated Verifications...");
        int passed = 0;
        int failed = 0;

        void Run(string name, Action test)
        {
            try
            {
                test();
                Console.WriteLine($"  [PASS] {name}");
                passed++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [FAIL] {name}: {ex.Message}");
                failed++;
            }
        }

        Run("ValidatePorts respects allowed pool and ranges", () =>
        {
            int[] pool = [4402, 4403, 4404];
            if (!Iptables.ValidatePorts(4402, 8080, pool)) throw new Exception("Expected 4402 to be valid.");
            if (Iptables.ValidatePorts(9999, 8080, pool)) throw new Exception("Expected 9999 to be rejected.");
            if (Iptables.ValidatePorts(4402, 0, pool)) throw new Exception("Expected port 0 to be rejected.");
            if (Iptables.ValidatePorts(4402, 70000, pool)) throw new Exception("Expected port 70000 to be rejected.");
        });

        Run("ResolveProtocols maps accurately", () =>
        {
            var tcp = Iptables.ResolveProtocols("TCP");
            if (tcp == null || tcp.Length != 1 || tcp[0] != "tcp") throw new Exception("TCP failed");
            var udp = Iptables.ResolveProtocols("udp");
            if (udp == null || udp.Length != 1 || udp[0] != "udp") throw new Exception("UDP failed");
            var both = Iptables.ResolveProtocols("both");
            if (both == null || both.Length != 2) throw new Exception("both failed");
            if (Iptables.ResolveProtocols("invalid") != null) throw new Exception("invalid should return null");
        });

        Run("TryResolveNatMode handles inputs & environment fallback", () =>
        {
            // Null or empty uses fallback
            if (!Iptables.TryResolveNatMode(null, defaultPreserve: true, out var m1) || m1 != "preserve") throw new Exception("m1 failed");
            if (!Iptables.TryResolveNatMode("", defaultPreserve: false, out var m2) || m2 != "masq") throw new Exception("m2 failed");

            // Explicit case-insensitive
            if (!Iptables.TryResolveNatMode("PRESERVE", defaultPreserve: false, out var m3) || m3 != "preserve") throw new Exception("m3 failed");
            if (!Iptables.TryResolveNatMode("MaSq", defaultPreserve: true, out var m4) || m4 != "masq") throw new Exception("m4 failed");

            // Rejection of invalid values
            if (Iptables.TryResolveNatMode("invalid", defaultPreserve: true, out _)) throw new Exception("invalid should be rejected");
            if (Iptables.TryResolveNatMode("snat", defaultPreserve: true, out _)) throw new Exception("snat should be rejected");
        });

        Run("BuildMasqArgs constructs exact conntrack iptables arguments", () =>
        {
            var argsTcp = Iptables.BuildMasqArgs("-A", "wg0", "tcp", "10.0.0.2", 8080, 4403);
            var expectedTcp = new List<string>
            {
                "-t", "nat", "-w", "-A", "POSTROUTING", "-o", "wg0", "-p", "tcp",
                "-d", "10.0.0.2", "--dport", "8080", "-m", "conntrack", "--ctstate", "NEW",
                "--ctorigdstport", "4403", "-j", "MASQUERADE"
            };
            if (!argsTcp.SequenceEqual(expectedTcp))
                throw new Exception($"TCP args mismatch: {string.Join(" ", argsTcp)}");

            var argsUdp = Iptables.BuildMasqArgs("-D", "tailscale0", "udp", "10.0.0.2", 9999, 4405);
            var expectedUdp = new List<string>
            {
                "-t", "nat", "-w", "-D", "POSTROUTING", "-o", "tailscale0", "-p", "udp",
                "-d", "10.0.0.2", "--dport", "9999", "-m", "conntrack", "--ctstate", "NEW",
                "--ctorigdstport", "4405", "-j", "MASQUERADE"
            };
            if (!argsUdp.SequenceEqual(expectedUdp))
                throw new Exception($"UDP args mismatch: {string.Join(" ", argsUdp)}");
        });

        Run("ParseRules distinguishes preserve vs masq on identical target port", () =>
        {
            string prerouting = """
            -A PREROUTING -p tcp -m tcp --dport 4402 -j DNAT --to-destination 10.0.0.2:8080
            -A PREROUTING -p tcp -m tcp --dport 4403 -j DNAT --to-destination 10.0.0.2:8080
            -A PREROUTING -p udp -m udp --dport 4404 -j DNAT --to-destination 10.0.0.2:9999
            -A PREROUTING -p udp -m udp --dport 4405 -j DNAT --to-destination 10.0.0.2:9999
            """;

            string postrouting = """
            -A POSTROUTING -o wg0 -p tcp -d 10.0.0.2 --dport 8080 -m conntrack --ctstate NEW --ctorigdstport 4403 -j MASQUERADE
            -A POSTROUTING -d 10.0.0.2/32 -o wg0 -p udp -m udp --dport 9999 -m conntrack --ctstate NEW --ctorigdstport 4405 -j MASQUERADE
            """;

            var rules = Iptables.ParseRules(prerouting, postrouting, "10.0.0.2");
            if (rules.Count != 4) throw new Exception($"Expected 4 rules, got {rules.Count}");

            var r4402 = rules.First(r => r.InPort == "4402");
            if (r4402.NatMode != "preserve") throw new Exception($"4402 expected preserve, got {r4402.NatMode}");
            if (r4402.Id != "4402_8080_tcp") throw new Exception($"4402 Id mismatch: {r4402.Id}");

            var r4403 = rules.First(r => r.InPort == "4403");
            if (r4403.NatMode != "masq") throw new Exception($"4403 expected masq, got {r4403.NatMode}");
            if (r4403.Id != "4403_8080_tcp") throw new Exception($"4403 Id mismatch: {r4403.Id}");

            var r4404 = rules.First(r => r.InPort == "4404");
            if (r4404.NatMode != "preserve") throw new Exception($"4404 expected preserve, got {r4404.NatMode}");

            var r4405 = rules.First(r => r.InPort == "4405");
            if (r4405.NatMode != "masq") throw new Exception($"4405 expected masq, got {r4405.NatMode}");
        });

        Run("ParseRules ignores legacy broad MASQ and defaults to preserve", () =>
        {
            string prerouting = "-A PREROUTING -p tcp -m tcp --dport 4402 -j DNAT --to-destination 10.0.0.2:8080";
            string postrouting = "-A POSTROUTING -o wg0 -j MASQUERADE"; // legacy broad rule

            var rules = Iptables.ParseRules(prerouting, postrouting, "10.0.0.2");
            if (rules.Count != 1) throw new Exception("Expected 1 rule");
            if (rules[0].NatMode != "preserve") throw new Exception($"Expected preserve, got {rules[0].NatMode}");
        });

        Run("ParseRules correctly parses TCP+UDP dual rule", () =>
        {
            string prerouting = """
            -A PREROUTING -p tcp -m tcp --dport 4402 -j DNAT --to-destination 10.0.0.2:8080
            -A PREROUTING -p udp -m udp --dport 4402 -j DNAT --to-destination 10.0.0.2:8080
            """;
            string postrouting = """
            -A POSTROUTING -o wg0 -p tcp -d 10.0.0.2 --dport 8080 -m conntrack --ctstate NEW --ctorigdstport 4402 -j MASQUERADE
            -A POSTROUTING -o wg0 -p udp -d 10.0.0.2 --dport 8080 -m conntrack --ctstate NEW --ctorigdstport 4402 -j MASQUERADE
            """;

            var rules = Iptables.ParseRules(prerouting, postrouting, "10.0.0.2");
            if (rules.Count != 1) throw new Exception($"Expected 1 combined rule, got {rules.Count}");
            if (!rules[0].Tcp || !rules[0].Udp) throw new Exception("Expected Tcp and Udp both true");
            if (rules[0].NatMode != "masq") throw new Exception("Expected masq");
            if (rules[0].Id != "4402_8080_both") throw new Exception($"Expected Id 4402_8080_both, got {rules[0].Id}");
        });

        Run("HasConflict validates port and protocol collisions during edit", () =>
        {
            var rules = new List<RuleDto>
            {
                new RuleDto { InPort = "4402", OutPort = "8080", Tcp = true, Udp = false },
                new RuleDto { InPort = "4403", OutPort = "9000", Tcp = true, Udp = false }
            };

            // Updating 4402 -> 4402 (same rule editing natMode): no conflict
            if (Iptables.HasConflict(rules, 4402, 8080, 4402, ["tcp"]))
                throw new Exception("Same rule should not conflict");

            // Updating 4402 -> 4403 (collides with existing 4403 TCP)
            if (!Iptables.HasConflict(rules, 4402, 8080, 4403, ["tcp"]))
                throw new Exception("Port 4403 TCP should conflict");

            // Updating 4402 -> 4403 with UDP only (existing 4403 is TCP only, so no conflict)
            if (Iptables.HasConflict(rules, 4402, 8080, 4403, ["udp"]))
                throw new Exception("Port 4403 UDP should not conflict with TCP");

            // Updating 4402 -> 4404 (unused port): no conflict
            if (Iptables.HasConflict(rules, 4402, 8080, 4404, ["tcp"]))
                throw new Exception("Unused port 4404 should not conflict");
        });

        Console.WriteLine($"\n[TEST SUMMARY] Total: {passed + failed}, Passed: {passed}, Failed: {failed}\n");
        return failed == 0 ? 0 : 1;
    }
}

// ---------------- DTOs & JSON SOURCE GEN ----------------
record CmdResult(bool Success, int ExitCode, string Output, string Error);
public record PortRequest(int inPort, int outPort, string protocol, string? natMode = null);
public record UpdateRuleRequest(int oldInPort, int oldOutPort, string oldProtocol, int inPort, int outPort, string protocol, string? natMode = null);
public record StatusResponse(string status, string architecture, string? publicIp, int[] ports, string? defaultNatMode = null);
public record ActionResponse(string message);
public record ErrorResponse(string error);
public record LoginRequest(string passphrase);
public class RuleDto
{
    public string Id { get; set; } = "";
    public string InPort { get; set; } = "";
    public string OutPort { get; set; } = "";
    public string TargetIp { get; set; } = "";
    public bool Tcp { get; set; }
    public bool Udp { get; set; }
    public string NatMode { get; set; } = "preserve";
}
public record RulesResponse(List<RuleDto> rules);

[JsonSerializable(typeof(PortRequest))]
[JsonSerializable(typeof(UpdateRuleRequest))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(ActionResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(RulesResponse))]
[JsonSerializable(typeof(RuleDto))]
[JsonSerializable(typeof(LoginRequest))]
[JsonSerializable(typeof(int[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }