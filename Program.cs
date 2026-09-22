using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

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

await Iptables.EnsureBaseRules(targetIpParam, preserveClientIp, privateInterface);

var iptablesLock = new SemaphoreSlim(1, 1);
var masterKeyBytes = Encoding.UTF8.GetBytes(passPhrase);

var authEpochFile = Path.Combine(AppContext.BaseDirectory, ".auth_generation");
long authEpoch = LoadAuthGeneration(authEpochFile);
var authFileLock = new object();

// --- CSRF & AUTH MIDDLEWARE ---
app.Use(async (context, next) =>
{
    if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path.StartsWithSegments("/api"))
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
    var clientIpStatus = preserveClientIp ? "PRESERVED" : "MASQ";
    return Results.Ok(new StatusResponse("ONLINE", $"GATEWAY // TARGET: {targetIpParam} ({privateInterface}) // CLIENT_IP: {clientIpStatus}", publicIp, allowedPorts));
});

app.MapGet("/api/rules", async (HttpContext _) => 
{
    var result = await Iptables.Run(new List<string> { "-w", "5", "-t", "nat", "-S", "PREROUTING" });
    if (!result.Success) return Results.Problem("Failed to read routing rules.", statusCode: 500);

    var rules = Iptables.ParseRules(result.Output, targetIpParam);
    return Results.Ok(new RulesResponse(rules));
});

app.MapPost("/api/forward", async (PortRequest req) =>
{
    if (!Iptables.ValidatePorts(req.inPort, req.outPort, allowedPorts))
        return Results.BadRequest(new ErrorResponse("Invalid port or port outside allowed pool."));

    var protocols = Iptables.ResolveProtocols(req.protocol);
    if (protocols is null or { Length: 0 }) return Results.BadRequest(new ErrorResponse("Invalid protocol."));

    if (!await iptablesLock.WaitAsync(TimeSpan.FromSeconds(5)))
        return Results.Problem("System busy.", statusCode: 503);

    int addedCount = 0;
    var addedDnat = new List<string>();
    var addedFwd = new List<string>();
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
        }

        if (hasFailure)
        {
            // Transaction rollback: remove any rules applied during this request
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
    private static string? _cachedPublicIp;
    private static DateTime _cacheExpiresAt = DateTime.MinValue;
    private static readonly SemaphoreSlim IpLock = new(1, 1);

    private static readonly HttpClient IpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(3)
    };
    
    [GeneratedRegex(@"-A\s+PREROUTING\s+.*?-p\s+(?<proto>tcp|udp)\s+.*?--dport\s+(?<inPort>\d+)\s+.*?-j\s+DNAT\s+--to-destination\s+(?<targetIp>[\d\.]+):(?<outPort>\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex RulePattern();

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

    public static async Task<string?> ResolvePublicIpAsync()
    {
        if (DateTime.UtcNow < _cacheExpiresAt)
            return _cachedPublicIp;

        await IpLock.WaitAsync();
        try
        {
            if (DateTime.UtcNow < _cacheExpiresAt)
                return _cachedPublicIp;

            string[] providers = 
            [
                "https://checkip.amazonaws.com",
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ifconfig.me/ip"
            ];

            var tasks = providers.Select(async url =>
            {
                try
                {
                    var raw = await IpClient.GetStringAsync(url);
                    var clean = raw.Trim();
                    if (IPAddress.TryParse(clean, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                        return clean;
                }
                catch { }
                return null;
            }).ToList();

            while (tasks.Count > 0)
            {
                var finished = await Task.WhenAny(tasks);
                tasks.Remove(finished);
                var result = await finished;
                if (result != null)
                {
                    _cachedPublicIp = result;
                    _cacheExpiresAt = DateTime.UtcNow.AddMinutes(5); // 5 Dk TTL
                    return _cachedPublicIp;
                }
            }

            _cacheExpiresAt = DateTime.UtcNow.AddSeconds(30); // 30 sn negative cache cooldown
            return _cachedPublicIp;
        }
        finally
        {
            IpLock.Release();
        }
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

        var activeRules = ParseRules(readPrerouting.Output, targetIp);
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

    public static async Task EnsureBaseRules(string targetIp, bool preserveClientIp, string privateInterface = "wg0")
    {
        if (OperatingSystem.IsWindows()) return;

        var checkMasq = new List<string> { "-t", "nat", "-w", "-C", "POSTROUTING", "-o", privateInterface, "-j", "MASQUERADE" };
        var hasMasq = (await Run(checkMasq)).ExitCode == 0;

        if (!preserveClientIp)
        {
            if (!hasMasq)
                await Run(new List<string> { "-t", "nat", "-w", "-A", "POSTROUTING", "-o", privateInterface, "-j", "MASQUERADE" });
        }
        else
        {
            if (hasMasq)
                await Run(new List<string> { "-t", "nat", "-w", "-D", "POSTROUTING", "-o", privateInterface, "-j", "MASQUERADE" });
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

    public static List<RuleDto> ParseRules(string bashOutput, string activeTargetIp)
    {
        var rules = new List<RuleDto>();
        var lines = bashOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var regex = RulePattern();

        foreach (var line in lines)
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
                    rules.Add(new RuleDto { InPort = inPort, OutPort = outPort, TargetIp = targetIp, Tcp = (proto == "TCP"), Udp = (proto == "UDP") });
                }
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

// ---------------- DTOs & JSON SOURCE GEN ----------------
record CmdResult(bool Success, int ExitCode, string Output, string Error);
public record PortRequest(int inPort, int outPort, string protocol);
public record StatusResponse(string status, string architecture, string? publicIp, int[] ports);
public record ActionResponse(string message);
public record ErrorResponse(string error);
public record LoginRequest(string passphrase);
public class RuleDto { public string InPort { get; set; } = ""; public string OutPort { get; set; } = ""; public string TargetIp { get; set; } = ""; public bool Tcp { get; set; } public bool Udp { get; set; } }
public record RulesResponse(List<RuleDto> rules);

[JsonSerializable(typeof(PortRequest))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(ActionResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(RulesResponse))]
[JsonSerializable(typeof(RuleDto))]
[JsonSerializable(typeof(LoginRequest))]
[JsonSerializable(typeof(int[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }