# TunnelDash

An ultra-lightweight, Native AOT compiled NAT port-forwarding management dashboard and daemon designed for low-resource edge gateways (128MB–256MB NAT VPS).

![TunnelDash UI](screenshot.png)

## Highlights

- **Resource Footprint:** ~11 MB RSS in idle deployment, Native AOT compiled (.NET 10). Zero external runtime dependencies.
- **Kernel-Level Routing:** Directly controls Linux `iptables` with transactional rollback, reference-counted FORWARD rules, and persistent firewall state.
- **Per-Rule NAT Modes (`preserve` vs `masq`):** Configure NAT behavior independently per forward rule. Run transparent real-client-IP traffic and MASQUERADEd traffic concurrently—even targeting the exact same internal port.
- **Conntrack Original Destination Matching:** Uses Linux `conntrack` (`--ctorigdstport`) to isolate SNAT/MASQUERADE rules by their pre-NAT public ingress port, avoiding routing conflicts across shared internal services.
- **Atomic Rule Editing:** Edit public port, internal target port, protocol (`tcp`, `udp`, `both`), or NAT mode in-place via `PUT /api/forward` with full state rollback on failure.
- **Principle of Least Privilege:** Tight, port-specific FORWARD filtering instead of broad subnet forwarding. Only explicitly mapped endpoints are forwarded.
- **Security First:** Rate-limited authentication, constant-time HMAC-SHA256 session handling, CSRF origin verification, and private-network-oriented deployment.
- **Minimalist Industrial Interface:** Monochromatic high-contrast control panel with instant endpoint clipboard replication, NAT mode toggles, and seamless in-place route editing.

## Table of Contents

- [Architecture](#architecture)
- [Per-Rule NAT Modes](#per-rule-nat-modes)
  - [Preserve Mode (Real Client IP)](#preserve-mode-real-client-ip)
  - [Masq Mode (Gateway SNAT)](#masq-mode-gateway-snat)
  - [Coexistence on the Same Target Port](#coexistence-on-the-same-target-port)
  - [Startup & Legacy Migration](#startup--legacy-migration)
- [REST API Reference](#rest-api-reference)
  - [Create Forwarding Route](#1-create-forwarding-route-post-apiforward)
  - [Edit Forwarding Route (Atomic)](#2-edit-forwarding-route-atomic-put-apiforward)
  - [Revoke Route](#3-revoke-route-post-apidelete)
  - [Query Active Rules](#4-query-active-rules-get-apirules)
  - [Gateway Status](#5-gateway-status-get-apistatus)
- [Private Network Compatibility](#private-network-compatibility)
  - [WireGuard Guide (Reference)](#wireguard)
  - [Tailscale Guide](#tailscale)
  - [Other Private Networks](#other-private-or-overlay-networks)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Automated Deployment](#automated-deployment-optional)
- [Security Notice](#security-notice)
- [License](#license)

## Architecture

TunnelDash is a **port-forwarding gateway**, not a VPN implementation. The private network can be WireGuard, Tailscale, OpenVPN, or another routed/overlay network, provided the gateway can reach the configured `TARGET_IP` and Linux forwarding/firewall rules permit the traffic.

By default, TunnelDash uses `wg0` as its private network interface, but any interface can be selected via the `PRIVATE_INTERFACE` environment variable (e.g., `tailscale0`, `tun0`).

### Generic traffic flow

```text
[Internet Client: 203.0.113.5]
       │
       ▼  (e.g. :4402 TCP/UDP)
[NAT VPS Gateway]
       │
       │  TunnelDash / iptables DNAT
       ▼
[Private Network Interface]
       │
       ├── WireGuard: wg0
       ├── Tailscale: tailscale0
       ├── OpenVPN: tun0
       └── Other routed / overlay interface
       │
       ▼
[Downstream Server: TARGET_IP]
```

---

## Per-Rule NAT Modes

Rather than forcing a single global MASQUERADE setting across the entire gateway, TunnelDash implements fine-grained **per-rule NAT modes**. Each route explicitly defines its own translation behavior.

### Preserve Mode (`preserve`)
- **Behavior:** Downstream host sees the real public IP address of the Internet client. No SNAT or MASQUERADE rule is added in `POSTROUTING`.
- **Downstream Requirement:** Because packets arrive with the remote client's real public IP, the downstream host must use policy-based routing (e.g. `CONNMARK` and a custom routing table) to direct replies back out through the tunnel gateway rather than its local default gateway.

### Masq Mode (`masq`)
- **Behavior:** Downstream host sees the private tunnel IP of the gateway (e.g. `10.0.0.1`). An isolated `POSTROUTING` MASQUERADE rule is generated specifically for this route.
- **Downstream Requirement:** Standard default routing. No special policy routing or `CONNMARK` is needed downstream; the host simply replies back to the gateway.

### Coexistence on the Same Target Port

Multiple public ports frequently map to the same downstream service port with conflicting NAT requirements:

```text
4402 -> 8080 TCP -> preserve
4403 -> 8080 TCP -> masq
4404 -> 9999 UDP -> preserve
4405 -> 9999 UDP -> masq
```

A naive MASQUERADE rule based solely on the target port (`-d 10.0.0.2 --dport 8080 -j MASQUERADE`) would inadvertently masquerade traffic destined for rule `4402`.

TunnelDash prevents cross-rule contamination by anchoring per-rule MASQUERADE entries to Linux connection tracking (`conntrack`), matching the **original pre-DNAT public ingress port** (`--ctorigdstport`):

```bash
iptables -t nat -A POSTROUTING \
  -o wg0 \
  -p tcp \
  -d 10.0.0.2 \
  --dport 8080 \
  -m conntrack \
  --ctstate NEW \
  --ctorigdstport 4403 \
  -j MASQUERADE
```

### Startup & Legacy Migration

- **Global MASQUERADE Removal:** At startup, `EnsureBaseRules` automatically detects and deletes any broad legacy MASQUERADE rules (`-t nat -A POSTROUTING -o <PRIVATE_INTERFACE> -j MASQUERADE`), ensuring they do not override rules marked as `preserve`.
- **Rule Inspection & Fallback:** When reading active rules (`GET /api/rules`), TunnelDash correlates `PREROUTING` DNAT entries with `POSTROUTING` conntrack rules. If a route matches a specific `--ctorigdstport` MASQUERADE rule, it is identified as `masq`. If no specific MASQUERADE rule exists, it safely defaults to `preserve`.

---

## REST API Reference

All `/api/*` endpoints (except `/api/login` and `/api/status`) require the `TunnelSession` cookie and enforce CSRF origin verification.

### 1. Create Forwarding Route (`POST /api/forward`)

Creates a new DNAT, FORWARD, and optional conntrack MASQUERADE rule atomically.

**Request:**

```json
{
  "inPort": 4402,
  "outPort": 8080,
  "protocol": "tcp",
  "natMode": "preserve"
}
```

Or for MASQ mode:

```json
{
  "inPort": 4403,
  "outPort": 8080,
  "protocol": "tcp",
  "natMode": "masq"
}
```

- `inPort` (int): Public port within `PORT_RANGE`.
- `outPort` (int): Destination port on downstream host (`1`–`65535`).
- `protocol` (string): `"tcp"`, `"udp"`, or `"both"`.
- `natMode` (string, optional): `"preserve"` or `"masq"`. If omitted, defaults to the mode configured by `PRESERVE_CLIENT_IP`.

**Response (200 OK):**
```json
{
  "message": "Route successfully added."
}
```

### 2. Edit Forwarding Route (Atomic) (`PUT /api/forward`)

Atomically modifies an existing route (ports, protocol, or NAT mode). If any step fails during execution, new changes are rolled back and previous rules are restored completely.

**Request:**

```json
{
  "oldInPort": 4402,
  "oldOutPort": 8080,
  "oldProtocol": "tcp",
  "inPort": 4402,
  "outPort": 8080,
  "protocol": "tcp",
  "natMode": "masq"
}
```

- Verifies that the previous rule exists in the kernel.
- Validates that the new `inPort` and `protocol` do not collide with another existing route.
- Atomically replaces old DNAT, orphan FORWARD, and per-rule MASQ rules with the new configuration.
- Persists changes via `iptables-save`.

**Response (200 OK):**
```json
{
  "message": "Route successfully updated."
}
```

### 3. Revoke Route (`POST /api/delete`)

Removes DNAT, cleans up orphan FORWARD rules (if no other route references `TARGET_IP:outPort`), and deletes any associated per-rule MASQUERADE entry.

**Request:**

```json
{
  "inPort": 4403,
  "outPort": 8080,
  "protocol": "tcp"
}
```

**Response (200 OK):**
```json
{
  "message": "Route revoked."
}
```

### 4. Query Active Rules (`GET /api/rules`)

Scans kernel `PREROUTING` and `POSTROUTING` tables, returning all routes targeting `TARGET_IP` along with their resolved NAT mode and composite ID.

**Response (200 OK):**

```json
{
  "rules": [
    {
      "id": "4402_8080_tcp",
      "inPort": "4402",
      "outPort": "8080",
      "targetIp": "10.0.0.2",
      "tcp": true,
      "udp": false,
      "natMode": "preserve"
    },
    {
      "id": "4403_8080_tcp",
      "inPort": "4403",
      "outPort": "8080",
      "targetIp": "10.0.0.2",
      "tcp": true,
      "udp": false,
      "natMode": "masq"
    }
  ]
}
```

### 5. Gateway Status (`GET /api/status`)

Returns connectivity status, detected public IP, assigned public port pool, and default NAT mode.

**Response (200 OK):**

```json
{
  "status": "ONLINE",
  "architecture": "GATEWAY // TARGET: 10.0.0.2 (wg0) // DEFAULT_NAT: PRESERVE",
  "publicIp": "198.51.100.1",
  "ports": [4402, 4403, 4404, 4405],
  "defaultNatMode": "preserve"
}
```

---

## Private Network Compatibility

TunnelDash only needs a reachable path from the gateway to `TARGET_IP`. The underlying private network does not need to be WireGuard-specific in principle.

For any private/overlay network, verify these conditions:

1. The private interface is up and has a working route to `TARGET_IP`.
2. IPv4 forwarding is enabled on the gateway.
3. The gateway firewall permits the forwarded traffic.
4. The downstream service is listening on the expected destination port.
5. Return traffic has a valid path back to the gateway.
6. If `masq` mode is selected for a rule, the downstream host simply replies to the gateway's private tunnel IP.
7. If `preserve` mode is selected for a rule, the downstream host must route replies back through the gateway instead of its local default internet gateway.

Useful checks on the gateway:

```bash
ip link
ip addr
ip route
ip route get <TARGET_IP>
sysctl net.ipv4.ip_forward
```

Then verify the forwarding path with:

```bash
sudo iptables -t nat -S
sudo iptables -S FORWARD
sudo tcpdump -n -i <PRIVATE_INTERFACE> host <TARGET_IP>
```

---

## Prerequisites

Before running TunnelDash, ensure your gateway host meets the following requirements:

- **Operating System:** Debian 12/13, Ubuntu 22.04+, or another supported modern Linux distribution (x86_64).
- **Kernel IP Forwarding:** Packet forwarding must be enabled on the host:
  ```bash
  sudo sysctl -w net.ipv4.ip_forward=1
  echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/99-forwarding.conf
  ```
- **Netfilter Tools:** `iptables` and `iptables-persistent` must be installed:
  ```bash
  sudo apt-get update && sudo apt-get install -y iptables iptables-persistent
  ```
- **Active Private Network:** A working private/overlay interface routing traffic between the gateway and your downstream host. Common examples are WireGuard `wg0`, Tailscale `tailscale0`, and OpenVPN `tun0`.
- **Privileges:** The daemon must run as `root` (or with appropriate netfilter capabilities) to execute `iptables` commands.

## Quick Start

### 1. Build Native Binary

Compile the standalone Linux x64 binary using the provided Docker build environment:

```bash
chmod +x build.sh && ./build.sh
```

This produces a stripped, self-contained executable inside `./publish/tunneldash`.

> [!NOTE]
> **Target Environment & Build Architecture**
>
> TunnelDash is specifically engineered for low-resource edge gateways (128MB–256MB NAT VPS). Native AOT compilation requires ~1.5GB–2GB peak RAM and heavy CPU resources during IL analysis, trimming, and code generation. Attempting to compile directly on constrained nodes may trigger the Linux OOM (Out of Memory) killer. Binaries should be built on a local workstation or CI runner using Docker, then deployed as a standalone executable to the gateway.

### 2. Service Setup

Copy the template systemd service file to your system configuration:

```bash
sudo cp tunneldash.service.example /etc/systemd/system/tunneldash.service
sudo nano /etc/systemd/system/tunneldash.service
```

Configure the environment variables:

- `PASS_PHRASE`: Master administrative key for dashboard authentication (min. 12 characters).
- `TARGET_IP`: The downstream target host IP inside your private network (for example, a WireGuard peer such as `10.0.0.2` or a Tailscale node address).
- `PORT_RANGE`: Public ports assigned to your node, formatted as a range or comma-separated list (for example, `4402-4420` or `4402-4410,8080`).
- `PRIVATE_INTERFACE`: (Optional, default: `wg0`). The network interface connecting the gateway to the private/overlay network (e.g., `wg0`, `tailscale0`, `tun0`).
- `PRESERVE_CLIENT_IP`: (Optional, default: `true`). Sets the **default NAT mode** for new rules created without an explicit `natMode`. When `true`, default is `preserve`; when `false`, default is `masq`. Individual rules can always override this.
- `ASPNETCORE_URLS`: Listening interface and port (for example, `http://10.0.0.1:80`).

Enable and start the daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tunneldash
```

---

## WireGuard

WireGuard is the current reference deployment and the environment used by the built-in transparent client-IP preservation example.

### Gateway

Create a working WireGuard interface on the NAT gateway, typically `wg0`, and make sure the gateway can route to the downstream peer (for example `10.0.0.2`).

Verify:

```bash
ip addr show wg0
ip route get 10.0.0.2
sudo wg show
```

### Real Client IP Preservation

When a rule is created with `natMode: "preserve"` (or under `PRESERVE_CLIENT_IP=true`), the gateway forwards packets with their original source IP address. Because the client IP is on the public internet, the downstream server must return reply packets back through the WireGuard tunnel rather than its local default gateway to avoid asymmetric routing drops.

This is achieved with Linux Policy-Based Routing and `CONNMARK` on the downstream host.

### Downstream `/etc/wireguard/wg0.conf`

On your downstream server (for example a home server or edge node at `10.0.0.2`), configure WireGuard as follows:

```ini
[Interface]
Address = 10.0.0.2/24
PrivateKey = <DOWNSTREAM_PRIVATE_KEY>

# Prevent wg-quick from overriding the machine's primary default route.
Table = off

# Mark incoming connections from the tunnel in connection tracking.
PostUp = iptables -t mangle -A PREROUTING -i %i -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x1
# Restore the mark on locally generated outgoing reply packets.
PostUp = iptables -t mangle -A OUTPUT -m connmark --mark 0x1 -j CONNMARK --restore-mark

# Route marked reply packets through the WireGuard routing table.
PostUp = ip rule add fwmark 0x1 table 100
# Force all packets originating from the downstream IP into table 100 (essential for UDP/connectionless services)
PostUp = ip rule add from 10.0.0.2 table 100
PostUp = ip route add default dev %i table 100

# Loosen reverse path filtering to allow the asymmetric ingress path.
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=2
PostUp = sysctl -w net.ipv4.conf.%i.rp_filter=2

# Cleanup rules when the tunnel goes down.
PostDown = iptables -t mangle -D PREROUTING -i %i -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x1
PostDown = iptables -t mangle -D OUTPUT -m connmark --mark 0x1 -j CONNMARK --restore-mark
PostDown = ip rule del fwmark 0x1 table 100
PostDown = ip rule del from 10.0.0.2 table 100
PostDown = ip route flush table 100

[Peer]
PublicKey = <GATEWAY_PUBLIC_KEY>
Endpoint = <GATEWAY_PUBLIC_IP>:<PORT>
# Allow the WireGuard peer to receive return traffic for internet destinations.
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

> [!TIP]
> **Routing Table 100 Note:**
> The routing table identifier `table 100` is purely numeric and works natively out-of-the-box in Linux without requiring an alias defined in `/etc/iproute2/rt_tables`.

### Verification

#### 1. Live Packet Inspection

Run `tcpdump` on the downstream server while connecting to a forwarded port:

```bash
sudo tcpdump -n -i wg0
```

You should see incoming packets carrying the remote client's public source IP, followed by replies using the same connection path.

#### 2. Quick HTTP IP Echo Server

To quickly test inbound connectivity and verify which source IP reaches your downstream host without installing a full web server, run this minimal Python one-liner on the downstream host:

```bash
python3 -c 'from http.server import BaseHTTPRequestHandler,HTTPServer; H=type("H",(BaseHTTPRequestHandler,),{"do_GET":lambda s:(s.send_response(200),s.send_header("Content-Type","text/plain"),s.end_headers(),s.wfile.write(s.client_address[0].encode())), "log_message":lambda *a:None}); HTTPServer(("0.0.0.0",8080),H).serve_forever()'
```

Map an external port (e.g. `4402` ➔ `8080`) in TunnelDash, then query it from an external client:

```bash
curl http://<GATEWAY_PUBLIC_IP>:4402
```

- When `preserve` mode is used, it returns your actual remote client IP.
- When `masq` mode is used, it returns the gateway's private tunnel IP (e.g. `10.0.0.1`).

#### 3. Quick UDP Echo Server

To verify inbound and outbound UDP routing, run this minimal Python UDP listener on the downstream host:

```bash
python3 - <<'PY'
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9999))

print("Listening on 9999...")

while True:
    data, addr = s.recvfrom(1024)
    print(f"Received from {addr}")
    s.sendto(b"PONG\n", addr)
PY
```

Map an external UDP port (e.g. `4404` ➔ `9999` UDP) in TunnelDash, then send a datagram from an external client:

```bash
echo "PING" | nc -u -w2 <GATEWAY_PUBLIC_IP> 4404
```

- Under `preserve` mode and policy routing, the downstream prints the client's real public IP, and the client receives `PONG`.
- Under `masq` mode, the downstream prints the gateway's IP, and the client receives `PONG`.

---

## Tailscale

Tailscale can provide the private routed path as well. On Linux, Tailscale uses kernel-mode routing by default and requires IP forwarding for routing features such as subnet routing.

### Gateway setup

Install and authenticate Tailscale on the gateway:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Enable IPv4 forwarding:

```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf
sudo sysctl -p /etc/sysctl.d/99-tailscale.conf
```

Check the Tailscale interface and route to your downstream node:

```bash
ip addr show tailscale0
sudo tailscale status
ip route get <TAILSCALE_TARGET_IP>
```

Use the downstream node's reachable private address as `TARGET_IP`.

### Recommended mode: `masq` (SNAT / MASQUERADE)

For simple Tailscale deployments, set `PRIVATE_INTERFACE=tailscale0` and use `masq` mode (or set `PRESERVE_CLIENT_IP=false` as default) so that the downstream server replies directly to the gateway without needing a custom route back to every internet client:

```text
TARGET_IP=<TAILSCALE_NODE_IP>
PRIVATE_INTERFACE=tailscale0
PRESERVE_CLIENT_IP=false
```

---

## Other Private or Overlay Networks

WireGuard and Tailscale are the most common examples, but TunnelDash does not fundamentally require either technology. The same networking model can be used with another routed private interface such as OpenVPN (`tun0`), ZeroTier, Nebula, or a custom tunnel.

---

## Automated Deployment (Optional)

To push updates from your local build machine to your remote gateway, set up `.env` from `.env.example`:

```bash
cp .env.example .env
nano .env
```

Run the deploy script to sync binaries and restart the service:

```bash
chmod +x deploy.sh && ./deploy.sh
```

---

## Public IP Resolution

TunnelDash resolves the gateway's public IPv4 address by issuing a raw RFC 1035 UDP query directly to Cloudflare DNS (`1.1.1.1:53`) for the `whoami.cloudflare` TXT record (CHAOS class). 

This eliminates dependencies on external HTTP scrapers/APIs, avoids HTTP connection overhead, and works natively in restricted network environments with zero external libraries.

---

## Security Notice

TunnelDash is intended to run on a dedicated NAT gateway and requires privileged access to manage Linux netfilter rules.

- Do not expose the dashboard directly to the public internet unless appropriate firewall and access controls are in place.
- Use a strong, unique `PASS_PHRASE`.
- Restrict dashboard access to a trusted private overlay network (for example, WireGuard or Tailscale) when running over HTTP without TLS.
- Review the generated `iptables` rules before deploying to production.

---

## License

TunnelDash is licensed under the MIT License.

See [LICENSE](LICENSE) for the full license text.