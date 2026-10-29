# RestrictVPN

A fail-closed VPN kill switch for Windows, as a single `.exe` with a UI and a
tray icon. It reconfigures Windows Firewall so **the only way out of your PC is
the VPN tunnel adapter**. If the VPN drops, every other app instantly loses its
network path instead of silently falling back to your real IP.

No installer, no service, no driver, no dependencies. One executable, compiled
by the C# compiler that already ships with Windows.

![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![.NET Framework](https://img.shields.io/badge/.NET%20Framework-4.x%20in--box-512BD4)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Quick start

1. Download `RestrictVPN.exe` from the [latest release](../../releases/latest),
   or [build it yourself](#building-from-source) in one command.
2. Put it in a folder of its own — it writes `config.json`, `state\` and
   `logs\` next to itself.
3. Run it. It asks for administrator (it has to — firewall rules need it), then
   shows one window with a big Arm / Disarm button.
4. Press **Self test (changes nothing)** first. It rehearses the whole
   mechanism without touching your firewall.
5. Choose how your VPN reaches the internet. If it has a tunnel adapter, tick it
   in the list. If it is a local proxy — V2rayN, Clash, sing-box with TUN mode
   off — choose **It is a local proxy** and press **Detect client**.
6. Press **ARM KILL SWITCH**.

If anything goes wrong, `Recover.cmd` forces your internet back on without
loading the app at all. See [If you get locked out](#if-you-get-locked-out).

### Requirements

- Windows 10 or 11 (also works on Windows Server 2016+).
- Administrator rights.
- Windows Firewall enabled — this app configures it rather than replacing it.
- Any VPN, in one of two shapes:
  - **It presents a tunnel adapter** — OpenVPN and OpenVPN Connect are what it
    was built and tested against; WireGuard, Outline and commercial clients work
    the same way as long as you tick the right adapter.
  - **It is a local proxy with no adapter** — V2rayN, Clash, sing-box and
    similar, whenever TUN mode is off. See [Proxy mode](#proxy-mode).

---

## Why a firewall-level kill switch

Forcing everything behind the VPN at the firewall layer, so that a disconnect
means no internet, is the standard way kill switches are built. The important
detail is *where* you enforce it:

| Approach | How it fails |
| --- | --- |
| **Reactive** — watch the VPN, then block when it drops | There is a window between the drop and your reaction. Packets leak in that window. Avoid this. |
| **Fail-closed** — deny by default, permanently allow only the tunnel | Nothing to react to. The moment the tunnel stops carrying packets, there is no permitted path out. |

This app implements the second one. There is no monitoring loop, no race
condition, and nothing that can be too slow — the block is the resting state,
and the tunnel is the only exception.

**Also worth doing:** OpenVPN Connect has a built-in *Seamless tunnel* setting
(Settings → Advanced). It uses the same Windows Filtering Platform underneath
and covers the reconnect window. Turning it on alongside this app costs nothing
and gives you a second independent layer.

**Unless you want split tunnelling.** Seamless tunnel blocks every packet that
does not go through the tunnel, at a layer below Windows Firewall that this app
cannot add exceptions to. That is the whole point of it — and it is the exact
opposite of what a split tunnel asks for. The two cannot both be on. See
[Split tunnel](#split-tunnel).

---

## The window

| Control | What it does |
| --- | --- |
| **ARM / DISARM KILL SWITCH** | The main toggle. |
| **Self test (changes nothing)** | Rehearses the whole mechanism without arming. Start here. |
| **Verify rules** | Reads the live rules back out of Windows Firewall and checks them. |
| **Split tunnel...** | The one place for everything you want kept *off* the VPN: addresses, apps, and the bypass proxy that makes app entries work. |
| **Emergency recover** | Forces internet back on, deletes every rule this app made, and removes its routes. |
| **Arm at Windows startup** | Registers a boot task so you're never exposed before the VPN connects. |
| **How your VPN reaches the internet** | Tunnel adapter, or local proxy. Not a preference — a fact about your VPN. See [Proxy mode](#proxy-mode). |
| **Detect client** | Finds V2rayN (or Clash, or sing-box), reads its port and TUN setting out of its own config, and fills in the programs. |
| **Tunnel adapter list** | Tick every adapter your VPN uses. A `*` marks the one currently carrying your internet traffic. In proxy mode this is only needed if the client runs in TUN mode. |

The banner is colour-coded and refreshes every 2 seconds:

- **Green — PROTECTED**: VPN up, kill switch armed.
- **Amber — BLOCKED**: kill switch armed, VPN down. No internet, which is the point.
- **Red — AT RISK / UNPROTECTED**: kill switch off. You leak if the VPN drops.

Closing the window **hides it to the tray**, where the icon shows the same
colour and the right-click menu can arm, disarm, or recover. *Exit* on that menu
really quits. Quitting does **not** disarm — the firewall policy stays exactly
as you left it, which is the whole point of a kill switch.

### Start with the self test

It creates a **disabled** probe rule, reads the interface binding back, deletes
it, and tells you whether the mechanism works on your machine. A disabled rule
filters nothing, so your traffic is never affected either way. Nothing about
your firewall changes.

---

## How it works

This describes **tunnel mode**, the default. A VPN that has no adapter of its
own works the same way with a process-scoped allow-list instead — see
[Proxy mode](#proxy-mode).

When armed, RestrictVPN:

1. Sets `DefaultOutboundAction = Block` on **all three** firewall profiles
   (Domain, Private, Public). Because that's a policy default rather than a
   rule, it covers IPv4 and IPv6 alike — closing the IPv6 leak that trips up a
   lot of hand-rolled kill switches.
2. Adds a narrow allow-list, all tagged with the group `RestrictVPN Kill Switch`:

   | Rule | Why it exists |
   | --- | --- |
   | Allow outbound/inbound on the tunnel adapter(s) | Your actual VPN traffic. Scoped by interface, so only packets egressing the tunnel match. |
   | Allow the VPN client executables | Otherwise the tunnel could never reconnect after a drop — you'd be offline permanently. |
   | Allow DHCP (v4 + v6) | Without it your Wi-Fi never gets an address, so nothing works at all. Link-local only; nothing leaks. |
   | Allow DNS *for the VPN client only* (optional) | Lets the client resolve its server hostname. The one deliberate plaintext query outside the tunnel; it disappears if you pin `VpnServerEndpoints` to literal IPs. |
   | Allow LAN (optional, **off** by default) | Printers and NAS. Off because it also reopens DNS to your router, handing your browsing back to your ISP. |

Your app traffic is allowed only because it leaves via the tunnel interface. If
the tunnel goes down, that interface stops carrying packets, traffic falls back
toward Wi-Fi — and Wi-Fi has no allow rule. Dropped.

### Why interface-scoped rather than IP-scoped

A common shortcut is to allow traffic from the tunnel's assigned IP. That
address changes on reconnect, and worse, it can collide with a private range
your real LAN also uses — at which point the "tunnel only" rule silently starts
permitting traffic over Wi-Fi. Binding to the adapter avoids both problems.

### Two ways this could go wrong, and the preflight that stops both

Arming runs a preflight: it creates the rules, reads them back out of Windows
Firewall, and only *then* flips the policy to default-deny. It's checking for
two distinct failures:

- **Interface filter missing** — the allow rule matches nothing, and
  default-deny would strand the machine offline.
- **Interface filter empty** — the firewall reads an empty interface list as
  *all* interfaces, which would quietly turn the kill switch into a permit-all
  rule. This one fails **open**, so it is the more dangerous of the two.

If either check fails, the app deletes its own rules and leaves your firewall
exactly as it was.

### How "VPN is up" is decided

In **proxy mode** the question is whether the core is accepting on its loopback
port, which is what an app would find if it tried right now. The rest of this
applies to **tunnel mode**.

Not by adapter status — an adapter can sit `Up` with a stale address long after
the tunnel died, which is exactly the situation that leaks. Instead the app asks
Windows which interface it would actually use to reach the public internet
(`GetBestInterface`) and checks whether that's one of your tunnel adapters.
Routing is unaffected by firewall rules, so this stays accurate even while the
kill switch is blocking everything.

---

## Proxy mode

Some VPN clients never create an adapter. **V2rayN, Clash, sing-box and Nekoray
in their default configuration** run a core process that opens a SOCKS/HTTP
listener on `127.0.0.1` and connect out from your ordinary NIC, using the same
IP as everything else on the machine. There is no tunnel interface, so there is
nothing to bind an interface-scoped rule to.

Ticking your Wi-Fi adapter instead would "work" in the sense that the VPN keeps
running — and would permit every other program on the machine at the same time,
which is the opposite of a kill switch. So proxy mode changes what the allow
rule is scoped to:

| | Tunnel mode | Proxy mode |
| --- | --- | --- |
| Default outbound action | Block, all three profiles | Block, all three profiles |
| The allow-list is | An **interface** — the tunnel adapter | A **process** — the VPN core |
| Your apps get out because | Their packets leave via the tunnel | They hand bytes to the core over loopback |
| When the VPN dies | The interface stops carrying packets, and the fallback path has no rule | The core stops accepting on its port, and the apps have no direct path either |
| Result | No internet, no leak | No internet, no leak |

The fail-closed property is identical, because it comes from the same place in
both: `DefaultOutboundAction = Block` is the resting state, and the allow-list
is narrow. Only the shape of the allow-list changes.

### Why loopback needs no rule

Windows does not apply firewall filtering to traffic that stays on `127.0.0.1`.
That is what makes this work: with default-deny outbound in force, Chrome can
still reach `127.0.0.1:10808`, the core still holds its one permitted
connection to your server, and nothing else on the machine has a path out at
all.

### This is stricter than the client on its own

A local-proxy client only diverts programs that *ask* to be proxied. Anything
that ignores the system proxy setting — plenty of updaters, telemetry, and
anything speaking a protocol the proxy setting does not cover — goes straight
out your NIC with your real IP, **while the client sits there apparently
connected**. That is not a failure mode, it is the normal behaviour, and it is
invisible.

Proxy mode closes exactly that gap. After arming, a program that ignores the
proxy does not leak; it fails.

### Setting it up

1. Start your VPN client.
2. Choose **It is a local proxy**, then press **Detect client**.

   Detection leads with the running process rather than a list of install
   paths, so a portable V2rayN on any drive is found without typing anything.
   It reads the listen port and the TUN setting from the client's own
   `guiConfigs\guiNConfig.json`, and picks up `v2rayN.exe` along with the cores
   under `bin\` — `xray.exe`, `sing-box.exe`, `mihomo.exe`. Bundled helpers
   that never touch the network are deliberately left out.
3. Press **Self test**, which rehearses program scoping the same way the tunnel
   self test rehearses interface scoping — a **disabled** probe rule, read back,
   then deleted.
4. **ARM KILL SWITCH**.

Leave the adapter list empty unless the client is in TUN mode.

### If your client is in TUN mode

Then it *does* present an adapter, usually Wintun-based, and **Detect client**
says so and leaves you in tunnel mode. Tick that adapter: scoping to the
interface is stricter than scoping to the process, because it holds even if the
core is compromised into making connections it should not.

The core keeps its own allow rule either way — it has to reach your server over
the physical NIC before there is a tunnel at all.

### Apps that ignore the system proxy

This is the one you will actually hit, and it is worth understanding rather than
working around.

Setting the Windows system proxy only redirects programs that *read* it.
Browsers do — Edge, Chrome, Firefox all keep working after arming with nothing
to configure. Plenty of other software does not: **VS Code, and most things
built on Node, Electron, Go, Python or Java**, use their own HTTP stack and go
straight out the NIC.

Before arming, those programs were quietly reaching the internet **with your
real IP while the VPN looked connected**. That is the leak this mode exists to
close, so when one of them stops working after arming, it is not a bug — it is
the first time you have been shown that it was never using the VPN.

There are two ways to deal with it, and only one of them is right:

| | What happens |
| --- | --- |
| **Point the app at the proxy** | Its traffic goes through the VPN like everything else. |
| ~~Add it to `AllowedPrograms` or the split tunnel~~ | It gets a direct hole and carries your real IP — you have re-opened exactly the leak you just closed. |

Reach for the second only for something that genuinely must be direct, such as
an RDP client, which cannot speak a proxy at all.

**VS Code**, as a worked example. In `settings.json`:

```json
"http.proxy": "http://127.0.0.1:10808",
"terminal.integrated.env.windows": {
    "HTTP_PROXY":  "http://127.0.0.1:10808",
    "HTTPS_PROXY": "http://127.0.0.1:10808",
    "NO_PROXY":    "localhost,127.0.0.1,::1"
}
```

`http.proxy` covers the editor itself — extensions, the marketplace, updates.
The terminal block is separate because child processes launched in the
integrated terminal inherit the environment, not the setting, so `npm`, `pip`
and `curl` need the variables. Reload the window afterwards.

Git is a third case again: the built-in Source Control panel runs `git` with VS
Code's own environment rather than the terminal's, so it needs git's own config:

```
git config --global http.proxy  http://127.0.0.1:10808
git config --global https.proxy http://127.0.0.1:10808
```

To undo that later, `git config --global --unset http.proxy` (and `https.proxy`).

**An editor extension that shells out to its own CLI** is a fourth case, and the
one that catches people after they think they are finished. A VS Code extension
does not run in the terminal, so `terminal.integrated.env.windows` never reaches
it; it is spawned by the extension host and inherits *VS Code's* environment.
Two ways to give it one:

- the tool's own config, if it has one — Claude Code takes an `env` block in
  `~/.claude/settings.json`, which applies immediately with no restart:

  ```json
  "env": {
      "HTTP_PROXY":  "http://127.0.0.1:10808",
      "HTTPS_PROXY": "http://127.0.0.1:10808",
      "NO_PROXY":    "localhost,127.0.0.1,::1"
  }
  ```

- or user-level environment variables, which every later process inherits:

  ```powershell
  [Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://127.0.0.1:10808", "User")
  [Environment]::SetEnvironmentVariable("HTTP_PROXY",  "http://127.0.0.1:10808", "User")
  [Environment]::SetEnvironmentVariable("NO_PROXY",    "localhost,127.0.0.1,::1", "User")
  ```

  **Fully quit and reopen VS Code** for these — *Developer: Reload Window* is not
  enough, because the environment is inherited from the main process, which a
  reload does not restart. To undo, set each to `$null`.

So: app setting, terminal environment, tool-specific config, and the inherited
process environment. Most software needs one of the four; something like VS Code
plus an extension that spawns a CLI needs several.

To check any of it, ask what address the far end sees, once each way:

```
curl -x http://127.0.0.1:10808 http://api.ipify.org   # should be your VPN exit
curl --noproxy "*"             http://api.ipify.org   # your real IP
```

Two different answers means the proxy is doing something. If a program reports
the second address, it is not using the VPN — and while armed it will simply
stop instead.

### What to know before arming

- **DNS is blocked unless it goes through the proxy.** Anything resolving via
  the system resolver is talking to your LAN's DNS server, which is now denied.
  For proxy-aware apps this is a non-issue and an improvement — hostnames go to
  the proxy and are resolved at the far end, so there is no plaintext lookup on
  the wire. Tick **Allow the VPN client to resolve its server hostname** so the
  core can still find your server, or pin `VpnServerEndpoints` to literal IPs
  and drop even that.
- **The banner reads the listener, not the far end.** "PROTECTED" means the
  core is accepting connections on its port, which is what an app would find if
  it tried right now. It does not prove your server is reachable — that would
  need a real request pushed through on every poll. Protection does not rest on
  this either way: it comes from the firewall policy, and the banner only
  reports.
- **An app in the split tunnel list is a full bypass here.** In tunnel mode an
  app exclusion permits traffic without moving it, which is why it needs the
  bypass proxy. In proxy mode nothing has taken the default route away from
  your NIC — the proxy is a destination, not a path — so permitting an app is
  all it takes for that app to go direct, with your real IP. The log says so
  when it builds those rules.

---

## Split tunnel

Some traffic you may want *off* the VPN: a bank that rejects VPN exit IPs, a NAS
on another subnet, a game server you want a direct route to. **Split tunnel...**
in the window opens the editor; a status line under Options shows what is live.

Two kinds of exclusion, and they are not equally capable:

| You exclude | RestrictVPN does | Does it actually work |
| --- | --- | --- |
| **A destination** — `1.2.3.4`, `192.168.50.0/24`, `example.com` | Installs a route via your physical gateway **and** a firewall allow rule for that address | **Yes, completely** |
| **An app** — `C:\...\chrome.exe` | Installs a firewall allow rule for that program | **Only with the bypass proxy switched on** — see below |

### Why a destination exclusion works

OpenVPN takes over the default route — usually as `0.0.0.0/1` + `128.0.0.0/1`,
which outrank a real default route without replacing it. RestrictVPN adds a
*more specific* route for the excluded address via your physical gateway, and
longest-prefix match means that route wins. The packet is handed to the NIC and
never reaches the tunnel.

The firewall rule is the other half. Without it, default-deny would drop the
packet the instant it stopped using the tunnel interface, so the route on its
own would break that destination rather than exclude it.

Both halves are built in one pass, and the rules are derived from the
destinations that were **actually routed** — a hole is never opened for traffic
that would still have gone through the VPN.

### Why an app exclusion needs the bypass proxy

A firewall can permit a packet or drop it. It cannot *move* one. Windows picks
the route by destination and has no idea which process a packet came from, so an
allow rule tagged with an `.exe` changes what is permitted and nothing at all
about where the traffic goes. Listing Chrome on its own does nothing.

There is exactly one thing that moves a single socket off the tunnel without a
kernel driver: **`IP_UNICAST_IF`**, a per-socket option that overrides the route
table's choice of outgoing interface. The catch is that it has to be set by
whoever owns the socket — and that isn't us, it's Chrome.

> **The app has to be *started* through RestrictVPN.** Chrome opened from your
> taskbar will use the VPN like everything else, no matter what is in the
> exclusion list — a browser only reads its proxy setting at startup, and
> nothing outside the kernel can change that afterwards. **Saving the split
> tunnel window offers to restart it for you**, which is the only way an app
> already running can be moved onto the bypass.

So RestrictVPN becomes the owner. Tick **Run the bypass proxy** and it opens a
SOCKS5 listener on `127.0.0.1`, sets `IP_UNICAST_IF` on every outbound
connection it makes, and starts your excluded apps pointed at it:

```
Chrome  --proxy-server="socks5://127.0.0.1:1080"
   -> RestrictVPN proxy   (IP_UNICAST_IF = your physical adapter)
      -> Wi-Fi, real IP, VPN bypassed
```

A socket left alone takes the tunnel; the same socket with `IP_UNICAST_IF`
pinned to Wi-Fi leaves from the physical adapter's address instead. The route
table is not consulted.

### Using it

Everything lives in the **Split tunnel...** window. Add addresses and apps to
one list, tick **Run the bypass proxy**, and press **Save and apply**. There is
no second button anywhere else.

Each app in the list says which side of the tunnel it is on right now, read from
its actual command line:

```
NET   192.168.50.0/24
NET   example.com
APP   C:\Program Files\Google\Chrome\Application\chrome.exe      [bypassing the VPN]
```

An address is live the moment you save. An app has to be restarted, so if one is
running on the VPN when you save, you are offered the choice:

| | |
| --- | --- |
| **Close it and reopen outside the VPN** | Your normal profile, bookmarks, logins and tabs — restarted onto the bypass. This is usually what you want. |
| **Open a separate bypass window** | A second window with its own profile, leaving your main browser on the VPN. Useful when you want both at once. |

Declining leaves it alone; it just stays on the VPN, and the list says so.

**Test bypass**, beside the proxy switch, asks an echo service what address it
sees on each path and tells you outright:

```
Normal traffic leaves as:   203.0.113.45
Through the bypass proxy:   198.51.100.12

The bypass is working.
```

Two different addresses means it works. The same address twice means nothing is
being bypassed — the log line `Bypass proxy: connection 1 to ... left from ...`
appears the first time anything actually uses it, and its absence means the app
never connected.

Reopening the window later is also how you check on things: the per-app state is
re-read every time it is shown.

**The limits, plainly:**

- **Only apps that speak proxy.** Chrome, Edge, Brave, Firefox, curl, most dev
  tools. An arbitrary process that ignores proxy settings still can't be caught
  — that genuinely does need a WFP callout driver.
- **Only Chromium browsers can be told on the command line.** Everything else
  launches normally and you set `127.0.0.1:<port>` as its SOCKS5 proxy by hand.
  The launcher says so rather than pretending.
- **A running Chrome ignores proxy arguments.** It hands the request to the
  existing process and you get a tab on the VPN. The launcher detects this and
  offers to restart it, or to open a separate bypass window.
- **Test bypass contacts `api.ipify.org`** over plain HTTP, and only when you
  press it. Nothing else in this app talks to the internet.
- **Only while RestrictVPN is running.** The proxy lives in the app, so a
  bypassed app loses its path when you Exit from the tray. `--enable` from the
  boot task arms the firewall but starts no proxy.
- **DNS still goes through the tunnel.** The proxy resolves hostnames with the
  system resolver, which is the VPN's while connected. The connection itself
  leaves over the physical adapter, so the site sees your real address — only
  the lookup is tunnelled.
- **It needs a broad firewall hole.** While the proxy is on, `RestrictVPN.exe`
  gets a blanket outbound allow, because it is the process making the bypassed
  connections. This is the widest exception this app can create, and it exists
  only while the proxy is switched on.

Destinations and apps compose: routes handle "this address never goes through
the VPN" for everything on the machine, and the proxy handles "this program
never goes through the VPN" for whatever you launch through it.

### Everything here fails closed

| If | Then |
| --- | --- |
| No physical adapter with a gateway is available | No routes and no holes. Everything stays on the VPN. |
| A route won't install | No allow rule is created for it either. That destination stays on the VPN. |
| The firewall rejects an address | That destination is *blocked* while armed, not leaked. The log says so. |
| A hostname won't resolve — tunnel down, DNS gone | The addresses it resolved to last time are reused, so an exclusion doesn't evaporate at the worst possible moment. |
| You move to a different Wi-Fi network | The old routes are removed and reinstalled against the new gateway, within 30 seconds. |

Hostnames are re-resolved every time the rules are applied. That is fine for a
bank or a NAS and unreliable for a large CDN, which may hand out a different
address every lookup — pin those to literal ranges if you can.

Routes are added **non-persistent** (`store=active`) on purpose: a stale route
surviving into a different network is exactly the sort of silent misdirection
this app exists to prevent. `state\splittunnel.json` records what was installed
so it can still be cleaned up after a restart, and the app reinstalls the routes
when it launches.

Split tunnel follows the **split tunnel setting, not the kill switch**.
Disarming leaves the routes in place, because "keep this off the VPN" is equally
true when the firewall isn't locked down. Turning split tunnel off removes them,
and so does **Emergency recover**.

### If nothing bypasses the VPN

Read `logs\restrictvpn.log`. Every run starts with the binary it is running and
the settings it read:

```
[INFO] RestrictVPN starting - C:\...\RestrictVPN.exe  (built 2026-08-19 14:23:11, 109056 bytes)
[INFO] Split tunnel config: enabled=True, destinations=2, apps=1, bypassProxy=True (port 1080), adapter=auto
[INFO] Split tunnel: 2 destination(s) resolved, physical adapter Wi-Fi if4=19 gw4=192.168.1.1 ...
[OK]   Bypass proxy listening on 127.0.0.1:1080, pinned to Wi-Fi.
[OK]   Bypass proxy: connection 1 to example.com:443 left from 192.168.1.102:51203 via Wi-Fi  <- this address is what the site sees
```

In order, the things that actually go wrong:

| Symptom in the log | Cause |
| --- | --- |
| The build stamp is older than your last `build.cmd` | The build never replaced the exe, because the app was running. Closing the window only hides it to the tray — use **Exit** on the tray menu. `build.cmd` refuses to run in that state instead of failing obscurely. |
| `bypassProxy=False` while apps are listed | The proxy is off, so app entries are firewall permissions and nothing more. A warning line says so explicitly. |
| `0 destination route(s)` with destinations configured | Look for the per-entry warning above it — an unresolvable hostname, or no gateway for that address family. |
| `Bypass proxy: 127.0.0.1:1080 was refused ... reserved range 1041-1140` | Windows hands whole blocks of ports to WinNAT for Hyper-V and WSL, and a bind inside one fails with "access denied" however you are running. Nothing to do — a free port is picked automatically and saved to `config.json`. `netsh interface ipv4 show excludedportrange protocol=tcp` lists the blocks. |
| Arming refuses with `No tunnel adapters are selected` | Your VPN has no adapter. Switch to [proxy mode](#proxy-mode) and press **Detect client**. |
| Proxy mode armed, browsers work but VS Code / npm / a CLI tool does not | That program ignores the system proxy and was going direct — with your real IP — before you armed. Point it at the proxy; see [Apps that ignore the system proxy](#apps-that-ignore-the-system-proxy). |
| Proxy mode armed and nothing has internet, including proxy-aware apps | The core is not running. The status line under the mode selector says whether anything is listening on the port. |
| `Proxy mode: client allow rule exists: No client rule found` | None of the configured executables exist on disk — usually a client that moved or updated. Press **Detect client**. |
| `Bypass proxy: could not reach ... AccessDenied` | A packet filter, never routing. Either the kill switch is armed without the bypass proxy's allow rule (press **Verify rules**, re-arm if it is missing), or OpenVPN Connect's **Seamless tunnel** is on and blocking everything outside the tunnel. |
| The proxy is listening but there is no `connection 1` line | Nothing ever used it. The app was started after the fact, outside RestrictVPN, so it never knew the proxy existed. The split tunnel list will show it as `running ON the VPN`. |
| An app shows `running ON the VPN` | Press **Save and apply** and accept the restart. A browser cannot be moved onto the bypass while it is running. |
| The restart says the app did not close | Either it is asking you to confirm, or "continue running background apps" is on in its settings — that leftover process keeps the profile locked, so a relaunch would be ignored. The message says which. |

### Picking the physical adapter

Auto-detection scores every adapter that is up, isn't a tunnel, and holds a
default gateway of its own. The decisive test is asking Windows which interface
reaches that adapter's own gateway: the gateway is on-link, so the answer is the
physical NIC even while the tunnel owns the default route. Override it in the
editor, or with `SplitTunnelUnderlayAlias`, if it picks wrong.

---

## If you get locked out

Three independent ways out, none of which need internet:

1. **Emergency recover** in the app (window or tray menu).
2. **`Recover.cmd`** — deliberately standalone. It doesn't load the exe or any
   module, so it still works if the app itself won't start.
3. **Nuclear option**, from any admin PowerShell:
   ```powershell
   Set-NetFirewallProfile -All -DefaultOutboundAction Allow
   ```
   or, if the firewall is in a genuinely bad state, `netsh advfirewall reset`
   (that wipes *all* rules, including other software's).

**Disarm** restores the exact policy captured before you first armed it
(`state\state.json`) — including a `NotConfigured` default, which is what a
machine that has never had these settings touched actually has. The snapshot is
taken through the `NetFirewallProfile` cmdlets for that reason; the COM API used
everywhere else reports the *effective* value and cannot express
`NotConfigured`, so a COM-only snapshot would restore `Allow`/`Block` where
`NotConfigured` used to be. If the cmdlets are unavailable the app falls back to
COM and says so in the log.

**Recover** is the blunt instrument that doesn't trust that file to exist or be
valid.

---

## Command line

The same exe, for scripting and the boot task:

```
RestrictVPN.exe                    Open the window
RestrictVPN.exe --selftest         Rehearse; change nothing
RestrictVPN.exe --enable           Arm
RestrictVPN.exe --disable          Disarm
RestrictVPN.exe --recover          Emergency restore
RestrictVPN.exe --status           Show current state
RestrictVPN.exe --split-apply      Reinstall the split tunnel routes only
RestrictVPN.exe --split-clear      Remove the split tunnel routes
RestrictVPN.exe --enable --quiet   Suppress dialogs (used by the boot task)
```

---

## Configuration

`config.json`, next to the exe, generated on first run — it discovers your
tunnel adapters and VPN client executables itself, so there is nothing to write
by hand. Most of it is editable from the window; open the file directly for the
rest. [`config.example.json`](config.example.json) documents the schema.

| Key | Meaning |
| --- | --- |
| `Mode` | `tunnel` (default) or `proxy`. See [Proxy mode](#proxy-mode). A config written before this key existed reads as `tunnel`, which is what it was written against. |
| `TunnelInterfaceAliases` | The adapters traffic may leave through. Everything not listed is blocked. Unused in proxy mode unless the client runs in TUN mode. |
| `VpnClientPrograms` | Executables allowed to reach the VPN server over the physical NIC. In proxy mode this is the entire egress allow-list. |
| `ProxyListenPort` | The loopback port the proxy client listens on, filled in by **Detect client**. Reporting only — Windows does not filter loopback, so nothing is opened for it. |
| `VpnServerEndpoints` | Optional. Literal server IPs. Setting these tightens the client rule *and* removes the plaintext DNS exception. |
| `AllowLan` | Local network access. Default `false`. |
| `AllowDhcp` | Default `true`. Turning it off will likely break your Wi-Fi. |
| `AllowVpnClientDns` | Let the VPN client resolve its server hostname. Ignored when `VpnServerEndpoints` is set. |
| `ExtraAllowedInterfaceAliases` | Extra interfaces to permit — see the WSL note below. |
| `AllowedPrograms` | Specific apps deliberately allowed outside the tunnel. Each entry is a hole in the kill switch. Same firewall mechanism as `SplitTunnelPrograms`; prefer the split tunnel list, which is paired with the routing that makes it mean something. |
| `SplitTunnelEnabled` | Master switch for the split tunnel. Default `false`. |
| `SplitTunnelAddresses` | Destinations kept off the VPN: an IP, a CIDR range, or a hostname. |
| `SplitTunnelPrograms` | Apps kept off the VPN. Only effective alongside the addresses they talk to. |
| `SplitTunnelUnderlayAlias` | Force a specific physical adapter for excluded traffic. Empty means auto-detect. |
| `BypassProxyEnabled` | Run the loopback SOCKS5 proxy that makes app exclusions real. Default `false`. |
| `BypassProxyPort` | Port for that proxy on `127.0.0.1`. Default `1080`. If that port cannot be bound, a free one is chosen and written back here. |
| `BlockInbound` | Also block unsolicited inbound. Default `true`. |
| `ArmAtBoot` | Register the scheduled task that arms before you log in. |

### Notes on common setups

- **OpenVPN Connect** can switch between its TAP and DCO drivers, so tick both
  the TAP adapter (often named `Local Area Connection`) and
  `OpenVPN Connect DCO Adapter`. The self test confirms whichever one is live.
- **Detection finds other VPNs' adapters too** — PrivadoVPN, Outline and
  similar. They are left unticked. Ticking them is safe either way, they're all
  tunnels, but a smaller allow-list is a smaller attack surface.
- **WSL and Hyper-V.** Default-deny outbound will cut WSL's internet, because
  WSL reaches the network through NAT on the host. Either accept that it's
  covered by the same kill switch (correct and intended), or add
  `vEthernet (WSL (Hyper-V firewall))` to `ExtraAllowedInterfaceAliases` —
  understanding that this is a deliberate hole.
- **V2rayN, Clash, sing-box.** Off by default these have no adapter at all, so
  they need [proxy mode](#proxy-mode) rather than an entry in the adapter list.
  Turn TUN mode on in the client and they behave like every other tunnel VPN
  instead.
- **Split tunnel needs a route more specific than the tunnel's.** OpenVPN
  typically holds `0.0.0.0/1` and `128.0.0.0/1`, so any exclusion you can
  express already is. A VPN that installs a true `0.0.0.0/0` default route works
  too, for the same reason.
- **Adapters shown as `(not present)` are skipped when arming.** A ticked
  adapter that no longer exists is ignored with a warning rather than passed to
  the firewall — and unticking it stops the warning. Arming with *only* missing
  adapters is refused, since that would block the VPN itself.

---

## Limits — what this does *not* protect against

Stated plainly, because a kill switch you trust too much is worse than none:

- **Local admin can undo it.** Anything running with admin rights, including
  malware, can flip the firewall back. This defends against a dropped tunnel,
  not against an attacker already on the box.
- **DNS already cached** by Windows before the tunnel came up can still be used;
  it just can't be refreshed. Run `ipconfig /flushdns` after arming if that
  matters to you.
- **Every entry in `AllowedPrograms` is a real hole.** An app allowed there
  bypasses the tunnel entirely, carrying your real IP.
- **Every split tunnel entry is the same hole, on purpose.** An excluded
  destination reaches you over your real IP — that is what you asked for. Keep
  the list short and specific for the same reason the tunnel allow-list is.
- **An app exclusion cannot steer traffic on its own.** It is a firewall
  permission, not a route. It needs the bypass proxy, or the app's destinations.
- **The bypass proxy is an unauthenticated way around the VPN.** It only listens
  on `127.0.0.1`, so nothing off this machine can reach it — but any local
  process that finds the port can use it. Leave it off unless you are using it.
- **It does not verify the tunnel is trustworthy** — only that traffic goes
  through it.
- Traffic *inside* the tunnel is the VPN client's business, not this app's.

---

## Building from source

No SDK, no NuGet, no internet. It compiles with the C# compiler that already
ships with Windows:

```
build.cmd
```

`build.cmd /force` stops a running instance first. Note that closing the window
only hides the app to the tray — use **Exit** on the tray icon, or the build
refuses rather than silently leaving you with a stale exe.

| Path | |
| --- | --- |
| `RestrictVPN.exe` | The app — build output, not committed; see [Releases](../../releases) |
| `Recover.cmd` / `Recover.ps1` | Standalone emergency restore |
| `build.cmd` | Rebuild the exe |
| `src\` | C# sources |
| `src\Program.cs` | Entry point and command line |
| `src\AppConfig.cs` | Settings, discovery and defaults |
| `src\Com.cs` | Late-bound Windows Firewall COM access |
| `src\FirewallService.cs` | Rules and profile policy |
| `src\KillSwitch.cs` | Arm, disarm, preflight, self test, snapshot |
| `src\AdapterService.cs` | Adapter discovery and live tunnel detection |
| `src\SplitTunnel.cs` | Split tunnel: physical path detection, routing, state |
| `src\SplitTunnelForm.cs` | The split tunnel editor, and the shared palette |
| `src\BypassProxy.cs` | The SOCKS5 bypass proxy and the app launcher |
| `src\MainForm.cs` | The window and tray icon |
| `src\BootTask.cs` | The scheduled task that arms at startup |
| `src\PolicyStore.cs` | Reading and restoring firewall profile policy |
| `src\Paths.cs` | File locations and the logger |
| `src\app.manifest` | Requests administrator elevation |
| `config.json` | Settings, generated on first run |
| `state\state.json` | Firewall policy captured before first arming |
| `state\splittunnel.json` | Routes the split tunnel installed, so they can be removed again |
| `logs\restrictvpn.log` | Activity log |
| `legacy-powershell\` | The earlier PowerShell version, superseded by the exe. Kept only for reference; safe to delete. |

`config.json`, `state\` and `logs\` are machine-specific and written at runtime,
so they are gitignored rather than committed.

---

## Contributing

Bug reports and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how
to build and what to test before opening one. The short version: keep it
dependency-free, and make sure every failure path still fails *closed*.

**Found a leak?** Don't open a public issue — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). No warranty: this software reconfigures your firewall, and you
run it at your own risk. Read
[Limits](#limits--what-this-does-not-protect-against) before you rely on it.
