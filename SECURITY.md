# Security policy

RestrictVPN's entire job is to make sure traffic cannot leave the machine
outside the VPN tunnel. A bug that lets a packet out is the worst kind of bug
this project can have, because it fails silently — everything looks fine and
your real IP is what the other end sees.

## Reporting a vulnerability

**Do not open a public issue for a leak.**

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. If that is unavailable, email the address on the maintainer's
GitHub profile.

Please include:

- What leaks, and the shortest sequence of steps that produces it.
- Your Windows version, VPN client, and adapter setup.
- The relevant lines from `logs\restrictvpn.log` — **redact your public IP**
  before sending; the `Bypass proxy: connection ... left from ...` lines
  contain addresses.
- Your `config.json` with paths and adapter names left in but nothing you
  consider private.

Expect an acknowledgement within a week. There is no bounty; this is a
single-maintainer hobby project.

## What counts

In scope, and worth reporting:

- Traffic leaving outside the tunnel while the kill switch is armed and the VPN
  is down.
- Arming that reports success while the interface filter is missing or empty
  (the preflight exists to catch exactly this — a bypass of it is a real bug).
- Disarm or recover leaving rules or routes behind.
- The bypass proxy being reachable from anywhere other than `127.0.0.1`.
- A split tunnel route or firewall hole created for something that was not in
  the exclusion list.

Out of scope, because they are documented design limits rather than defects
(see the *Limits* section of the [README](README.md)):

- **A local administrator turning the firewall back on.** Anything with admin
  rights can undo this app. It defends against a dropped tunnel, not against an
  attacker already on the box.
- **Entries you added yourself leaking.** Every item in `AllowedPrograms` and
  every split tunnel exclusion is a deliberate hole that carries your real IP.
  That is what they are for.
- **The bypass proxy being usable by other local processes.** It listens
  unauthenticated on loopback by design. Leave it off unless you are using it.
- **DNS cached before arming** still resolving, and DNS lookups from the bypass
  proxy going through the tunnel's resolver.
- **Traffic inside the tunnel.** That is the VPN client's business.

## Trusting the binary

Releases are built from the tagged source with `build.cmd` and nothing else.
If you would rather not trust a download, build it yourself — it takes one
command and no toolchain beyond what Windows already has.
