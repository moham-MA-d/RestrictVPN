# Contributing

Thanks for looking. This is a small, deliberately dependency-free Windows
utility, and the bar for changes is mostly "does it still fail closed".

## Building

```
build.cmd
```

That is the whole toolchain. It uses `csc.exe` from the .NET Framework 4
runtime that ships with Windows — no SDK, no NuGet, no internet. If the exe is
running, the build refuses rather than failing obscurely; use **Exit** on the
tray icon (closing the window only hides it), or `build.cmd /force` from an
elevated prompt.

## Testing a change

There is no unit test suite — nearly everything here talks to Windows Firewall,
the routing table or a live adapter, so the tests that matter are on a real
machine. Before opening a PR, on a machine you can afford to lock out of the
network:

1. `RestrictVPN.exe --selftest` — must still pass. It creates a *disabled*
   probe rule, reads the interface binding back and deletes it, so it changes
   nothing.
2. Arm, then **Verify rules**. Confirm the interface filter is present and
   non-empty.
3. Drop the VPN while armed and confirm you actually lose internet.
4. Disarm, and confirm the profile defaults returned to what they were
   (`state\state.json` holds the snapshot).
5. **Emergency recover**, and confirm no `RestrictVPN Kill Switch` rules survive:
   ```powershell
   Get-NetFirewallRule -Group "RestrictVPN Kill Switch"
   ```

If you touched the split tunnel, also check **Test bypass** reports two
different addresses, and that turning split tunnel off removes the routes
(`route print`).

## House rules for the code

- **Fail closed.** Every failure path must end with traffic on the VPN or
  blocked — never leaked. If a route will not install, no allow rule is created
  for it either. Keep that pairing intact.
- **No new dependencies.** C# 5 / .NET Framework 4.x, referencing only
  assemblies present in a stock Windows install (see the `/reference:` list in
  `build.cmd`). This is what makes the app buildable and auditable on an
  offline machine.
- **Log what you do.** Anything that changes firewall state, routes, or the
  proxy writes a line to `logs\restrictvpn.log`. Diagnosing this app from a
  user's log is the only debugging available.
- **Never widen the allow-list quietly.** A new exception is a new hole in the
  kill switch; it needs a UI affordance, a config key, or both, and a mention
  in the README's limits section.
- Match the surrounding style: explicit types, no LINQ query syntax, comments
  that explain *why* rather than restate the code.

## Pull requests

Say what you changed, what you tested it on (Windows version, VPN client), and
which of the checks above you ran. Small, focused PRs get read; large ones that
mix a refactor with a behaviour change usually do not.

Security issues do not belong in a PR or a public issue — see
[SECURITY.md](SECURITY.md).
