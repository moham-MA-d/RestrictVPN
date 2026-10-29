using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace RestrictVpn
{
    internal class CheckResult
    {
        public string Check;
        public bool Passed;
        public bool Fatal;
        public string Detail;

        public CheckResult(string check, bool passed, bool fatal, string detail)
        {
            Check = check; Passed = passed; Fatal = fatal; Detail = detail;
        }
    }

    internal enum Verdict { Protected, Blocked, AtRisk, Unprotected }

    internal class StatusInfo
    {
        public bool KillSwitchEnabled;
        public bool TunnelCarryingInternet;
        public Verdict Verdict;
        public string Headline;
        public string Detail;
        public int RuleCount;
        public List<ProfileState> Profiles = new List<ProfileState>();
    }

    /// <summary>
    /// Orchestrates the fail-closed policy: default-deny outbound on every
    /// profile, with a narrow allow-list for the VPN.
    ///
    /// What that allow-list is scoped to depends on the shape of the VPN:
    ///
    ///   tunnel mode - the VPN owns an adapter, so one rule bound to that
    ///                 adapter permits everything leaving through it. Traffic is
    ///                 allowed because of the path it takes.
    ///   proxy  mode - the VPN is a local proxy with no adapter, so the only
    ///                 rules are for the core process itself. Traffic is allowed
    ///                 because of the process that sends it, and every other app
    ///                 reaches the network by handing bytes to that process over
    ///                 loopback, which Windows Firewall does not filter.
    ///
    /// The failure behaviour is the same in both. In tunnel mode a dead tunnel
    /// stops carrying packets and the fallback path has no allow rule. In proxy
    /// mode a dead core stops accepting on its port and the apps that were using
    /// it have no direct path either. Neither leaks; both simply stop.
    /// </summary>
    internal class KillSwitch
    {
        public const string RuleGroup = "RestrictVPN Kill Switch";
        private const string Prefix = "RestrictVPN - ";

        private readonly FirewallService _fw;

        public KillSwitch()
        {
            _fw = new FirewallService();
        }

        public FirewallService Firewall { get { return _fw; } }

        // -------------------------------------------------------------- status

        public StatusInfo GetStatus(AppConfig config)
        {
            return GetStatus(config, true, 0);
        }

        /// <summary>
        /// Counting our rules means walking every firewall rule on the machine,
        /// which is too costly for a UI polling every couple of seconds. Callers
        /// that poll can pass enumerateRules=false and supply the last known
        /// count; the cheap part (profile defaults, routing) is always live.
        /// </summary>
        public StatusInfo GetStatus(AppConfig config, bool enumerateRules, int cachedRuleCount)
        {
            StatusInfo s = new StatusInfo();
            s.Profiles = _fw.GetProfiles();
            s.RuleCount = enumerateRules ? _fw.GetRulesInGroup(RuleGroup).Count : cachedRuleCount;
            s.KillSwitchEnabled = _fw.AllProfilesBlockOutbound() && s.RuleCount > 0;
            s.TunnelCarryingInternet = IsVpnUp(config);

            bool proxy = config.IsProxyMode;
            string up = proxy ? "The proxy is up" : "VPN is up";
            string down = proxy ? "The proxy is down" : "VPN is down";

            if (s.KillSwitchEnabled && s.TunnelCarryingInternet)
            {
                s.Verdict = Verdict.Protected;
                s.Headline = "PROTECTED";
                s.Detail = up + " and the kill switch is armed.";
            }
            else if (s.KillSwitchEnabled)
            {
                s.Verdict = Verdict.Blocked;
                s.Headline = "BLOCKED";
                s.Detail = down + " and the kill switch is armed, so this PC has no internet. That is intended.";
            }
            else if (s.TunnelCarryingInternet)
            {
                s.Verdict = Verdict.AtRisk;
                s.Headline = "AT RISK";
                s.Detail = up + " but the kill switch is OFF. Your traffic will leak if " +
                           (proxy ? "an app ignores the proxy." : "the VPN drops.");
            }
            else
            {
                s.Verdict = Verdict.Unprotected;
                s.Headline = "UNPROTECTED";
                s.Detail = down + " and the kill switch is OFF.";
            }
            return s;
        }

        /// <summary>
        /// Whether the VPN is currently carrying traffic.
        ///
        /// In tunnel mode this asks the routing table, because an adapter can sit
        /// Up with a stale address long after the tunnel died - the exact case
        /// that leaks.
        ///
        /// In proxy mode there is no route to inspect: every app's packets go to
        /// loopback, and the core makes its own connection. The equivalent
        /// question is whether the core is accepting on its port, which is what
        /// an app would find if it tried right now.
        /// </summary>
        private static bool IsVpnUp(AppConfig config)
        {
            if (!config.IsProxyMode)
            {
                return AdapterService.IsTunnelCarryingInternet(config.TunnelInterfaceAliases);
            }

            // A TUN-mode client satisfies either test, so accept both rather than
            // reporting it down while it is plainly working.
            if (ProxyClientService.IsProxyListening(config.ProxyListenPort)) return true;
            return AdapterService.IsTunnelCarryingInternet(config.TunnelInterfaceAliases);
        }

        // -------------------------------------------------------------- enable

        public void Enable(AppConfig config)
        {
            Log.Info("=== Enabling kill switch ===");

            // Only adapters that exist may reach the firewall. A name with no
            // adapter behind it must be filtered here and not one line later:
            // INetFwRule.put_Interfaces resolves every entry, and an array with
            // an unknown name kills the process in native code - no exception,
            // no log, the window just vanishes. (Seen with a stale
            // "Local Area Connection 4" in proxy mode.)
            List<string> missingAdapters;
            List<string> interfaces;
            AdapterService.SplitExistingAliases(
                config.AllAllowedInterfaces(), out interfaces, out missingAdapters);
            if (missingAdapters.Count > 0)
            {
                Log.Warn("Skipping " + missingAdapters.Count + " adapter(s) that are not present: " +
                         string.Join(", ", missingAdapters.ToArray()) +
                         ". Untick them in the adapter list to stop seeing this.");
            }

            // Whichever mode is in force, refuse to arm without an allow-list.
            // Default-deny with nothing permitted is not a kill switch, it is a
            // machine with no internet and no way for the VPN to come back.
            if (config.IsProxyMode)
            {
                List<string> live = config.ExistingClientPrograms();
                if (live.Count == 0)
                {
                    throw new InvalidOperationException(
                        "Proxy mode is selected but none of the configured VPN client programs exist " +
                        "on disk. Arming now would block the proxy itself, so nothing was changed.\r\n\r\n" +
                        "Press \"Detect client\" to find it, or check VpnClientPrograms in config.json.");
                }
                Log.Info("Proxy mode: " + live.Count + " program(s) may reach the network directly; " +
                         "everything else must go through 127.0.0.1:" + config.ProxyListenPort + ".");
            }
            else if (interfaces.Count == 0)
            {
                string missing = missingAdapters.Count > 0
                    ? "\r\n\r\nNot present right now: " + string.Join(", ", missingAdapters.ToArray())
                    : "";
                throw new InvalidOperationException(
                    "No tunnel adapters are selected. Arming now would block the VPN itself, " +
                    "so nothing was changed." + missing + "\r\n\r\n" +
                    "If your VPN is a local proxy with no adapter of its own - V2rayN, Clash, " +
                    "sing-box without TUN mode - switch the mode to Proxy instead.");
            }

            SavePolicySnapshot();

            // Split tunnel routes go in first, while the network is still open.
            // Two reasons for the order: resolving a hostname exclusion needs DNS,
            // and the firewall holes below are built from the destinations that
            // were *actually* routed - so a hole is never opened for traffic that
            // would still have gone through the VPN.
            SplitTunnelResult split = SplitTunnelService.Apply(config);

            // Build the allow-list while the firewall is still permissive. If any
            // of this throws, the machine is still online and nothing is stranded.
            _fw.RemoveGroup(RuleGroup);
            BuildRules(config, interfaces, split.Targets);

            // Preflight before switching to default-deny. Two distinct failures
            // are possible and both matter:
            //   - filters missing  -> the allow rule matches nothing, and
            //                         default-deny would strand the machine.
            //   - filters empty    -> in the firewall API an empty interface list
            //                         means ALL interfaces, which would silently
            //                         defeat the kill switch and leak.
            List<CheckResult> checks = Verify(config);
            List<CheckResult> failed = new List<CheckResult>();
            foreach (CheckResult c in checks)
            {
                if (c.Fatal && !c.Passed) failed.Add(c);
            }

            if (failed.Count > 0)
            {
                _fw.RemoveGroup(RuleGroup);
                StringBuilder sb = new StringBuilder();
                foreach (CheckResult c in failed)
                {
                    if (sb.Length > 0) sb.Append("; ");
                    sb.Append(c.Check).Append(": ").Append(c.Detail);
                }
                Log.Error("Preflight failed, firewall policy left untouched. " + sb);
                throw new InvalidOperationException(
                    "Preflight check failed, so the kill switch was NOT armed and your internet " +
                    "is untouched.\r\n\r\n" + sb);
            }

            FwAction inbound = config.BlockInbound ? FwAction.Block : FwAction.Allow;
            _fw.SetAllProfileDefaults(true, inbound, FwAction.Block);

            Log.Ok(config.IsProxyMode
                ? "Kill switch ENABLED. Only the VPN client may reach the network directly; " +
                  "everything else must go through 127.0.0.1:" + config.ProxyListenPort + "."
                : "Kill switch ENABLED. All outbound traffic now requires the VPN tunnel.");
        }

        private void BuildRules(AppConfig config, List<string> interfaces, List<RouteTarget> splitTargets)
        {
            string[] ifaces = interfaces.ToArray();

            // 1. The tunnel itself.
            //
            //    Only when there is something to scope to. A rule carrying an
            //    empty interface list is not a narrow rule that matches nothing -
            //    the firewall reads it as EVERY interface, which would turn the
            //    first rule of the kill switch into a blanket permit. Proxy mode
            //    legitimately has no adapter, so this has to be a condition here
            //    rather than a check that fires after the fact.
            if (ifaces.Length > 0)
            {
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow VPN Tunnel (outbound)",
                    Description = "Permit all outbound traffic that leaves through the VPN tunnel adapter(s).",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    Interfaces = ifaces
                });
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow VPN Tunnel (inbound)",
                    Description = "Permit inbound traffic arriving on the VPN tunnel adapter(s).",
                    Direction = FwDirection.Inbound,
                    Action = FwAction.Allow,
                    Interfaces = ifaces
                });
            }

            // 2. The VPN client must still reach its server over the physical NIC,
            //    or the tunnel could never come back up after a drop.
            //
            //    In proxy mode these are not a supporting exception but the whole
            //    allow-list: the core process is the only thing on the machine
            //    with a path off the box, and every other app has to hand its
            //    bytes to that process over loopback to get anywhere.
            string endpoints = null;
            if (config.VpnServerEndpoints.Count > 0)
            {
                endpoints = string.Join(",", config.VpnServerEndpoints.ToArray());
            }

            string clientPurpose = config.IsProxyMode
                ? "Permit the VPN client to reach its server. In proxy mode this is the only permitted way out."
                : "Permit the VPN client to reach the VPN server so the tunnel can be established.";

            foreach (string exe in config.VpnClientPrograms)
            {
                if (!File.Exists(exe))
                {
                    Log.Warn("VPN client program not found, skipping: " + exe);
                    continue;
                }
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow VPN client " + Path.GetFileName(exe),
                    Description = clientPurpose,
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    ApplicationName = exe,
                    RemoteAddresses = endpoints
                });
            }

            // 3. DHCP, or the physical NIC never gets a lease and nothing works.
            if (config.AllowDhcp)
            {
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow DHCP (IPv4)",
                    Description = "Permit DHCPv4 so the physical adapter can obtain a lease.",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    Protocol = FirewallService.ProtocolUdp,
                    LocalPorts = "68",
                    RemotePorts = "67"
                });
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow DHCP (IPv6)",
                    Description = "Permit DHCPv6 so the physical adapter can obtain a lease.",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    Protocol = FirewallService.ProtocolUdp,
                    LocalPorts = "546",
                    RemotePorts = "547"
                });
            }

            // 4. Optionally let the VPN client resolve its server hostname. This is
            //    the one deliberate plaintext query outside the tunnel, and pinning
            //    VpnServerEndpoints to literal IPs removes the need for it.
            if (config.AllowVpnClientDns && endpoints == null)
            {
                foreach (string exe in config.VpnClientPrograms)
                {
                    if (!File.Exists(exe)) continue;
                    _fw.AddRule(RuleGroup, new RuleSpec
                    {
                        Name = Prefix + "Allow DNS for " + Path.GetFileName(exe),
                        Description = "Permit the VPN client to resolve the VPN server hostname.",
                        Direction = FwDirection.Outbound,
                        Action = FwAction.Allow,
                        ApplicationName = exe,
                        Protocol = FirewallService.ProtocolUdp,
                        RemotePorts = "53"
                    });
                }
            }

            // 5. Optional LAN access. Off by default because it also reopens DNS
            //    to your router, handing your browsing back to the ISP.
            if (config.AllowLan)
            {
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow LAN (outbound)",
                    Description = "Permit local network traffic (printers, NAS, router admin).",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    RemoteAddresses = "LocalSubnet,192.168.0.0/255.255.0.0,10.0.0.0/255.0.0.0,172.16.0.0/255.240.0.0,224.0.0.0/240.0.0.0,255.255.255.255"
                });
            }

            // 6. Deliberate holes for specific apps the user trusts outside the tunnel.
            foreach (string exe in config.AllowedPrograms)
            {
                if (!File.Exists(exe))
                {
                    Log.Warn("Allowed program not found, skipping: " + exe);
                    continue;
                }
                _fw.AddRule(RuleGroup, new RuleSpec
                {
                    Name = Prefix + "Allow program " + Path.GetFileName(exe),
                    Description = "User-approved program permitted outside the tunnel.",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    ApplicationName = exe
                });
            }

            // 7. Split tunnel. The routes are already in place; without a matching
            //    allow rule, default-deny would drop the very packets we just told
            //    Windows to send out the physical adapter.
            if (config.SplitTunnelEnabled) BuildSplitTunnelRules(config, splitTargets);
        }

        /// <summary>
        /// One allow rule per routed destination, plus one per excluded app.
        ///
        /// The destination rules are scoped by address rather than by interface on
        /// purpose: the address is what the user actually chose, and the route
        /// already decides the path. Interface-scoping them would add a second
        /// thing to go stale when the machine changes network, and would buy no
        /// security - the same destination is reachable through the tunnel anyway.
        /// </summary>
        private void BuildSplitTunnelRules(AppConfig config, List<RouteTarget> splitTargets)
        {
            List<string> used = new List<string>();

            if (splitTargets != null)
            {
                foreach (RouteTarget t in splitTargets)
                {
                    string name = Unique(used, Prefix + "Split tunnel " + t.Cidr);
                    try
                    {
                        _fw.AddRule(RuleGroup, new RuleSpec
                        {
                            Name = name,
                            Description = "Split tunnel exception for " + t.Source +
                                          ". Routed out the physical adapter, so it bypasses the VPN.",
                            Direction = FwDirection.Outbound,
                            Action = FwAction.Allow,
                            RemoteAddresses = t.FirewallAddress
                        });
                    }
                    catch (Exception ex)
                    {
                        // One malformed address must not abort arming, but the user
                        // has to know that destination ends up blocked rather than
                        // excluded.
                        Log.Warn("Split tunnel: the firewall rejected " + t.FirewallAddress +
                                 " (" + ex.Message + "). That destination will be blocked while armed.");
                    }
                }
            }

            foreach (string exe in config.SplitTunnelPrograms)
            {
                if (!File.Exists(exe))
                {
                    Log.Warn("Split tunnel app not found, skipping: " + exe);
                    continue;
                }
                string name = Unique(used, Prefix + "Split tunnel app " + Path.GetFileName(exe));
                try
                {
                    _fw.AddRule(RuleGroup, new RuleSpec
                    {
                        Name = name,
                        Description = "Split tunnel exception for " + exe +
                                      (config.IsProxyMode
                                          ? ". In proxy mode this is a full bypass: the app may reach the " +
                                            "internet directly instead of through the proxy."
                                          : ". Permitted outside the tunnel; see the README for what an app " +
                                            "exclusion can and cannot do."),
                        Direction = FwDirection.Outbound,
                        Action = FwAction.Allow,
                        ApplicationName = exe
                    });
                }
                catch (Exception ex)
                {
                    Log.Warn("Split tunnel: the firewall rejected " + exe + " (" + ex.Message + ").");
                }
            }

            // The bypass proxy makes its outbound connections itself, so the
            // permission it needs is on RestrictVPN.exe rather than on the app
            // being proxied. This is the widest hole this app can open, which is
            // why it exists only while the proxy is switched on.
            if (config.BypassProxyEnabled)
            {
                try
                {
                    _fw.AddRule(RuleGroup, new RuleSpec
                    {
                        Name = Unique(used, Prefix + "Split tunnel bypass proxy"),
                        Description = "Lets the bypass proxy reach the internet over the physical adapter " +
                                      "on behalf of the apps you launch outside the VPN.",
                        Direction = FwDirection.Outbound,
                        Action = FwAction.Allow,
                        ApplicationName = Paths.Exe
                    });
                    Log.Info("Split tunnel: the bypass proxy is allowed outside the tunnel (" + Paths.Exe + ").");
                }
                catch (Exception ex)
                {
                    Log.Warn("Split tunnel: could not allow the bypass proxy (" + ex.Message +
                             "). Apps launched outside the VPN will have no internet while armed.");
                }
            }
            else if (config.SplitTunnelPrograms.Count > 0)
            {
                // The same rule means two different things depending on the mode,
                // and saying the tunnel-mode thing in proxy mode would be exactly
                // backwards. In tunnel mode the VPN owns the default route, so a
                // permitted app still takes the tunnel and needs the bypass proxy
                // to be moved off it. In proxy mode nothing has taken the default
                // route away from the physical NIC - the proxy is a destination,
                // not a path - so permitting an app is all it takes for that app
                // to go direct.
                Log.Info(config.IsProxyMode
                    ? "Split tunnel: " + config.SplitTunnelPrograms.Count + " app rule(s) are a full bypass " +
                      "in proxy mode - those apps reach the internet directly, with your real IP, and do " +
                      "not need the bypass proxy to do it."
                    : "Split tunnel: bypass proxy is off, so the " + config.SplitTunnelPrograms.Count +
                      " app rule(s) permit traffic but do not move it off the tunnel.");
            }
        }

        /// <summary>Rule names are the firewall's key, so two entries must never collide.</summary>
        private static string Unique(List<string> used, string name)
        {
            string candidate = name;
            int n = 2;
            while (used.Contains(candidate)) candidate = name + " (" + (n++) + ")";
            used.Add(candidate);
            return candidate;
        }

        // ------------------------------------------------------------- disable

        public void Disable()
        {
            Log.Info("=== Disabling kill switch ===");
            RestorePolicySnapshot();
            _fw.RemoveGroup(RuleGroup);

            // Split tunnel routes deliberately survive a disarm: they follow the
            // SplitTunnelEnabled setting, not the kill switch, so "keep this off
            // the VPN" stays true whether or not the firewall is locked down.
            SplitState split = SplitState.Load();
            if (split.Routes.Count > 0)
            {
                Log.Info("Split tunnel left in place (" + split.Routes.Count +
                         " route(s)). Turn split tunnel off, or use Emergency recover, to remove them.");
            }

            Log.Ok("Kill switch DISABLED. Normal (unprotected) internet access restored.");
        }

        /// <summary>
        /// Emergency recovery. Forces outbound back to Allow without trusting the
        /// snapshot file to exist or be valid.
        /// </summary>
        public void Recover()
        {
            Log.Warn("=== EMERGENCY RECOVERY ===");
            _fw.SetAllProfileDefaults(true, FwAction.Block, FwAction.Allow);
            _fw.RemoveGroup(RuleGroup);

            // The blunt instrument takes the routing back too, so a split tunnel
            // route pointing at a gateway that is no longer there cannot be the
            // reason something still looks broken.
            try { SplitTunnelService.Remove(); }
            catch (Exception ex) { Log.Warn("Could not remove split tunnel routes: " + ex.Message); }
            try { if (File.Exists(Paths.State)) File.Delete(Paths.State); }
            catch { }
            Log.Ok("Outbound access forced back to Allow; RestrictVPN rules and split tunnel routes removed.");
        }

        // -------------------------------------------------------------- verify

        public List<CheckResult> Verify(AppConfig config)
        {
            List<CheckResult> results = new List<CheckResult>();
            // Fatal checks run against the adapters that exist: Enable arms with
            // that same filtered list, so a "(not present)" entry must warn here,
            // never fail the preflight for rules that were built correctly.
            List<string> missing;
            List<string> expected;
            AdapterService.SplitExistingAliases(
                config.AllAllowedInterfaces(), out expected, out missing);
            List<RuleInfo> liveRules = _fw.GetRulesInGroup(RuleGroup);

            if (config.IsProxyMode) VerifyProxyMode(config, liveRules, results);

            foreach (string alias in missing)
            {
                results.Add(new CheckResult("Adapter present: " + alias, false, false,
                    "Not present right now - skipped when arming. Untick it to stop seeing this."));
            }

            // In proxy mode there is no tunnel adapter unless the client is in
            // TUN mode, so the interface checks below only apply when adapters
            // were actually ticked. Skipping them is safe: the proxy checks
            // above are fatal in their place, so the arm path is never left
            // without a preflight that can stop it.
            if (config.IsProxyMode && expected.Count == 0)
            {
                if (config.SplitTunnelEnabled) VerifySplitTunnel(config, liveRules, results);
                return results;
            }

            RuleInfo tunnelRule = null;
            foreach (RuleInfo r in liveRules)
            {
                if (r.Name != null && r.Name.IndexOf("Allow VPN Tunnel (outbound)",
                        StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    tunnelRule = r;
                    break;
                }
            }

            if (tunnelRule == null)
            {
                results.Add(new CheckResult("Tunnel allow rule exists", false, true,
                    "Rule not found - the kill switch is not armed."));
                return results;
            }
            results.Add(new CheckResult("Tunnel allow rule exists", true, true, tunnelRule.Name));

            string[] bound = tunnelRule.Interfaces ?? new string[0];
            string boundList = bound.Length == 0 ? "(none - would match ALL interfaces)" : string.Join(", ", bound);

            // An empty interface list is the dangerous case: the firewall reads it
            // as "every interface", which quietly turns the kill switch into a
            // permit-all rule. Treat it as fatal, not as a pass.
            results.Add(new CheckResult("Interface filter is scoped", bound.Length > 0, true,
                bound.Length > 0
                    ? "Scoped to " + bound.Length + " interface(s)"
                    : "Interface list came back EMPTY, which the firewall treats as ALL interfaces."));

            foreach (string alias in expected)
            {
                bool ok = false;
                foreach (string b in bound)
                {
                    if (string.Equals(b, alias, StringComparison.OrdinalIgnoreCase)) { ok = true; break; }
                }
                results.Add(new CheckResult("Interface bound: " + alias, ok, true,
                    ok ? "Bound" : "NOT bound. Live filters: " + boundList));
            }

            foreach (string exe in config.VpnClientPrograms)
            {
                results.Add(new CheckResult(
                    "VPN client present: " + Path.GetFileName(exe),
                    File.Exists(exe), false, exe));
            }

            if (config.SplitTunnelEnabled) VerifySplitTunnel(config, liveRules, results);

            return results;
        }

        /// <summary>
        /// The proxy-mode counterpart of the interface checks: it is looking for
        /// the same two failures, in the form they take when the allow-list is
        /// made of processes rather than adapters.
        ///
        ///   - no client rule at all -> nothing may leave, and default-deny would
        ///     strand the machine with no way for the proxy to reconnect.
        ///   - a rule with no program on it -> the firewall reads a missing
        ///     ApplicationName as EVERY program, which would quietly turn the
        ///     kill switch into a permit-all. This is the one that fails open, so
        ///     it is the more dangerous of the two and is checked explicitly.
        /// </summary>
        private void VerifyProxyMode(AppConfig config, List<RuleInfo> liveRules, List<CheckResult> results)
        {
            List<RuleInfo> clientRules = new List<RuleInfo>();
            foreach (RuleInfo r in liveRules)
            {
                if (r.Name != null &&
                    r.Name.StartsWith(Prefix + "Allow VPN client", StringComparison.OrdinalIgnoreCase))
                {
                    clientRules.Add(r);
                }
            }

            results.Add(new CheckResult("Proxy mode: client allow rule exists", clientRules.Count > 0, true,
                clientRules.Count > 0
                    ? clientRules.Count + " rule(s) for the VPN client"
                    : "No client rule found - nothing would be able to reach the network."));

            if (clientRules.Count == 0) return;

            int unscoped = 0;
            foreach (RuleInfo r in clientRules)
            {
                if (string.IsNullOrEmpty(r.ApplicationName)) unscoped++;
            }

            results.Add(new CheckResult("Proxy mode: rules are scoped to a program", unscoped == 0, true,
                unscoped == 0
                    ? "Every client rule names an executable."
                    : unscoped + " rule(s) came back with NO program, which the firewall treats as ALL programs."));

            // Each configured program should have made it into a live rule. A
            // missing one is not fatal - the others still carry the connection -
            // but it is exactly how a client half-loses its network after an
            // update moves an executable.
            foreach (string exe in config.VpnClientPrograms)
            {
                if (!File.Exists(exe))
                {
                    results.Add(new CheckResult("VPN client present: " + Path.GetFileName(exe),
                        false, false, "Not on disk: " + exe));
                    continue;
                }

                bool bound = false;
                foreach (RuleInfo r in clientRules)
                {
                    if (string.Equals(r.ApplicationName, exe, StringComparison.OrdinalIgnoreCase))
                    {
                        bound = true;
                        break;
                    }
                }
                results.Add(new CheckResult("Client rule bound: " + Path.GetFileName(exe), bound, false,
                    bound ? exe : "No live rule names this executable - re-arm to rebuild it."));
            }

            results.Add(new CheckResult("Proxy mode: client is listening",
                ProxyClientService.IsProxyListening(config.ProxyListenPort), false,
                "127.0.0.1:" + config.ProxyListenPort +
                (ProxyClientService.IsProxyListening(config.ProxyListenPort)
                    ? " is accepting connections."
                    : " is not accepting. Apps have no way out until the client is started.")));
        }

        /// <summary>
        /// Split tunnel checks are never fatal. Every way this half can break -
        /// a route that did not install, a rule the firewall rejected - leaves the
        /// destination going through the VPN or blocked outright. It fails closed,
        /// so it can cost you an app but never your real IP.
        /// </summary>
        private void VerifySplitTunnel(AppConfig config, List<RuleInfo> liveRules, List<CheckResult> results)
        {
            SplitState split = SplitState.Load();

            int ruleCount = 0;
            foreach (RuleInfo r in liveRules)
            {
                if (r.Name != null &&
                    r.Name.StartsWith(Prefix + "Split tunnel", StringComparison.OrdinalIgnoreCase))
                {
                    ruleCount++;
                }
            }

            Underlay underlay = RouteService.Find(config);
            results.Add(new CheckResult("Split tunnel: physical adapter found", underlay != null, false,
                underlay != null
                    ? underlay.Summary
                    : "No non-tunnel adapter with a default gateway. Nothing can bypass the VPN."));

            int wantedAddresses = 0;
            foreach (string a in config.SplitTunnelAddresses)
            {
                if (!string.IsNullOrEmpty(a) && !a.TrimStart().StartsWith("#")) wantedAddresses++;
            }

            results.Add(new CheckResult("Split tunnel: routes installed",
                split.Routes.Count > 0 || wantedAddresses == 0, false,
                split.Routes.Count + " route(s) recorded for " + wantedAddresses + " destination entry(ies)"));

            int wantedRules = split.Routes.Count;
            foreach (string exe in config.SplitTunnelPrograms)
            {
                if (File.Exists(exe)) wantedRules++;
            }

            if (config.BypassProxyEnabled) wantedRules++;

            results.Add(new CheckResult("Split tunnel: allow rules present",
                ruleCount >= wantedRules, false,
                ruleCount + " rule(s) live, " + wantedRules + " expected" +
                (ruleCount < wantedRules ? " - re-arm to rebuild them" : "")));

            if (config.BypassProxyEnabled)
            {
                results.Add(new CheckResult("Split tunnel: bypass proxy listening",
                    BypassProxy.IsRunning, false, BypassProxy.Status));
            }
        }

        // ------------------------------------------------------------ selftest

        private const string TestGroup = "RestrictVPN Self Test";

        /// <summary>
        /// Proves the mechanism works on this machine without arming anything.
        ///
        /// The whole kill switch rests on one assumption: that a firewall rule
        /// scoped to an interface really binds to that interface. This creates a
        /// DISABLED probe rule, reads the binding back, and deletes it. A disabled
        /// rule filters nothing, so live traffic is never affected either way.
        /// </summary>
        public List<CheckResult> SelfTest(AppConfig config)
        {
            List<CheckResult> results = new List<CheckResult>();
            // The probe carries the same names the real rules would, so it gets
            // the same filtering: a stale entry must never reach put_Interfaces,
            // where it kills the process instead of failing the test.
            List<string> missing;
            List<string> expected;
            AdapterService.SplitExistingAliases(
                config.AllAllowedInterfaces(), out expected, out missing);

            // Proxy mode rehearses the program-scoped rule instead, since that is
            // the mechanism it will actually rely on.
            if (config.IsProxyMode && expected.Count == 0) return SelfTestProxyMode(config);

            if (expected.Count == 0)
            {
                string detail = "No tunnel adapters are ticked, so there is nothing to test.";
                if (missing.Count > 0)
                {
                    detail = "None of the ticked adapters are present right now (" +
                             string.Join(", ", missing.ToArray()) +
                             "). Reconnect the VPN or untick them.";
                }
                results.Add(new CheckResult("Adapters selected", false, true, detail));
                return results;
            }

            foreach (string alias in missing)
            {
                results.Add(new CheckResult("Adapter present: " + alias, false, false,
                    "Not present - skipped by the probe, and skipped when arming."));
            }

            try
            {
                _fw.RemoveGroup(TestGroup);
                _fw.AddRule(TestGroup, new RuleSpec
                {
                    Name = "RestrictVPN - Self test probe (disabled, safe to delete)",
                    Description = "Temporary disabled rule used to verify interface binding. Removed automatically.",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    Interfaces = expected.ToArray(),
                    Enabled = false
                });
                results.Add(new CheckResult("Can create firewall rules", true, true,
                    "Probe rule created (disabled, affects no traffic)."));

                RuleInfo probe = null;
                foreach (RuleInfo r in _fw.GetRulesInGroup(TestGroup)) { probe = r; break; }

                if (probe == null)
                {
                    results.Add(new CheckResult("Probe rule readable", false, true,
                        "The rule was created but could not be read back."));
                    return results;
                }

                string[] bound = probe.Interfaces ?? new string[0];
                results.Add(new CheckResult("Interface scoping supported", bound.Length > 0, true,
                    bound.Length > 0
                        ? "Bound to: " + string.Join(", ", bound)
                        : "Interface list came back EMPTY - the firewall would treat this as ALL interfaces."));

                foreach (string alias in expected)
                {
                    bool ok = false;
                    foreach (string b in bound)
                    {
                        if (string.Equals(b, alias, StringComparison.OrdinalIgnoreCase)) { ok = true; break; }
                    }
                    results.Add(new CheckResult("Binds to adapter: " + alias, ok, true,
                        ok ? "Confirmed" : "Did not bind. The adapter name may have changed."));
                }

                foreach (string exe in config.VpnClientPrograms)
                {
                    results.Add(new CheckResult("VPN client present: " + Path.GetFileName(exe),
                        File.Exists(exe), false, exe));
                }
            }
            catch (Exception ex)
            {
                results.Add(new CheckResult("Self test", false, true, ex.Message));
            }
            finally
            {
                try { _fw.RemoveGroup(TestGroup); }
                catch { }
            }

            return results;
        }

        /// <summary>
        /// The proxy-mode rehearsal. Same shape as the interface one and the same
        /// promise: a DISABLED probe rule is created, read back, and deleted, so
        /// no live traffic is filtered either way.
        ///
        /// What it proves is that a rule scoped to an executable really binds to
        /// that executable, since in proxy mode that binding is the whole kill
        /// switch. It also reports whether the client is listening, which is not
        /// a property of the firewall but is the first thing to check when
        /// nothing can reach the internet after arming.
        /// </summary>
        private List<CheckResult> SelfTestProxyMode(AppConfig config)
        {
            List<CheckResult> results = new List<CheckResult>();
            List<string> live = config.ExistingClientPrograms();

            results.Add(new CheckResult("VPN client programs found", live.Count > 0, true,
                live.Count > 0
                    ? live.Count + " of " + config.VpnClientPrograms.Count + " configured program(s) exist on disk"
                    : "None of the configured programs exist. Arming would leave nothing able to reach the network."));

            if (live.Count == 0) return results;

            string probeExe = live[0];

            try
            {
                _fw.RemoveGroup(TestGroup);
                _fw.AddRule(TestGroup, new RuleSpec
                {
                    Name = "RestrictVPN - Self test probe (disabled, safe to delete)",
                    Description = "Temporary disabled rule used to verify program binding. Removed automatically.",
                    Direction = FwDirection.Outbound,
                    Action = FwAction.Allow,
                    ApplicationName = probeExe,
                    Enabled = false
                });
                results.Add(new CheckResult("Can create firewall rules", true, true,
                    "Probe rule created (disabled, affects no traffic)."));

                RuleInfo probe = null;
                foreach (RuleInfo r in _fw.GetRulesInGroup(TestGroup)) { probe = r; break; }

                if (probe == null)
                {
                    results.Add(new CheckResult("Probe rule readable", false, true,
                        "The rule was created but could not be read back."));
                    return results;
                }

                bool scoped = !string.IsNullOrEmpty(probe.ApplicationName);
                results.Add(new CheckResult("Program scoping supported", scoped, true,
                    scoped
                        ? "Bound to: " + probe.ApplicationName
                        : "Program came back EMPTY - the firewall would treat this as ALL programs."));

                if (scoped)
                {
                    bool same = string.Equals(probe.ApplicationName, probeExe, StringComparison.OrdinalIgnoreCase);
                    results.Add(new CheckResult("Binds to the right program", same, true,
                        same ? "Confirmed" : "Read back as " + probe.ApplicationName + " instead of " + probeExe));
                }

                foreach (string exe in config.VpnClientPrograms)
                {
                    results.Add(new CheckResult("VPN client present: " + Path.GetFileName(exe),
                        File.Exists(exe), false, exe));
                }

                bool listening = ProxyClientService.IsProxyListening(config.ProxyListenPort);
                results.Add(new CheckResult("Client is listening", listening, false,
                    "127.0.0.1:" + config.ProxyListenPort +
                    (listening
                        ? " is accepting connections."
                        : " is not accepting. Start the VPN client before arming, or apps will have no way out.")));
            }
            catch (Exception ex)
            {
                results.Add(new CheckResult("Self test", false, true, ex.Message));
            }
            finally
            {
                try { _fw.RemoveGroup(TestGroup); }
                catch { }
            }

            return results;
        }

        // ------------------------------------------------------------ snapshot

        /// <summary>
        /// Records the firewall policy that was in place before we first armed,
        /// so Disable can put it back exactly. Written once and only once.
        /// Schema matches the PowerShell tooling in src\.
        /// </summary>
        private void SavePolicySnapshot()
        {
            if (File.Exists(Paths.State)) return;

            // Prefer the cmdlets: they can express "NotConfigured", which COM
            // reports as its effective value instead. Capturing that distinction
            // is what lets Disable put the policy back byte-for-byte.
            List<ProfilePolicy> captured = PolicyStore.Read();
            if (captured == null)
            {
                Log.Warn("Falling back to COM for the policy snapshot; a NotConfigured " +
                         "default will be restored as its effective value.");
                captured = new List<ProfilePolicy>();
                foreach (ProfileState p in _fw.GetProfiles())
                {
                    ProfilePolicy pp = new ProfilePolicy();
                    pp.Name = p.Name;
                    pp.Enabled = p.Enabled ? "True" : "False";
                    pp.Inbound = p.DefaultInbound.ToString();
                    pp.Outbound = p.DefaultOutbound.ToString();
                    captured.Add(pp);
                }
            }

            Paths.EnsureDirs();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"CapturedAt\": \"" + DateTime.Now.ToString("o") + "\",");
            sb.AppendLine("  \"Profiles\": [");

            for (int i = 0; i < captured.Count; i++)
            {
                ProfilePolicy p = captured[i];
                sb.AppendLine("    {");
                sb.AppendLine("      \"Name\": \"" + p.Name + "\",");
                sb.AppendLine("      \"Enabled\": \"" + p.Enabled + "\",");
                sb.AppendLine("      \"DefaultInboundAction\": \"" + p.Inbound + "\",");
                sb.AppendLine("      \"DefaultOutboundAction\": \"" + p.Outbound + "\"");
                sb.AppendLine(i < captured.Count - 1 ? "    }," : "    }");
            }
            sb.AppendLine("  ]");
            sb.Append("}");

            File.WriteAllText(Paths.State, sb.ToString(), new UTF8Encoding(false));
            Log.Info("Saved pre-kill-switch firewall policy snapshot.");
        }

        private void RestorePolicySnapshot()
        {
            if (!File.Exists(Paths.State))
            {
                Log.Warn("No snapshot found; restoring Windows defaults (outbound Allow, inbound Block).");
                _fw.SetAllProfileDefaults(true, FwAction.Block, FwAction.Allow);
                return;
            }

            try
            {
                string raw = File.ReadAllText(Paths.State, Encoding.UTF8);
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> map = ser.DeserializeObject(raw) as Dictionary<string, object>;

                object profilesObj = null;
                if (map == null || !map.TryGetValue("Profiles", out profilesObj) || profilesObj == null)
                {
                    throw new InvalidDataException("snapshot has no Profiles array");
                }

                // First choice: hand the recorded strings straight back to the
                // cmdlets, so a NotConfigured default is restored as NotConfigured.
                List<ProfilePolicy> recorded = new List<ProfilePolicy>();
                foreach (object o in (IEnumerable)profilesObj)
                {
                    Dictionary<string, object> d = o as Dictionary<string, object>;
                    if (d == null) continue;
                    ProfilePolicy pp = new ProfilePolicy();
                    pp.Name = Str(d, "Name");
                    pp.Enabled = Str(d, "Enabled");
                    pp.Inbound = Str(d, "DefaultInboundAction");
                    pp.Outbound = Str(d, "DefaultOutboundAction");
                    recorded.Add(pp);
                }

                if (PolicyStore.Restore(recorded))
                {
                    File.Delete(Paths.State);
                    Log.Ok("Restored previous firewall policy from snapshot.");
                    return;
                }

                Log.Warn("Cmdlet restore unavailable; falling back to COM.");

                List<ProfileState> live = _fw.GetProfiles();
                foreach (object entryObj in (IEnumerable)profilesObj)
                {
                    Dictionary<string, object> entry = entryObj as Dictionary<string, object>;
                    if (entry == null) continue;

                    string name = Str(entry, "Name");
                    ProfileState target = null;
                    foreach (ProfileState p in live)
                    {
                        if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) { target = p; break; }
                    }
                    if (target == null) continue;

                    // "NotConfigured" comes from the PowerShell tooling and has no
                    // COM equivalent, so it maps to the Windows default it means:
                    // outbound Allow, inbound Block.
                    bool enabled = !string.Equals(Str(entry, "Enabled"), "False", StringComparison.OrdinalIgnoreCase);
                    FwAction inbound = string.Equals(Str(entry, "DefaultInboundAction"), "Allow", StringComparison.OrdinalIgnoreCase)
                        ? FwAction.Allow : FwAction.Block;
                    FwAction outbound = string.Equals(Str(entry, "DefaultOutboundAction"), "Block", StringComparison.OrdinalIgnoreCase)
                        ? FwAction.Block : FwAction.Allow;

                    _fw.SetProfileDefaults(target.Id, enabled, inbound, outbound);
                }

                File.Delete(Paths.State);
                Log.Ok("Restored previous firewall policy from snapshot.");
            }
            catch (Exception ex)
            {
                Log.Warn("Snapshot unreadable (" + ex.Message + "); restoring Windows defaults instead.");
                _fw.SetAllProfileDefaults(true, FwAction.Block, FwAction.Allow);
                try { if (File.Exists(Paths.State)) File.Delete(Paths.State); }
                catch { }
            }
        }

        private static string Str(Dictionary<string, object> map, string key)
        {
            object v;
            if (map.TryGetValue(key, out v) && v != null) return v.ToString();
            return "";
        }
    }
}
