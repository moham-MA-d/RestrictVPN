using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Web.Script.Serialization;

namespace RestrictVpn
{
    /// <summary>Shared JSON escaping, so every hand-written file uses one encoder.</summary>
    internal static class Json
    {
        public static string Quote(string s)
        {
            if (s == null) return "\"\"";
            StringBuilder sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }
    }

    // =========================================================================
    // Model
    // =========================================================================

    /// <summary>One destination network the split tunnel steers around the VPN.</summary>
    internal class RouteTarget
    {
        public string Source;      // the config entry it came from, for logging
        public string Network;     // canonical network address (host bits cleared)
        public int Prefix;
        public bool IsV6;

        public string Cidr
        {
            get { return Network + "/" + Prefix; }
        }

        /// <summary>
        /// The same network in the form INetFwRule.RemoteAddresses accepts. IPv4
        /// wants a dotted mask (or a bare address for a single host); IPv6 uses
        /// prefix notation.
        /// </summary>
        public string FirewallAddress
        {
            get
            {
                if (Prefix >= (IsV6 ? 128 : 32)) return Network;   // a single host
                if (IsV6) return Network + "/" + Prefix;
                return Network + "/" + IpMath.MaskV4(Prefix);      // the firewall wants a dotted mask for IPv4
            }
        }
    }

    /// <summary>
    /// The physical path excluded traffic takes: a real adapter that owns a
    /// default gateway, as opposed to the VPN tunnel.
    /// </summary>
    internal class Underlay
    {
        public string Alias;
        public string Description;
        public int IfIndex = -1;       // IPv4 interface index
        public int IfIndexV6 = -1;
        public string GatewayV4;
        public string GatewayV6;
        public int Score;

        public bool HasV4 { get { return IfIndex > 0 && !string.IsNullOrEmpty(GatewayV4); } }
        public bool HasV6 { get { return IfIndexV6 > 0 && !string.IsNullOrEmpty(GatewayV6); } }

        public string Summary
        {
            get
            {
                string gw = GatewayV4;
                if (string.IsNullOrEmpty(gw)) gw = GatewayV6;
                return Alias + " (gateway " + (gw ?? "none") + ")";
            }
        }
    }

    /// <summary>A route this app added and is therefore responsible for removing.</summary>
    internal class AppliedRoute
    {
        public string Source;
        public string Cidr;
        public string Gateway;
        public int IfIndex;
        public bool IsV6;
    }

    internal class SplitTunnelResult
    {
        public bool Enabled;
        public Underlay Underlay;
        public List<RouteTarget> Targets = new List<RouteTarget>();   // successfully routed
        public List<string> Problems = new List<string>();
        public int ProgramCount;
    }

    // =========================================================================
    // Address arithmetic
    // =========================================================================

    internal static class IpMath
    {
        public static IPAddress Network(IPAddress addr, int prefix)
        {
            byte[] b = addr.GetAddressBytes();
            for (int i = 0; i < b.Length; i++)
            {
                int keep = prefix - i * 8;
                if (keep >= 8) continue;
                if (keep <= 0) b[i] = 0;
                else b[i] = (byte)(b[i] & (0xFF << (8 - keep)));
            }
            return new IPAddress(b);
        }

        public static string MaskV4(int prefix)
        {
            uint m = prefix <= 0 ? 0u : (prefix >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix)));
            return string.Format("{0}.{1}.{2}.{3}",
                (m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF);
        }
    }

    // =========================================================================
    // Persisted state
    // =========================================================================

    /// <summary>
    /// What the split tunnel currently has installed. The routes are added
    /// non-persistent (store=active) on purpose - a stale persistent route
    /// surviving into a different network is exactly the sort of silent
    /// misdirection this app exists to avoid - so this file is how we still know
    /// what to clean up after a restart.
    /// </summary>
    internal class SplitState
    {
        public string AppliedAt = "";
        public string UnderlayAlias = "";
        public List<AppliedRoute> Routes = new List<AppliedRoute>();

        public static SplitState Load()
        {
            SplitState s = new SplitState();
            if (!File.Exists(Paths.SplitState)) return s;

            try
            {
                string raw = File.ReadAllText(Paths.SplitState, Encoding.UTF8);
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> map = ser.DeserializeObject(raw) as Dictionary<string, object>;
                if (map == null) return s;

                s.AppliedAt = Str(map, "AppliedAt");
                s.UnderlayAlias = Str(map, "UnderlayAlias");

                object routes;
                if (!map.TryGetValue("Routes", out routes) || routes == null) return s;

                foreach (object o in (IEnumerable)routes)
                {
                    Dictionary<string, object> d = o as Dictionary<string, object>;
                    if (d == null) continue;

                    AppliedRoute r = new AppliedRoute();
                    r.Source = Str(d, "Source");
                    r.Cidr = Str(d, "Cidr");
                    r.Gateway = Str(d, "Gateway");
                    r.IsV6 = string.Equals(Str(d, "IsV6"), "True", StringComparison.OrdinalIgnoreCase) ||
                             Str(d, "IsV6") == "true";
                    int idx;
                    int.TryParse(Str(d, "IfIndex"), out idx);
                    r.IfIndex = idx;

                    if (r.Cidr.Length > 0) s.Routes.Add(r);
                }
            }
            catch (Exception ex)
            {
                Log.Warn("Could not read splittunnel.json (" + ex.Message + "). " +
                         "Any routes it recorded will have to be cleared by hand or by a reboot.");
            }
            return s;
        }

        public void Save()
        {
            try
            {
                Paths.EnsureDirs();
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("{");
                sb.AppendLine("  \"AppliedAt\": " + Json.Quote(DateTime.Now.ToString("o")) + ",");
                sb.AppendLine("  \"UnderlayAlias\": " + Json.Quote(UnderlayAlias ?? "") + ",");
                sb.AppendLine("  \"Routes\": [");
                for (int i = 0; i < Routes.Count; i++)
                {
                    AppliedRoute r = Routes[i];
                    sb.AppendLine("    {");
                    sb.AppendLine("      \"Source\": " + Json.Quote(r.Source) + ",");
                    sb.AppendLine("      \"Cidr\": " + Json.Quote(r.Cidr) + ",");
                    sb.AppendLine("      \"Gateway\": " + Json.Quote(r.Gateway) + ",");
                    sb.AppendLine("      \"IfIndex\": " + r.IfIndex + ",");
                    sb.AppendLine("      \"IsV6\": " + (r.IsV6 ? "true" : "false"));
                    sb.AppendLine(i < Routes.Count - 1 ? "    }," : "    }");
                }
                sb.AppendLine("  ]");
                sb.Append("}");

                File.WriteAllText(Paths.SplitState, sb.ToString(), new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                Log.Warn("Could not write splittunnel.json (" + ex.Message + ").");
            }
        }

        public static void Delete()
        {
            try { if (File.Exists(Paths.SplitState)) File.Delete(Paths.SplitState); }
            catch { }
        }

        private static string Str(Dictionary<string, object> map, string key)
        {
            object v;
            if (map.TryGetValue(key, out v) && v != null) return v.ToString();
            return "";
        }
    }

    // =========================================================================
    // Routing
    // =========================================================================

    /// <summary>
    /// Finds the physical path and installs the host routes that make excluded
    /// traffic prefer it.
    ///
    /// Why routes at all: OpenVPN takes over the default route (usually as
    /// 0.0.0.0/1 + 128.0.0.0/1, which outrank a real default route without
    /// replacing it). A firewall rule cannot move a packet - it can only permit
    /// or drop one - so a firewall-only "exclusion" would still hand the packet
    /// to the tunnel. A more specific route via the physical gateway wins on
    /// longest-prefix match, and that is what actually keeps the traffic off the
    /// VPN.
    /// </summary>
    internal static class RouteService
    {
        private static readonly string[] VirtualMarkers = new string[]
        {
            "vEthernet", "Hyper-V", "Virtual", "VMware", "VirtualBox", "Loopback",
            "Bluetooth", "WSL", "Docker", "Npcap", "Pseudo"
        };

        /// <summary>
        /// Every adapter that could carry excluded traffic: up, not a tunnel, and
        /// holding a default gateway of its own.
        /// </summary>
        public static List<Underlay> Candidates(AppConfig config)
        {
            List<Underlay> found = new List<Underlay>();
            List<string> tunnels = config != null ? config.TunnelInterfaceAliases : new List<string>();

            NetworkInterface[] all;
            try { all = NetworkInterface.GetAllNetworkInterfaces(); }
            catch { return found; }

            foreach (NetworkInterface ni in all)
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (AdapterService.LooksLikeTunnel(ni.Description, ni.Name)) continue;

                bool isTunnel = false;
                foreach (string alias in tunnels)
                {
                    if (string.Equals(alias, ni.Name, StringComparison.OrdinalIgnoreCase)) { isTunnel = true; break; }
                }
                if (isTunnel) continue;

                Underlay u = new Underlay();
                u.Alias = ni.Name;
                u.Description = ni.Description;

                bool hasRealIPv4 = false;
                try
                {
                    IPInterfaceProperties props = ni.GetIPProperties();

                    foreach (GatewayIPAddressInformation g in props.GatewayAddresses)
                    {
                        if (g == null || g.Address == null) continue;
                        string text = g.Address.ToString();
                        if (g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            if (text != "0.0.0.0" && u.GatewayV4 == null) u.GatewayV4 = text;
                        }
                        else if (g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            if (text != "::" && u.GatewayV6 == null)
                            {
                                // A link-local next hop is only usable with its zone id,
                                // which the interface index supplies separately.
                                int zone = text.IndexOf('%');
                                u.GatewayV6 = zone > 0 ? text.Substring(0, zone) : text;
                            }
                        }
                    }

                    try { u.IfIndex = props.GetIPv4Properties().Index; }
                    catch { u.IfIndex = -1; }
                    try { u.IfIndexV6 = props.GetIPv6Properties().Index; }
                    catch { u.IfIndexV6 = -1; }

                    foreach (UnicastIPAddressInformation ip in props.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                        if (ip.Address.ToString().StartsWith("169.254.")) continue;
                        hasRealIPv4 = true;
                    }
                }
                catch { continue; }

                if (u.GatewayV4 == null && u.GatewayV6 == null) continue;

                u.Score = ScoreOf(ni, u, hasRealIPv4);
                found.Add(u);
            }

            found.Sort(delegate(Underlay x, Underlay y) { return y.Score.CompareTo(x.Score); });
            return found;
        }

        private static int ScoreOf(NetworkInterface ni, Underlay u, bool hasRealIPv4)
        {
            int score = 0;

            if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                ni.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet ||
                ni.NetworkInterfaceType == NetworkInterfaceType.FastEthernetT)
            {
                score += 40;
            }

            string haystack = (u.Alias ?? "") + " " + (u.Description ?? "");
            foreach (string marker in VirtualMarkers)
            {
                if (haystack.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score -= 60;
                    break;
                }
            }

            // The decisive signal: ask Windows which interface reaches this
            // adapter's own gateway. The gateway is on-link, so the answer is the
            // physical NIC even while the tunnel holds the default route.
            if (u.HasV4)
            {
                score += 20;
                IPAddress gw;
                if (IPAddress.TryParse(u.GatewayV4, out gw) &&
                    AdapterService.GetBestInterfaceIndexFor(gw) == u.IfIndex)
                {
                    score += 50;
                }
            }
            if (hasRealIPv4) score += 10;

            return score;
        }

        /// <summary>
        /// The adapter excluded traffic should leave through. Honours an explicit
        /// SplitTunnelUnderlayAlias, otherwise picks the best-scoring candidate.
        /// </summary>
        public static Underlay Find(AppConfig config)
        {
            List<Underlay> candidates = Candidates(config);
            if (candidates.Count == 0) return null;

            string pinned = config != null ? (config.SplitTunnelUnderlayAlias ?? "").Trim() : "";
            if (pinned.Length > 0)
            {
                foreach (Underlay u in candidates)
                {
                    if (string.Equals(u.Alias, pinned, StringComparison.OrdinalIgnoreCase)) return u;
                }
                Log.Warn("Split tunnel: pinned adapter '" + pinned + "' is not available; " +
                         "falling back to auto-detection.");
            }
            return candidates[0];
        }

        // ------------------------------------------------------------- netsh

        private static bool Run(string args, out string output)
        {
            output = "";
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process p = Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(15000))
                    {
                        try { p.Kill(); }
                        catch { }
                        output = "netsh did not finish within 15 seconds";
                        return false;
                    }
                    output = (stdout + " " + stderr).Trim();
                    return p.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                output = ex.Message;
                return false;
            }
        }

        private static string Family(bool v6) { return v6 ? "ipv6" : "ipv4"; }

        public static bool Add(RouteTarget target, int ifIndex, string gateway, out string error)
        {
            string args = string.Format(
                "interface {0} add route prefix={1} interface={2} nexthop={3} metric=1 store=active",
                Family(target.IsV6), target.Cidr, ifIndex, gateway);

            string output;
            if (Run(args, out output)) { error = null; return true; }

            // Adding over an identical route is not a failure; the end state is
            // the one we wanted either way.
            if (output.IndexOf("already exists", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                error = null;
                return true;
            }

            error = output.Length > 0 ? output : "netsh refused the route";
            return false;
        }

        public static bool Delete(AppliedRoute route, out string output)
        {
            string args = string.Format(
                "interface {0} delete route prefix={1} interface={2} nexthop={3} store=active",
                Family(route.IsV6), route.Cidr, route.IfIndex, route.Gateway);
            return Run(args, out output);
        }
    }

    // =========================================================================
    // Service
    // =========================================================================

    /// <summary>
    /// Split tunnelling: destinations (and apps) the user deliberately keeps off
    /// the VPN.
    ///
    /// Two halves, and both are needed while the kill switch is armed:
    ///   routing  - a more specific route via the physical gateway, so the packet
    ///              is handed to the NIC instead of the tunnel;
    ///   firewall - an allow rule, because default-deny would otherwise drop the
    ///              packet the moment it stopped using the tunnel interface.
    ///
    /// The firewall rules are built from the destinations that were *actually*
    /// routed, so a hole is never opened for traffic that would still go through
    /// the VPN anyway.
    /// </summary>
    internal static class SplitTunnelService
    {
        private static readonly object Gate = new object();
        private static string _summary = "Split tunnel: off";

        /// <summary>Cheap, lock-free text for the UI to poll.</summary>
        public static string Summary { get { return _summary; } }

        /// <summary>
        /// Everything the split tunnel was asked to do, on one line. Logged at
        /// startup and on every apply, so a log can always be read back without
        /// having to guess what the settings were at the time.
        /// </summary>
        public static string DescribeConfig(AppConfig c)
        {
            return "enabled=" + c.SplitTunnelEnabled +
                   ", destinations=" + c.SplitTunnelAddresses.Count +
                   ", apps=" + c.SplitTunnelPrograms.Count +
                   ", bypassProxy=" + c.BypassProxyEnabled + " (port " + c.BypassProxyPort + ")" +
                   ", adapter=" + (string.IsNullOrEmpty(c.SplitTunnelUnderlayAlias)
                                       ? "auto" : c.SplitTunnelUnderlayAlias);
        }

        // ------------------------------------------------------------- parsing

        /// <summary>
        /// Turns the config entries into concrete networks. Accepts a literal IPv4
        /// or IPv6 address, a CIDR, or a hostname (resolved now).
        /// </summary>
        public static List<RouteTarget> Resolve(AppConfig config, SplitState previous, List<string> problems)
        {
            List<RouteTarget> list = new List<RouteTarget>();
            if (config == null) return list;

            foreach (string raw in config.SplitTunnelAddresses)
            {
                string entry = (raw ?? "").Trim();
                if (entry.Length == 0 || entry.StartsWith("#")) continue;
                ParseInto(entry, list, previous, problems);
            }

            // Two entries can legitimately resolve to the same network; installing
            // the route twice would just make the second attempt fail.
            List<RouteTarget> unique = new List<RouteTarget>();
            foreach (RouteTarget t in list)
            {
                bool seen = false;
                foreach (RouteTarget u in unique)
                {
                    if (u.Cidr == t.Cidr) { seen = true; break; }
                }
                if (!seen) unique.Add(t);
            }
            return unique;
        }

        private static void ParseInto(string entry, List<RouteTarget> into,
                                      SplitState previous, List<string> problems)
        {
            string host = entry;
            int prefix = -1;

            int slash = entry.IndexOf('/');
            if (slash >= 0)
            {
                host = entry.Substring(0, slash).Trim();
                string tail = entry.Substring(slash + 1).Trim();
                if (!int.TryParse(tail, out prefix))
                {
                    problems.Add(entry + ": '" + tail + "' is not a prefix length.");
                    return;
                }
            }

            IPAddress ip;
            if (IPAddress.TryParse(host, out ip))
            {
                RouteTarget t = MakeTarget(entry, ip, prefix, problems);
                if (t != null) into.Add(t);
                return;
            }

            if (slash >= 0)
            {
                problems.Add(entry + ": a prefix length only applies to a literal IP address.");
                return;
            }

            IPAddress[] resolved = null;
            string failure = null;
            try { resolved = Dns.GetHostAddresses(host); }
            catch (Exception ex) { failure = ex.Message; }

            if (resolved == null || resolved.Length == 0)
            {
                // DNS is the first thing to go when the tunnel is down, and losing
                // an exclusion at that moment would be the worst possible timing.
                // Carry forward whatever this entry resolved to last time.
                List<RouteTarget> carried = FromPrevious(previous, entry);
                if (carried.Count > 0)
                {
                    problems.Add(entry + ": could not be resolved now (" + (failure ?? "no addresses") +
                                 "), reusing the " + carried.Count + " address(es) from last time.");
                    into.AddRange(carried);
                }
                else
                {
                    problems.Add(entry + ": could not be resolved (" + (failure ?? "no addresses") +
                                 "), so nothing was excluded for it.");
                }
                return;
            }

            foreach (IPAddress addr in resolved)
            {
                RouteTarget t = MakeTarget(entry, addr, -1, problems);
                if (t != null) into.Add(t);
            }
        }

        private static RouteTarget MakeTarget(string source, IPAddress ip, int prefix, List<string> problems)
        {
            bool v6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            int max = v6 ? 128 : 32;
            if (prefix < 0) prefix = max;

            if (prefix > max)
            {
                problems.Add(source + ": /" + prefix + " is too long for this address family.");
                return null;
            }

            // A prefix of 0 is the default route. Excluding that is not split
            // tunnelling, it is turning the VPN off, so refuse it outright.
            if (prefix == 0)
            {
                problems.Add(source + ": /0 would send everything around the VPN. Refused.");
                return null;
            }

            if (IPAddress.IsLoopback(ip))
            {
                problems.Add(source + ": loopback needs no route. Skipped.");
                return null;
            }

            RouteTarget t = new RouteTarget();
            t.Source = source;
            t.IsV6 = v6;
            t.Prefix = prefix;
            t.Network = IpMath.Network(ip, prefix).ToString();
            return t;
        }

        private static List<RouteTarget> FromPrevious(SplitState previous, string source)
        {
            List<RouteTarget> list = new List<RouteTarget>();
            if (previous == null) return list;

            foreach (AppliedRoute r in previous.Routes)
            {
                if (!string.Equals(r.Source, source, StringComparison.OrdinalIgnoreCase)) continue;

                int slash = r.Cidr.IndexOf('/');
                if (slash < 0) continue;

                int prefix;
                if (!int.TryParse(r.Cidr.Substring(slash + 1), out prefix)) continue;

                RouteTarget t = new RouteTarget();
                t.Source = source;
                t.Network = r.Cidr.Substring(0, slash);
                t.Prefix = prefix;
                t.IsV6 = r.IsV6;
                list.Add(t);
            }
            return list;
        }

        // --------------------------------------------------------------- apply

        /// <summary>
        /// Brings the routing table in line with the config: removes every route
        /// this app previously installed, then installs the ones wanted now.
        ///
        /// Removing first means a changed list, a changed gateway or a hopped
        /// network can never leave an orphan pointing at a gateway that is no
        /// longer there. The brief gap in between sends that traffic through the
        /// VPN, which is the safe direction to fail.
        /// </summary>
        public static SplitTunnelResult Apply(AppConfig config)
        {
            lock (Gate)
            {
                SplitTunnelResult result = new SplitTunnelResult();
                result.Enabled = config.SplitTunnelEnabled;

                Log.Info("Split tunnel config: " + DescribeConfig(config));

                SplitState previous = SplitState.Load();
                ClearRoutes(previous);

                SplitState next = new SplitState();

                if (!config.SplitTunnelEnabled)
                {
                    SplitState.Delete();
                    _summary = "Split tunnel: off";
                    if (previous.Routes.Count > 0) Log.Info("Split tunnel disabled; its routes were removed.");
                    return result;
                }

                result.ProgramCount = CountExistingPrograms(config, result.Problems);

                List<RouteTarget> desired = Resolve(config, previous, result.Problems);
                Underlay underlay = RouteService.Find(config);
                result.Underlay = underlay;

                Log.Info("Split tunnel: " + desired.Count + " destination(s) resolved, physical adapter " +
                         (underlay != null
                              ? underlay.Alias + " if4=" + underlay.IfIndex + " gw4=" + (underlay.GatewayV4 ?? "none") +
                                " if6=" + underlay.IfIndexV6 + " gw6=" + (underlay.GatewayV6 ?? "none")
                              : "NOT FOUND"));

                if (desired.Count == 0 && config.SplitTunnelPrograms.Count > 0 && !config.BypassProxyEnabled)
                {
                    // The exact combination that quietly does nothing. Name it.
                    Log.Warn("Split tunnel: apps are listed but there are no destinations and the bypass " +
                             "proxy is off, so nothing will actually leave the VPN. An app entry is only a " +
                             "firewall permission - turn on the bypass proxy, or add destinations.");
                }

                if (desired.Count > 0 && underlay == null)
                {
                    result.Problems.Add(
                        "No physical adapter with a default gateway is available, so no destination " +
                        "could be steered around the VPN.");
                }
                else if (underlay != null)
                {
                    next.UnderlayAlias = underlay.Alias;

                    int skippedV6 = 0;
                    int skippedV4 = 0;

                    foreach (RouteTarget t in desired)
                    {
                        string gateway = t.IsV6 ? underlay.GatewayV6 : underlay.GatewayV4;
                        int ifIndex = t.IsV6 ? underlay.IfIndexV6 : underlay.IfIndex;

                        if (string.IsNullOrEmpty(gateway) || ifIndex <= 0)
                        {
                            // Nothing to be done about it, and on a v4-only network
                            // every hostname produces one of these, so count them
                            // and say it once at the end.
                            if (t.IsV6) skippedV6++; else skippedV4++;
                            continue;
                        }

                        string error;
                        if (RouteService.Add(t, ifIndex, gateway, out error))
                        {
                            Log.Info("Split tunnel: routed " + t.Cidr + " via " + gateway +
                                     " on if " + ifIndex + " (from '" + t.Source + "')");
                            AppliedRoute r = new AppliedRoute();
                            r.Source = t.Source;
                            r.Cidr = t.Cidr;
                            r.Gateway = gateway;
                            r.IfIndex = ifIndex;
                            r.IsV6 = t.IsV6;
                            next.Routes.Add(r);
                            result.Targets.Add(t);
                        }
                        else
                        {
                            result.Problems.Add(t.Source + " -> " + t.Cidr + ": " + error);
                        }
                    }

                    if (skippedV6 > 0)
                    {
                        result.Problems.Add(skippedV6 + " IPv6 destination(s) skipped: " + underlay.Alias +
                                            " has no IPv6 gateway, so they stay on the VPN.");
                    }
                    if (skippedV4 > 0)
                    {
                        result.Problems.Add(skippedV4 + " IPv4 destination(s) skipped: " + underlay.Alias +
                                            " has no IPv4 gateway, so they stay on the VPN.");
                    }
                }

                next.Save();
                _summary = BuildSummary(result);

                Log.Info("Split tunnel applied: " + result.Targets.Count + " destination route(s), " +
                         result.ProgramCount + " app(s)" +
                         (underlay != null ? " via " + underlay.Summary : " (no physical adapter)") + ".");
                foreach (string p in result.Problems) Log.Warn("Split tunnel: " + p);

                return result;
            }
        }

        /// <summary>Removes every route this app installed and forgets about them.</summary>
        public static void Remove()
        {
            lock (Gate)
            {
                SplitState previous = SplitState.Load();
                int count = previous.Routes.Count;
                ClearRoutes(previous);
                SplitState.Delete();
                _summary = "Split tunnel: off";
                if (count > 0) Log.Ok("Split tunnel routes removed (" + count + ").");
            }
        }

        private static void ClearRoutes(SplitState state)
        {
            foreach (AppliedRoute r in state.Routes)
            {
                string output;
                if (!RouteService.Delete(r, out output))
                {
                    // After a reboot the route is already gone, because we add
                    // them non-persistent. Not worth a warning.
                    Log.Info("Split tunnel: route " + r.Cidr + " was not removed (" + output + ").");
                }
            }
        }

        private static int CountExistingPrograms(AppConfig config, List<string> problems)
        {
            int count = 0;
            foreach (string exe in config.SplitTunnelPrograms)
            {
                if (File.Exists(exe)) count++;
                else problems.Add("excluded app not found, skipped: " + exe);
            }
            return count;
        }

        private static string BuildSummary(SplitTunnelResult result)
        {
            if (!result.Enabled) return "Split tunnel: off";

            StringBuilder sb = new StringBuilder("Split tunnel: ");
            sb.Append(result.Targets.Count).Append(result.Targets.Count == 1 ? " destination" : " destinations");
            sb.Append(", ").Append(result.ProgramCount).Append(result.ProgramCount == 1 ? " app" : " apps");
            sb.Append(result.Underlay != null ? "  ->  " + result.Underlay.Summary : "  ->  no physical adapter found");
            if (result.Problems.Count > 0) sb.Append("   [").Append(result.Problems.Count).Append(" warning(s)]");
            return sb.ToString();
        }

        /// <summary>Restores the summary text from disk when the app starts.</summary>
        public static void PrimeSummary(AppConfig config)
        {
            if (!config.SplitTunnelEnabled)
            {
                _summary = "Split tunnel: off";
                return;
            }
            SplitState state = SplitState.Load();
            _summary = "Split tunnel: " + state.Routes.Count +
                       (state.Routes.Count == 1 ? " destination" : " destinations") +
                       ", " + config.SplitTunnelPrograms.Count +
                       (config.SplitTunnelPrograms.Count == 1 ? " app" : " apps") +
                       (state.UnderlayAlias.Length > 0 ? "  ->  " + state.UnderlayAlias : "");
        }

        /// <summary>
        /// True when the physical path has moved out from under the routes we
        /// installed - a different Wi-Fi network, a cable plugged in, a gateway
        /// change. Cheap enough for the UI timer: it only inspects adapters.
        /// </summary>
        public static bool NeedsReapply(AppConfig config)
        {
            if (!config.SplitTunnelEnabled) return false;

            SplitState state = SplitState.Load();
            Underlay underlay = RouteService.Find(config);
            if (underlay == null) return false;

            if (!string.Equals(state.UnderlayAlias, underlay.Alias, StringComparison.OrdinalIgnoreCase)) return true;

            foreach (AppliedRoute r in state.Routes)
            {
                string expected = r.IsV6 ? underlay.GatewayV6 : underlay.GatewayV4;
                if (!string.Equals(r.Gateway, expected, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}
