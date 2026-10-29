using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace RestrictVpn
{
    internal class AdapterInfo
    {
        public string Alias;
        public string Description;
        public string Status;
        public int Index = -1;
        public List<string> IPv4 = new List<string>();
        public bool IsTunnelCandidate;
        public bool CarriesInternet;
    }

    internal static class AdapterService
    {
        /// <summary>
        /// Interface descriptions that identify a VPN tunnel rather than real hardware.
        /// </summary>
        private static readonly string[] TunnelPatterns = new string[]
        {
            "TAP-Windows Adapter",
            "Wintun",
            "OpenVPN Data Channel Offload",
            "OpenVPN",
            "WireGuard",
            "TAP-Win32",
            // The TUN adapters a local-proxy client raises when TUN mode is on.
            // Most of them are Wintun underneath and are already caught above,
            // but they are named here too so the ones that are not still show up.
            "sing-box",
            "singbox",
            "Mihomo",
            "Clash",
            "v2rayN"
        };

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestInterface(uint destAddr, out uint bestIfIndex);

        /// <summary>
        /// The interface index Windows would actually use to reach the public
        /// internet right now. This is what proves a tunnel is carrying traffic:
        /// an adapter can sit "Up" with a stale address long after the VPN died,
        /// so adapter status alone is not evidence of anything.
        ///
        /// Routing is unaffected by firewall rules, so this stays accurate even
        /// while the kill switch is blocking everything.
        /// </summary>
        public static int GetInternetInterfaceIndex()
        {
            return GetBestInterfaceIndexFor(IPAddress.Parse("8.8.8.8"));
        }

        /// <summary>
        /// The interface index Windows would use to reach one specific IPv4
        /// destination. Asking about an adapter's own default gateway is how the
        /// split tunnel confirms that gateway is really on-link there: the answer
        /// is the physical NIC even while the tunnel owns the default route.
        /// Returns -1 for IPv6, which GetBestInterface cannot answer.
        /// </summary>
        public static int GetBestInterfaceIndexFor(IPAddress destination)
        {
            try
            {
                if (destination == null ||
                    destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return -1;
                }

                byte[] bytes = destination.GetAddressBytes();
                uint dest = BitConverter.ToUInt32(bytes, 0);   // already network byte order

                uint best;
                if (GetBestInterface(dest, out best) == 0) return (int)best;
            }
            catch { }
            return -1;
        }

        public static bool LooksLikeTunnel(string description, string alias)
        {
            if (string.IsNullOrEmpty(description)) description = "";
            if (description.IndexOf("WAN Miniport", StringComparison.OrdinalIgnoreCase) >= 0) return false;

            foreach (string p in TunnelPatterns)
            {
                if (description.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        public static List<AdapterInfo> GetAdapters()
        {
            List<AdapterInfo> list = new List<AdapterInfo>();
            int internetIndex = GetInternetInterfaceIndex();

            NetworkInterface[] all;
            try { all = NetworkInterface.GetAllNetworkInterfaces(); }
            catch { return list; }

            foreach (NetworkInterface ni in all)
            {
                AdapterInfo a = new AdapterInfo();
                a.Alias = ni.Name;
                a.Description = ni.Description;
                a.Status = ni.OperationalStatus.ToString();
                a.IsTunnelCandidate = LooksLikeTunnel(ni.Description, ni.Name);

                try
                {
                    IPInterfaceProperties props = ni.GetIPProperties();
                    try { a.Index = props.GetIPv4Properties().Index; }
                    catch { a.Index = -1; }

                    foreach (UnicastIPAddressInformation ip in props.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                        string s = ip.Address.ToString();
                        if (s.StartsWith("169.254.")) continue;   // APIPA means "no real address"
                        a.IPv4.Add(s);
                    }
                }
                catch { }

                a.CarriesInternet = (a.Index >= 0 && a.Index == internetIndex);
                list.Add(a);
            }
            return list;
        }

        public static List<AdapterInfo> GetTunnelCandidates()
        {
            List<AdapterInfo> result = new List<AdapterInfo>();
            foreach (AdapterInfo a in GetAdapters())
            {
                if (a.IsTunnelCandidate) result.Add(a);
            }
            result.Sort(delegate(AdapterInfo x, AdapterInfo y)
            {
                return string.Compare(x.Alias, y.Alias, StringComparison.OrdinalIgnoreCase);
            });
            return result;
        }

        /// <summary>
        /// True when the interface currently carrying internet traffic is one of
        /// the allow-listed tunnel adapters.
        /// </summary>
        public static bool IsTunnelCarryingInternet(IList<string> tunnelAliases)
        {
            if (tunnelAliases == null || tunnelAliases.Count == 0) return false;

            foreach (AdapterInfo a in GetAdapters())
            {
                if (!a.CarriesInternet) continue;
                foreach (string alias in tunnelAliases)
                {
                    if (string.Equals(alias, a.Alias, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Splits an allow-list into adapters that exist right now and ones that
        /// do not.
        ///
        /// This must run before any alias reaches INetFwRule.put_Interfaces: that
        /// setter resolves every name against the interface table, and an array
        /// containing a name with no adapter behind it kills the process inside
        /// native code - no managed exception, no log line, the window just
        /// vanishes. A single unknown name returns catchable "Element not found",
        /// but a mixed array does not come back at all. Filtering here keeps a
        /// stale "(not present)" entry from turning ARM into a crash.
        /// </summary>
        public static void SplitExistingAliases(
            IEnumerable<string> aliases, out List<string> existing, out List<string> missing)
        {
            existing = new List<string>();
            missing = new List<string>();

            List<string> present = new List<string>();
            foreach (AdapterInfo a in GetAdapters())
            {
                if (!string.IsNullOrEmpty(a.Alias)) present.Add(a.Alias);
            }

            if (aliases == null) return;
            foreach (string alias in aliases)
            {
                if (string.IsNullOrEmpty(alias)) continue;

                bool found = false;
                foreach (string name in present)
                {
                    if (string.Equals(name, alias, StringComparison.OrdinalIgnoreCase))
                    {
                        found = true;
                        break;
                    }
                }

                List<string> target = found ? existing : missing;
                bool dup = false;
                foreach (string s in target)
                {
                    if (string.Equals(s, alias, StringComparison.OrdinalIgnoreCase)) { dup = true; break; }
                }
                if (!dup) target.Add(alias);
            }
        }
    }
}
