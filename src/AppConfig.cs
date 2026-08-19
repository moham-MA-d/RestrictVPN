using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace RestrictVpn
{
    /// <summary>
    /// Settings, stored as config.json next to the executable. The schema is
    /// shared with the PowerShell tooling in src\, so either can read it.
    /// </summary>
    internal class AppConfig
    {
        public List<string> TunnelInterfaceAliases = new List<string>();
        public List<string> ExtraAllowedInterfaceAliases = new List<string>();
        public List<string> VpnClientPrograms = new List<string>();
        public List<string> VpnServerEndpoints = new List<string>();
        public List<string> AllowedPrograms = new List<string>();

        // Split tunnel: destinations and apps deliberately kept off the VPN.
        public List<string> SplitTunnelAddresses = new List<string>();
        public List<string> SplitTunnelPrograms = new List<string>();
        public string SplitTunnelUnderlayAlias = "";
        public bool SplitTunnelEnabled = false;

        // The loopback SOCKS5 proxy that lets a proxy-aware app bypass the VPN.
        public bool BypassProxyEnabled = false;
        public int BypassProxyPort = 1080;

        public bool AllowLan = false;
        public bool AllowDhcp = true;
        public bool AllowVpnClientDns = true;
        public bool BlockInbound = true;
        public bool ArmAtBoot = false;

        private const string Comment =
            "RestrictVPN config. TunnelInterfaceAliases is the allow-list of adapters traffic " +
            "may leave through. While the kill switch is on, every other outbound path is blocked. " +
            "SplitTunnelAddresses and SplitTunnelPrograms are the deliberate exceptions routed around the VPN.";

        private static readonly string[] VpnProgramSearchDirs = new string[]
        {
            @"%ProgramFiles%\OpenVPN Connect",
            @"%ProgramFiles(x86)%\OpenVPN Connect",
            @"%ProgramFiles%\OpenVPN\bin",
            @"%ProgramFiles(x86)%\OpenVPN\bin",
            @"%LOCALAPPDATA%\Programs\OpenVPN Connect"
        };

        // ------------------------------------------------------------ discovery

        public static List<string> DiscoverVpnPrograms()
        {
            List<string> found = new List<string>();
            foreach (string raw in VpnProgramSearchDirs)
            {
                string dir = Environment.ExpandEnvironmentVariables(raw);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                try
                {
                    foreach (string exe in Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly))
                    {
                        if (!found.Contains(exe)) found.Add(exe);
                    }
                }
                catch { }
            }
            found.Sort(StringComparer.OrdinalIgnoreCase);
            return found;
        }

        public static AppConfig CreateDefault()
        {
            AppConfig c = new AppConfig();
            c.VpnClientPrograms = DiscoverVpnPrograms();

            foreach (AdapterInfo a in AdapterService.GetTunnelCandidates())
            {
                // Prefer adapters that exist and are not permanently absent.
                if (a.Status == "NotPresent") continue;
                c.TunnelInterfaceAliases.Add(a.Alias);
            }
            return c;
        }

        // ----------------------------------------------------------- load/save

        public static AppConfig Load()
        {
            if (!File.Exists(Paths.Config))
            {
                AppConfig fresh = CreateDefault();
                fresh.Save();
                Log.Info("Created default config at " + Paths.Config);
                return fresh;
            }

            try
            {
                string raw = File.ReadAllText(Paths.Config, Encoding.UTF8);
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> map =
                    ser.DeserializeObject(raw) as Dictionary<string, object>;

                if (map == null) throw new InvalidDataException("config.json is not a JSON object.");

                AppConfig c = new AppConfig();
                c.TunnelInterfaceAliases = Strings(map, "TunnelInterfaceAliases");
                c.ExtraAllowedInterfaceAliases = Strings(map, "ExtraAllowedInterfaceAliases");
                c.VpnClientPrograms = Strings(map, "VpnClientPrograms");
                c.VpnServerEndpoints = Strings(map, "VpnServerEndpoints");
                c.AllowedPrograms = Strings(map, "AllowedPrograms");
                c.SplitTunnelAddresses = Strings(map, "SplitTunnelAddresses");
                c.SplitTunnelPrograms = Strings(map, "SplitTunnelPrograms");
                c.SplitTunnelUnderlayAlias = Text(map, "SplitTunnelUnderlayAlias");
                c.SplitTunnelEnabled = Bool(map, "SplitTunnelEnabled", false);
                c.BypassProxyEnabled = Bool(map, "BypassProxyEnabled", false);
                c.BypassProxyPort = Int(map, "BypassProxyPort", 1080);
                c.AllowLan = Bool(map, "AllowLan", false);
                c.AllowDhcp = Bool(map, "AllowDhcp", true);
                c.AllowVpnClientDns = Bool(map, "AllowVpnClientDns", true);
                c.BlockInbound = Bool(map, "BlockInbound", true);
                c.ArmAtBoot = Bool(map, "ArmAtBoot", false);

                // A config with no client programs is almost certainly stale
                // rather than intentional, so re-discover instead of leaving the
                // VPN unable to reconnect.
                if (c.VpnClientPrograms.Count == 0) c.VpnClientPrograms = DiscoverVpnPrograms();

                return c;
            }
            catch (Exception ex)
            {
                Log.Warn("Could not read config.json (" + ex.Message + "). Using defaults.");
                return CreateDefault();
            }
        }

        public void Save()
        {
            Paths.EnsureDirs();

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"_comment\": " + Quote(Comment) + ",");
            sb.AppendLine("  " + Quote("TunnelInterfaceAliases") + ": " + Array(TunnelInterfaceAliases) + ",");
            sb.AppendLine("  " + Quote("ExtraAllowedInterfaceAliases") + ": " + Array(ExtraAllowedInterfaceAliases) + ",");
            sb.AppendLine("  " + Quote("VpnClientPrograms") + ": " + Array(VpnClientPrograms) + ",");
            sb.AppendLine("  " + Quote("VpnServerEndpoints") + ": " + Array(VpnServerEndpoints) + ",");
            sb.AppendLine("  " + Quote("AllowedPrograms") + ": " + Array(AllowedPrograms) + ",");
            sb.AppendLine("  " + Quote("SplitTunnelEnabled") + ": " + Bool(SplitTunnelEnabled) + ",");
            sb.AppendLine("  " + Quote("SplitTunnelAddresses") + ": " + Array(SplitTunnelAddresses) + ",");
            sb.AppendLine("  " + Quote("SplitTunnelPrograms") + ": " + Array(SplitTunnelPrograms) + ",");
            sb.AppendLine("  " + Quote("SplitTunnelUnderlayAlias") + ": " + Quote(SplitTunnelUnderlayAlias ?? "") + ",");
            sb.AppendLine("  " + Quote("BypassProxyEnabled") + ": " + Bool(BypassProxyEnabled) + ",");
            sb.AppendLine("  " + Quote("BypassProxyPort") + ": " + BypassProxyPort + ",");
            sb.AppendLine("  " + Quote("AllowLan") + ": " + Bool(AllowLan) + ",");
            sb.AppendLine("  " + Quote("AllowDhcp") + ": " + Bool(AllowDhcp) + ",");
            sb.AppendLine("  " + Quote("AllowVpnClientDns") + ": " + Bool(AllowVpnClientDns) + ",");
            sb.AppendLine("  " + Quote("BlockInbound") + ": " + Bool(BlockInbound) + ",");
            sb.AppendLine("  " + Quote("ArmAtBoot") + ": " + Bool(ArmAtBoot));
            sb.Append("}");

            File.WriteAllText(Paths.Config, sb.ToString(), new UTF8Encoding(false));
        }

        /// <summary>Every interface permitted to carry traffic while armed.</summary>
        public List<string> AllAllowedInterfaces()
        {
            List<string> all = new List<string>();
            foreach (string s in TunnelInterfaceAliases)
            {
                if (!string.IsNullOrEmpty(s) && !all.Contains(s)) all.Add(s);
            }
            foreach (string s in ExtraAllowedInterfaceAliases)
            {
                if (!string.IsNullOrEmpty(s) && !all.Contains(s)) all.Add(s);
            }
            return all;
        }

        // -------------------------------------------------------------- helpers

        private static List<string> Strings(Dictionary<string, object> map, string key)
        {
            List<string> result = new List<string>();
            object value;
            if (!map.TryGetValue(key, out value) || value == null) return result;

            IEnumerable seq = value as IEnumerable;
            if (seq != null && !(value is string))
            {
                foreach (object o in seq)
                {
                    if (o == null) continue;
                    string s = o.ToString().Trim();
                    if (s.Length > 0 && !result.Contains(s)) result.Add(s);
                }
            }
            else
            {
                string s = value.ToString().Trim();
                if (s.Length > 0) result.Add(s);
            }
            return result;
        }

        private static bool Bool(Dictionary<string, object> map, string key, bool fallback)
        {
            object value;
            if (!map.TryGetValue(key, out value) || value == null) return fallback;
            try { return Convert.ToBoolean(value); }
            catch { return fallback; }
        }

        private static int Int(Dictionary<string, object> map, string key, int fallback)
        {
            object value;
            if (!map.TryGetValue(key, out value) || value == null) return fallback;
            try
            {
                int parsed = Convert.ToInt32(value);
                return parsed > 0 && parsed < 65536 ? parsed : fallback;
            }
            catch { return fallback; }
        }

        private static string Text(Dictionary<string, object> map, string key)
        {
            object value;
            if (!map.TryGetValue(key, out value) || value == null) return "";
            return value.ToString().Trim();
        }

        private static string Bool(bool b) { return b ? "true" : "false"; }

        private static string Quote(string s) { return Json.Quote(s); }

        private static string Array(List<string> items)
        {
            if (items == null || items.Count == 0) return "[]";
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append(",");
                sb.AppendLine();
                sb.Append("    ").Append(Quote(items[i]));
            }
            sb.AppendLine();
            sb.Append("  ]");
            return sb.ToString();
        }
    }
}
