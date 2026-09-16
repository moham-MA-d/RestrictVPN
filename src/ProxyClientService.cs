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
    /// <summary>
    /// A VPN client that presents a local proxy instead of a tunnel adapter:
    /// V2rayN, and everything shaped like it. The core process holds the
    /// connection to the server and every other app reaches it over loopback,
    /// so there is no interface to scope a firewall rule to.
    /// </summary>
    internal class ProxyClientInfo
    {
        public string Name = "";
        public string BaseDir = "";
        public string SettingsPath = "";
        public List<string> Programs = new List<string>();
        public int ListenPort;
        public bool TunModeEnabled;

        public string Summary
        {
            get
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(Name.Length > 0 ? Name : "local proxy client");
                if (BaseDir.Length > 0) sb.Append(" at ").Append(BaseDir);
                sb.Append(", ").Append(Programs.Count).Append(" program(s)");
                if (ListenPort > 0) sb.Append(", listening on 127.0.0.1:").Append(ListenPort);
                if (TunModeEnabled) sb.Append(", TUN mode ON");
                return sb.ToString();
            }
        }
    }

    /// <summary>
    /// Finds a local-proxy VPN client and reports whether it is live.
    ///
    /// Discovery leads with the running process rather than a list of install
    /// paths: V2rayN is portable and is as likely to sit on a second drive as
    /// anywhere a static list would think to look.
    /// </summary>
    internal static class ProxyClientService
    {
        /// <summary>GUI process names that identify a local-proxy client.</summary>
        private static readonly string[] GuiProcessNames = new string[]
        {
            "v2rayN", "nekoray", "nekobox", "clash-verge", "Clash for Windows", "Clash Verge"
        };

        /// <summary>Core process names. These hold the actual connection to the server.</summary>
        private static readonly string[] CoreProcessNames = new string[]
        {
            "xray", "v2ray", "sing-box", "sing_box", "mihomo", "clash", "clash-meta",
            "hysteria", "tuic", "juicity", "naive", "shadowsocks", "sslocal"
        };

        /// <summary>
        /// Where a portable client keeps its cores, relative to the GUI exe.
        /// V2rayN uses bin\{core}\{core}.exe.
        /// </summary>
        private static readonly string[] CoreSubDirs = new string[]
        {
            "bin", @"bin\xray", @"bin\Xray", @"bin\v2fly", @"bin\v2fly_v5",
            @"bin\sing_box", @"bin\sing-box", @"bin\mihomo", @"bin\clash", @"bin\hysteria"
        };

        /// <summary>Fallback install locations, used only when nothing is running.</summary>
        private static readonly string[] SearchDirs = new string[]
        {
            @"%LOCALAPPDATA%\v2rayN",
            @"%ProgramFiles%\v2rayN",
            @"%ProgramFiles(x86)%\v2rayN",
            @"%USERPROFILE%\Desktop\v2rayN",
            @"%USERPROFILE%\Downloads\v2rayN"
        };

        public const int DefaultListenPort = 10808;

        // ------------------------------------------------------------ discovery

        /// <summary>
        /// Locates the local-proxy client on this machine, or null if there is
        /// none. Never throws: a failed probe means "not found", not an error.
        /// </summary>
        public static ProxyClientInfo Detect()
        {
            string baseDir = FindBaseDirFromRunningProcess();

            if (string.IsNullOrEmpty(baseDir))
            {
                foreach (string raw in SearchDirs)
                {
                    string dir = SafeExpand(raw);
                    if (dir.Length == 0 || !Directory.Exists(dir)) continue;
                    baseDir = dir;
                    break;
                }
            }

            if (string.IsNullOrEmpty(baseDir)) return null;

            ProxyClientInfo info = new ProxyClientInfo();
            info.Name = "V2rayN";
            info.BaseDir = baseDir;
            info.Programs = CollectPrograms(baseDir);
            info.ListenPort = DefaultListenPort;

            ReadSettings(baseDir, info);

            // A directory with no executables is not an install, it is a
            // coincidence. Report nothing found rather than arming against it.
            if (info.Programs.Count == 0) return null;

            return info;
        }

        /// <summary>Every executable this client needs a hole for.</summary>
        public static List<string> DiscoverPrograms()
        {
            ProxyClientInfo info = Detect();
            return info == null ? new List<string>() : info.Programs;
        }

        private static string FindBaseDirFromRunningProcess()
        {
            // The GUI is the anchor: it sits beside bin\, so finding it finds the
            // cores too. Falling back to a running core covers the case where the
            // GUI was closed but the connection is still up.
            string fromGui = FindProcessDir(GuiProcessNames, false);
            if (fromGui != null) return fromGui;

            return FindProcessDir(CoreProcessNames, true);
        }

        /// <summary>
        /// Directory of the first running process matching one of these names.
        /// When climb is true the result walks up out of bin\{core}\ to the
        /// install root, because a core exe is nested two levels down.
        /// </summary>
        private static string FindProcessDir(string[] names, bool climb)
        {
            foreach (string name in names)
            {
                Process[] procs;
                try { procs = Process.GetProcessesByName(name); }
                catch { continue; }

                foreach (Process p in procs)
                {
                    string path = null;
                    try { path = p.MainModule.FileName; }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }

                    if (string.IsNullOrEmpty(path)) continue;

                    string dir;
                    try { dir = Path.GetDirectoryName(path); }
                    catch { continue; }
                    if (string.IsNullOrEmpty(dir)) continue;

                    if (!climb) return dir;

                    string root = ClimbOutOfBin(dir);
                    return root != null ? root : dir;
                }
            }
            return null;
        }

        private static string ClimbOutOfBin(string dir)
        {
            try
            {
                DirectoryInfo d = new DirectoryInfo(dir);
                for (int i = 0; i < 3 && d != null && d.Parent != null; i++)
                {
                    if (string.Equals(d.Name, "bin", StringComparison.OrdinalIgnoreCase))
                    {
                        return d.Parent.FullName;
                    }
                    d = d.Parent;
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// The GUI plus every core binary under bin\. Only files that look like a
        /// proxy core are taken - a portable install also ships helpers such as
        /// AmazTool.exe and EnableLoopback.exe, which never touch the network and
        /// have no business holding a firewall exception.
        /// </summary>
        private static List<string> CollectPrograms(string baseDir)
        {
            List<string> found = new List<string>();

            foreach (string gui in GuiProcessNames)
            {
                string exe = Path.Combine(baseDir, gui + ".exe");
                if (File.Exists(exe) && !Contains(found, exe)) found.Add(exe);
            }

            foreach (string sub in CoreSubDirs)
            {
                string dir = Path.Combine(baseDir, sub);
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (string exe in files)
                {
                    if (!LooksLikeCore(Path.GetFileNameWithoutExtension(exe))) continue;
                    if (!Contains(found, exe)) found.Add(exe);
                }
            }

            found.Sort(StringComparer.OrdinalIgnoreCase);
            return found;
        }

        private static bool LooksLikeCore(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return false;
            foreach (string core in CoreProcessNames)
            {
                if (fileName.IndexOf(core, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        // ------------------------------------------------------------- settings

        /// <summary>
        /// Reads the listen port and TUN state out of the client's own settings,
        /// so the port never has to be typed in twice and cannot drift out of
        /// sync with the client. Any failure leaves the defaults in place.
        /// </summary>
        private static void ReadSettings(string baseDir, ProxyClientInfo info)
        {
            string path = Path.Combine(baseDir, @"guiConfigs\guiNConfig.json");
            if (!File.Exists(path)) return;
            info.SettingsPath = path;

            try
            {
                string raw = File.ReadAllText(path, Encoding.UTF8);
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> map =
                    ser.DeserializeObject(raw) as Dictionary<string, object>;
                if (map == null) return;

                object inbound;
                if (map.TryGetValue("Inbound", out inbound))
                {
                    IEnumerable seq = inbound as IEnumerable;
                    if (seq != null && !(inbound is string))
                    {
                        foreach (object entry in seq)
                        {
                            Dictionary<string, object> item = entry as Dictionary<string, object>;
                            if (item == null) continue;
                            int port = Int(item, "LocalPort", 0);
                            if (port > 0 && port < 65536) { info.ListenPort = port; break; }
                        }
                    }
                }

                object tun;
                if (map.TryGetValue("TunModeItem", out tun))
                {
                    Dictionary<string, object> item = tun as Dictionary<string, object>;
                    if (item != null) info.TunModeEnabled = Bool(item, "EnableTun", false);
                }
            }
            catch (Exception ex)
            {
                Log.Warn("Could not read the proxy client's settings (" + ex.Message +
                         "). Using defaults.");
            }
        }

        // ------------------------------------------------------------- liveness

        /// <summary>
        /// True when something is accepting on the client's loopback port.
        ///
        /// This reads the TCP listener table rather than opening a connection,
        /// because the UI asks every couple of seconds and a real connect would
        /// leave a trail of dud sessions in the proxy's log.
        ///
        /// It proves the proxy is there to be used. It does not prove the far end
        /// is reachable - for that the app would have to push a request through,
        /// which is too expensive to poll. The kill switch does not rest on this
        /// either way: protection comes from the firewall policy, and this only
        /// decides what colour the banner is.
        /// </summary>
        public static bool IsProxyListening(int port)
        {
            if (port <= 0 || port > 65535) return false;
            try
            {
                IPEndPoint[] listeners =
                    IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();

                foreach (IPEndPoint ep in listeners)
                {
                    if (ep.Port != port) continue;
                    if (IPAddress.IsLoopback(ep.Address) ||
                        ep.Address.Equals(IPAddress.Any) ||
                        ep.Address.Equals(IPAddress.IPv6Any))
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>True when at least one of these executables is running.</summary>
        public static bool IsAnyRunning(IList<string> programs)
        {
            if (programs == null) return false;
            foreach (string exe in programs)
            {
                if (string.IsNullOrEmpty(exe)) continue;

                string name;
                try { name = Path.GetFileNameWithoutExtension(exe); }
                catch { continue; }
                if (string.IsNullOrEmpty(name)) continue;

                try
                {
                    Process[] procs = Process.GetProcessesByName(name);
                    bool any = procs.Length > 0;
                    foreach (Process p in procs) { try { p.Dispose(); } catch { } }
                    if (any) return true;
                }
                catch { }
            }
            return false;
        }

        // -------------------------------------------------------------- helpers

        private static bool Contains(List<string> list, string value)
        {
            foreach (string s in list)
            {
                if (string.Equals(s, value, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static string SafeExpand(string raw)
        {
            try { return Environment.ExpandEnvironmentVariables(raw); }
            catch { return ""; }
        }

        private static int Int(Dictionary<string, object> map, string key, int fallback)
        {
            object value;
            if (!map.TryGetValue(key, out value) || value == null) return fallback;
            try { return Convert.ToInt32(value); }
            catch { return fallback; }
        }

        private static bool Bool(Dictionary<string, object> map, string key, bool fallback)
        {
            object value;
            if (!map.TryGetValue(key, out value) || value == null) return fallback;
            try { return Convert.ToBoolean(value); }
            catch { return fallback; }
        }
    }
}
