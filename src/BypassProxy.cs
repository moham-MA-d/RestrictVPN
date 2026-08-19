using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Management;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace RestrictVpn
{
    /// <summary>
    /// A loopback-only SOCKS5 proxy whose outbound sockets are pinned to the
    /// physical adapter, so a proxy-aware app really does bypass the VPN.
    ///
    /// Why this exists: a firewall rule can permit a packet or drop it, and a
    /// route is chosen by destination, so neither can express "this program goes
    /// around the tunnel". The one thing that can is IP_UNICAST_IF, a per-socket
    /// option that overrides the route table's choice of outgoing interface - but
    /// it has to be set by whoever owns the socket. Sending the app's traffic
    /// through a proxy we control is how we get to own the socket without a
    /// kernel driver.
    ///
    /// The limit is honest and worth stating: this only reaches apps that speak
    /// proxy. Catching an arbitrary process transparently still needs a WFP
    /// callout driver.
    /// </summary>
    internal static class BypassProxy
    {
        // Same numeric value at both levels, different byte order rules. See Pin().
        private const int IP_UNICAST_IF = 31;
        private const int IPV6_UNICAST_IF = 31;

        private const int BufferSize = 16384;
        private const int HandshakeTimeoutMs = 15000;
        private const int ConnectTimeoutMs = 10000;

        private static readonly object Gate = new object();
        private static readonly List<Relay> Relays = new List<Relay>();

        private static Socket _listener;
        private static int _port;
        private static int _ifIndex = -1;
        private static int _ifIndexV6 = -1;
        private static string _pinnedAlias = "";
        private static long _served;
        private static long _failed;

        public static bool IsRunning { get { return _listener != null; } }
        public static int Port { get { return _port; } }
        public static string PinnedAlias { get { return _pinnedAlias; } }

        public static int ActiveConnections
        {
            get { lock (Gate) { return Relays.Count; } }
        }

        public static string Status
        {
            get
            {
                if (!IsRunning) return "bypass proxy off";
                return "bypass proxy 127.0.0.1:" + _port + " via " + _pinnedAlias +
                       " (" + ActiveConnections + " open)";
            }
        }

        // =====================================================================
        // Lifecycle
        // =====================================================================

        /// <summary>
        /// Makes the proxy match the config: starts it, stops it, or restarts it
        /// when the port or the physical adapter underneath it has changed.
        /// </summary>
        public static void Sync(AppConfig config)
        {
            bool wanted = config.SplitTunnelEnabled && config.BypassProxyEnabled;
            if (!wanted)
            {
                if (IsRunning)
                {
                    Log.Info("Bypass proxy: switching off (" +
                             (config.SplitTunnelEnabled ? "BypassProxyEnabled is false"
                                                        : "split tunnel is off") + ").");
                }
                else if (config.SplitTunnelEnabled)
                {
                    // Split tunnel is on but the proxy is not. Anyone reading this
                    // log after an app exclusion "did nothing" needs to see it.
                    Log.Info("Bypass proxy: not started, BypassProxyEnabled is false. " +
                             "App exclusions are firewall permissions only.");
                }
                Stop();
                return;
            }

            Underlay underlay = RouteService.Find(config);
            int port = config.BypassProxyPort > 0 && config.BypassProxyPort < 65536
                ? config.BypassProxyPort : 1080;

            if (underlay == null)
            {
                if (IsRunning) Log.Warn("Bypass proxy stopped: no physical adapter with a gateway.");
                Stop();
                return;
            }

            if (IsRunning && _port == port &&
                string.Equals(_pinnedAlias, underlay.Alias, StringComparison.OrdinalIgnoreCase))
            {
                Log.Info("Bypass proxy: already correct (" + Status + ").");
                return;
            }

            Stop();
            Start(config, underlay, port);
        }

        private static void Start(AppConfig config, Underlay underlay, int port)
        {
            _ifIndex = underlay.HasV4 ? underlay.IfIndex : -1;
            _ifIndexV6 = underlay.HasV6 ? underlay.IfIndexV6 : -1;

            if (_ifIndex <= 0 && _ifIndexV6 <= 0)
            {
                Log.Warn("Bypass proxy not started: " + underlay.Alias + " has no usable gateway.");
                return;
            }

            Socket listener;
            string error;

            if (!TryBind(port, out listener, out error))
            {
                // A machine with Hyper-V or WSL has whole blocks of ports reserved
                // by WinNAT, and a bind inside one fails with "access denied" no
                // matter who you are. Say which range, then get out of the way and
                // let Windows hand us a port that works.
                string reserved = ExcludedRangeContaining(port);
                Log.Warn("Bypass proxy: 127.0.0.1:" + port + " was refused (" + error + ")." +
                         (reserved != null
                              ? "  Port " + port + " is inside the reserved range " + reserved +
                                " - Hyper-V and WSL reserve these, so nothing can bind there."
                              : "  Another program may be holding it."));

                if (!TryBind(0, out listener, out error))
                {
                    Log.Error("Bypass proxy could not listen on any port (" + error + ").");
                    return;
                }

                port = ((IPEndPoint)listener.LocalEndPoint).Port;

                // Remember it, so the port stays put across restarts and anything
                // configured by hand keeps working.
                try
                {
                    config.BypassProxyPort = port;
                    config.Save();
                    Log.Ok("Bypass proxy: using port " + port + " instead, saved to config.json.");
                }
                catch (Exception ex)
                {
                    Log.Warn("Bypass proxy: using port " + port +
                             ", but it could not be saved to config.json (" + ex.Message + ").");
                }
            }

            _listener = listener;
            _port = port;
            _pinnedAlias = underlay.Alias;
            Interlocked.Exchange(ref _served, 0);
            Interlocked.Exchange(ref _failed, 0);

            Log.Ok("Bypass proxy listening on 127.0.0.1:" + port + ", pinned to " + underlay.Alias + ".");
            BeginAccept(listener);
        }

        /// <summary>Loopback only. This must never be reachable from the network.</summary>
        private static bool TryBind(int port, out Socket listener, out string error)
        {
            listener = null;
            error = null;

            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                s.Bind(new IPEndPoint(IPAddress.Loopback, port));
                s.Listen(64);
                listener = s;
                return true;
            }
            catch (SocketException ex)
            {
                error = ex.SocketErrorCode + " (" + ex.NativeErrorCode + ")";
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }

            try { s.Close(); }
            catch { }
            return false;
        }

        /// <summary>
        /// The reserved range a port falls into, or null. Windows hands these
        /// blocks to WinNAT for Hyper-V and WSL, and they are invisible until a
        /// bind fails for no apparent reason.
        /// </summary>
        public static string ExcludedRangeContaining(int port)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh.exe",
                    "interface ipv4 show excludedportrange protocol=tcp");
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                string output;
                using (Process p = Process.Start(psi))
                {
                    output = p.StandardOutput.ReadToEnd();
                    if (!p.WaitForExit(10000))
                    {
                        try { p.Kill(); }
                        catch { }
                        return null;
                    }
                }

                // Only the numbers matter, so this survives any display language.
                foreach (string line in output.Split('\n'))
                {
                    string[] parts = line.Split(new char[] { ' ', '\t', '\r' },
                                                StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;

                    int start, end;
                    if (!int.TryParse(parts[0], out start)) continue;
                    if (!int.TryParse(parts[1], out end)) continue;
                    if (port >= start && port <= end) return start + "-" + end;
                }
            }
            catch { }
            return null;
        }

        public static void Stop()
        {
            Socket listener = _listener;
            _listener = null;

            if (listener != null)
            {
                try { listener.Close(); }
                catch { }
                Log.Info("Bypass proxy stopped.");
            }

            Relay[] open;
            lock (Gate)
            {
                open = Relays.ToArray();
                Relays.Clear();
            }
            foreach (Relay r in open) r.Close();

            _pinnedAlias = "";
            _port = 0;
        }

        // =====================================================================
        // Accept
        // =====================================================================

        private static void BeginAccept(Socket listener)
        {
            try { listener.BeginAccept(OnAccept, listener); }
            catch { }   // the listener was closed; nothing to keep alive
        }

        private static void OnAccept(IAsyncResult ar)
        {
            Socket listener = (Socket)ar.AsyncState;

            Socket client = null;
            try { client = listener.EndAccept(ar); }
            catch { return; }   // stopped

            if (_listener == listener) BeginAccept(listener);

            if (client == null) return;
            ThreadPool.QueueUserWorkItem(delegate { Serve(client); });
        }

        // =====================================================================
        // SOCKS5 (RFC 1928, CONNECT only)
        // =====================================================================

        private static void Serve(Socket client)
        {
            Socket remote = null;
            bool relaying = false;
            try
            {
                client.ReceiveTimeout = HandshakeTimeoutMs;
                client.SendTimeout = HandshakeTimeoutMs;
                client.NoDelay = true;

                byte[] greeting = ReadExactly(client, 2);
                if (greeting[0] != 0x05) return;                 // not SOCKS5
                ReadExactly(client, greeting[1]);                // auth methods, all ignored
                client.Send(new byte[] { 0x05, 0x00 });          // no authentication

                byte[] request = ReadExactly(client, 4);
                if (request[0] != 0x05) return;
                if (request[1] != 0x01) { Reply(client, 0x07); return; }   // CONNECT only

                string hostName = null;
                IPAddress literal = null;

                switch (request[3])
                {
                    case 0x01: literal = new IPAddress(ReadExactly(client, 4)); break;
                    case 0x04: literal = new IPAddress(ReadExactly(client, 16)); break;
                    case 0x03:
                        int length = ReadExactly(client, 1)[0];
                        hostName = Encoding.ASCII.GetString(ReadExactly(client, length));
                        break;
                    default:
                        Reply(client, 0x08);   // address type not supported
                        return;
                }

                byte[] portBytes = ReadExactly(client, 2);
                int port = (portBytes[0] << 8) | portBytes[1];

                IPAddress[] targets;
                if (literal != null)
                {
                    targets = new IPAddress[] { literal };
                }
                else
                {
                    // Resolved with the system resolver, which while the tunnel is
                    // up means the VPN's DNS. The connection itself still leaves
                    // over the physical adapter, so the destination sees the real
                    // address - only the lookup goes through the tunnel.
                    try { targets = Dns.GetHostAddresses(hostName); }
                    catch { Reply(client, 0x04); return; }       // host unreachable
                }

                string target = (hostName ?? literal.ToString()) + ":" + port;

                string failure;
                remote = ConnectPinned(targets, port, out failure);
                if (remote == null)
                {
                    NoteFailure(target, failure);
                    Reply(client, 0x05);   // connection refused
                    return;
                }

                NoteSuccess(remote, target);
                Reply(client, 0x00);

                // A relayed connection can idle for a long time and that is normal.
                client.ReceiveTimeout = 0;
                client.SendTimeout = 0;
                remote.ReceiveTimeout = 0;
                remote.SendTimeout = 0;

                relaying = true;
                new Relay(client, remote).Start();
            }
            catch
            {
                // A browser abandoning a speculative connection is routine.
            }
            finally
            {
                if (!relaying)
                {
                    Close(client);
                    Close(remote);
                }
            }
        }

        /// <summary>
        /// The first line proves the bypass is real - the local endpoint it prints
        /// is the physical adapter's address, not the tunnel's. After that a
        /// heartbeat every 50 connections keeps the log readable.
        /// </summary>
        private static void NoteSuccess(Socket remote, string target)
        {
            long n = Interlocked.Increment(ref _served);
            if (n != 1 && n % 50 != 0) return;

            string local;
            try { local = remote.LocalEndPoint.ToString(); }
            catch { local = "?"; }

            Log.Ok("Bypass proxy: connection " + n + " to " + target + " left from " + local +
                   " via " + _pinnedAlias + (n == 1 ? "  <- this address is what the site sees" : ""));
        }

        private static void NoteFailure(string target, string reason)
        {
            long n = Interlocked.Increment(ref _failed);
            if (n > 5 && n % 50 != 0) return;

            string hint = "";
            if (n == 1 && reason != null &&
                reason.IndexOf("AccessDenied", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                // WSAEACCES on a pinned socket is always a packet filter, never
                // routing, and there are only two plausible culprits.
                hint = "  This is a firewall block, not a routing problem. Two things do it: " +
                       "(1) the kill switch is armed without the bypass proxy allow rule - press " +
                       "Verify rules, and re-arm if it is missing; (2) OpenVPN Connect's " +
                       "\"Seamless tunnel\" setting, which blocks every non-tunnel packet at the WFP " +
                       "layer and has to be turned off for any split tunnelling to work.";
            }

            Log.Warn("Bypass proxy: could not reach " + target + " via " + _pinnedAlias +
                     " - " + (reason ?? "no route") + hint);
        }

        private static byte[] ReadExactly(Socket s, int count)
        {
            byte[] buffer = new byte[count];
            int got = 0;
            while (got < count)
            {
                int n = s.Receive(buffer, got, count - got, SocketFlags.None);
                if (n <= 0) throw new IOException("closed during the SOCKS handshake");
                got += n;
            }
            return buffer;
        }

        /// <summary>Reply with a bound address of 0.0.0.0:0, which every client accepts.</summary>
        private static void Reply(Socket client, byte code)
        {
            byte[] reply = new byte[10];
            reply[0] = 0x05;
            reply[1] = code;
            reply[3] = 0x01;
            try { client.Send(reply); }
            catch { }
        }

        // =====================================================================
        // The part that does the actual bypassing
        // =====================================================================

        /// <summary>
        /// Connects with the outgoing interface forced, so the route table's
        /// preference for the tunnel is ignored for this socket alone.
        /// </summary>
        private static Socket ConnectPinned(IPAddress[] targets, int port, out string error)
        {
            error = null;
            List<IPAddress> ordered = Ordered(targets);
            if (ordered.Count == 0) error = "no address in a family this adapter can reach";

            foreach (IPAddress address in ordered)
            {
                bool v6 = address.AddressFamily == AddressFamily.InterNetworkV6;
                int ifIndex = v6 ? _ifIndexV6 : _ifIndex;
                if (ifIndex <= 0)
                {
                    error = _pinnedAlias + " has no IPv" + (v6 ? "6" : "4") + " gateway";
                    continue;
                }

                Socket s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    Pin(s, v6, ifIndex);
                    s.NoDelay = true;

                    // Blocking Connect waits ~21s on a black hole, which is far too
                    // long to hold a browser tab.
                    IAsyncResult ar = s.BeginConnect(new IPEndPoint(address, port), null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(ConnectTimeoutMs, false))
                    {
                        throw new SocketException((int)SocketError.TimedOut);
                    }
                    s.EndConnect(ar);
                    return s;
                }
                catch (SocketException ex)
                {
                    error = ex.SocketErrorCode + " (" + ex.NativeErrorCode + ") connecting to " + address;
                    Close(s);
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    Close(s);
                }
            }
            return null;
        }

        private static void Pin(Socket s, bool v6, int ifIndex)
        {
            if (v6)
            {
                s.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)IPV6_UNICAST_IF, ifIndex);
            }
            else
            {
                // IPv4 takes the index in NETWORK byte order while IPv6 takes host
                // order. Getting this backwards silently pins nothing.
                s.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IP_UNICAST_IF,
                    IPAddress.HostToNetworkOrder(ifIndex));
            }
        }

        /// <summary>Try the families we can actually pin, and IPv4 first.</summary>
        private static List<IPAddress> Ordered(IPAddress[] targets)
        {
            List<IPAddress> v4 = new List<IPAddress>();
            List<IPAddress> v6 = new List<IPAddress>();
            foreach (IPAddress a in targets)
            {
                if (a.AddressFamily == AddressFamily.InterNetwork) v4.Add(a);
                else if (a.AddressFamily == AddressFamily.InterNetworkV6) v6.Add(a);
            }
            v4.AddRange(v6);
            return v4;
        }

        private static void Close(Socket s)
        {
            if (s == null) return;
            try { s.Shutdown(SocketShutdown.Both); }
            catch { }
            try { s.Close(); }
            catch { }
        }

        // =====================================================================
        // Proving it works
        // =====================================================================

        /// <summary>
        /// Contacted only when the user presses Test bypass. Plain HTTP because
        /// the answer is one line of text and TLS would buy nothing here - the
        /// request carries no information beyond the connection itself, which is
        /// the entire point of the check.
        /// </summary>
        private const string CheckHost = "api.ipify.org";

        /// <summary>
        /// Asks an echo service what address it sees, once the way Windows would
        /// route it and once through the proxy. Two different answers is proof the
        /// bypass is live; the same answer means it is not.
        /// </summary>
        public static BypassCheck Check()
        {
            BypassCheck result = new BypassCheck();

            if (!IsRunning)
            {
                result.Error = "The bypass proxy is not running.";
                return result;
            }

            Log.Info("Bypass check: asking " + CheckHost + " what address it sees, direct and bypassed.");

            try { result.Direct = FetchDirect(); }
            catch (Exception ex) { result.Direct = "failed: " + Describe(ex); }

            try { result.Bypassed = FetchBypassed(); }
            catch (Exception ex) { result.Bypassed = "failed: " + Describe(ex); }

            Log.Info("Bypass check: direct=" + result.Direct + "  bypassed=" + result.Bypassed +
                     "  => " + (result.Working ? "WORKING" : "not bypassing"));
            return result;
        }

        private static string Describe(Exception ex)
        {
            SocketException se = ex as SocketException;
            return se != null ? se.SocketErrorCode + " (" + se.NativeErrorCode + ")" : ex.Message;
        }

        private static string FetchDirect()
        {
            using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                s.ReceiveTimeout = 15000;
                s.SendTimeout = 15000;
                s.Connect(CheckHost, 80);
                return HttpBody(s);
            }
        }

        private static string FetchBypassed()
        {
            using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                s.ReceiveTimeout = 25000;
                s.SendTimeout = 25000;
                s.Connect(new IPEndPoint(IPAddress.Loopback, _port));

                s.Send(new byte[] { 0x05, 0x01, 0x00 });
                byte[] hello = ReadExactly(s, 2);
                if (hello[0] != 0x05 || hello[1] != 0x00) throw new IOException("the proxy refused the handshake");

                byte[] name = Encoding.ASCII.GetBytes(CheckHost);
                byte[] request = new byte[4 + 1 + name.Length + 2];
                request[0] = 0x05; request[1] = 0x01; request[2] = 0x00; request[3] = 0x03;
                request[4] = (byte)name.Length;
                Array.Copy(name, 0, request, 5, name.Length);
                request[request.Length - 1] = 80;
                s.Send(request);

                byte[] reply = ReadExactly(s, 10);
                if (reply[1] != 0x00) throw new IOException("the proxy could not connect out (code " + reply[1] + ")");

                return HttpBody(s);
            }
        }

        private static string HttpBody(Socket s)
        {
            byte[] request = Encoding.ASCII.GetBytes(
                "GET / HTTP/1.1\r\nHost: " + CheckHost +
                "\r\nConnection: close\r\nUser-Agent: RestrictVPN\r\n\r\n");
            s.Send(request);

            StringBuilder sb = new StringBuilder();
            byte[] buffer = new byte[4096];
            while (sb.Length < 8192)
            {
                int n;
                try { n = s.Receive(buffer); }
                catch { break; }
                if (n <= 0) break;
                sb.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }

            string all = sb.ToString();
            int split = all.IndexOf("\r\n\r\n");
            return (split < 0 ? all : all.Substring(split + 4)).Trim();
        }

        // =====================================================================
        // Relay
        // =====================================================================

        /// <summary>
        /// Copies bytes both ways using completion callbacks rather than a thread
        /// per direction - a browser opens enough connections that thread-per-pipe
        /// would be a problem.
        /// </summary>
        private class Relay
        {
            private readonly Socket _a;
            private readonly Socket _b;
            private readonly byte[] _bufA = new byte[BufferSize];
            private readonly byte[] _bufB = new byte[BufferSize];
            private int _closed;

            public Relay(Socket a, Socket b) { _a = a; _b = b; }

            public void Start()
            {
                lock (Gate) Relays.Add(this);
                Read(_a, _b, _bufA);
                Read(_b, _a, _bufB);
            }

            private void Read(Socket from, Socket to, byte[] buffer)
            {
                try
                {
                    from.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnRead,
                        new object[] { from, to, buffer });
                }
                catch { Close(); }
            }

            private void OnRead(IAsyncResult ar)
            {
                object[] state = (object[])ar.AsyncState;
                Socket from = (Socket)state[0];
                Socket to = (Socket)state[1];
                byte[] buffer = (byte[])state[2];

                try
                {
                    int read = from.EndReceive(ar);
                    if (read <= 0) { Close(); return; }

                    int sent = 0;
                    while (sent < read) sent += to.Send(buffer, sent, read - sent, SocketFlags.None);

                    Read(from, to, buffer);
                }
                catch
                {
                    Close();
                }
            }

            public void Close()
            {
                if (Interlocked.Exchange(ref _closed, 1) != 0) return;
                lock (Gate) Relays.Remove(this);
                BypassProxy.Close(_a);
                BypassProxy.Close(_b);
            }
        }
    }

    /// <summary>What the internet sees on each path. Different answers means it works.</summary>
    internal class BypassCheck
    {
        public string Direct;
        public string Bypassed;
        public string Error;

        public bool Working
        {
            get
            {
                IPAddress a, b;
                return IPAddress.TryParse((Direct ?? "").Trim(), out a) &&
                       IPAddress.TryParse((Bypassed ?? "").Trim(), out b) &&
                       !a.Equals(b);
            }
        }
    }

    /// <summary>Where an excluded app's traffic is going right now.</summary>
    internal enum AppBypassState
    {
        NotRunning,
        OnVpn,
        Bypassing
    }

    // =========================================================================
    // Launcher
    // =========================================================================

    /// <summary>
    /// Starts an excluded app pointed at the bypass proxy. Only Chromium-family
    /// browsers can be told about a proxy on the command line; everything else
    /// has to be configured by hand, and saying so is better than launching it
    /// and letting the user believe it worked.
    /// </summary>
    internal static class BypassLauncher
    {
        private static readonly string[] Chromium = new string[]
        {
            "chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "chromium.exe", "thorium.exe"
        };

        public static bool IsChromium(string exe)
        {
            string name = Path.GetFileName(exe ?? "");
            foreach (string c in Chromium)
            {
                if (string.Equals(name, c, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>
        /// Whether the app is running, and if so whether it was started pointed at
        /// our proxy. Read from the process command line, because that is the only
        /// place the answer exists - a bypassed browser is indistinguishable from a
        /// normal one in every other respect.
        /// </summary>
        public static AppBypassState GetState(string exe, int port)
        {
            string name = Path.GetFileName(exe ?? "");
            if (name.Length == 0 || name.IndexOf('\'') >= 0) return AppBypassState.NotRunning;

            string quoted = "--proxy-server=\"socks5://127.0.0.1:" + port + "\"";
            string bare = "--proxy-server=socks5://127.0.0.1:" + port;

            bool anyRunning = false;
            try
            {
                using (ManagementObjectSearcher search = new ManagementObjectSearcher(
                    "SELECT CommandLine FROM Win32_Process WHERE Name = '" + name + "'"))
                {
                    foreach (ManagementObject process in search.Get())
                    {
                        anyRunning = true;
                        string commandLine = process["CommandLine"] as string;
                        if (commandLine == null) continue;

                        if (commandLine.IndexOf(quoted, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            commandLine.IndexOf(bare, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            return AppBypassState.Bypassing;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // WMI can be disabled or slow. Degrade to the coarse answer rather
                // than claiming to know something we do not.
                Log.Info("Could not read command lines for " + name + " (" + ex.Message +
                         "); reporting running/not-running only.");
                return IsRunning(exe) ? AppBypassState.OnVpn : AppBypassState.NotRunning;
            }

            return anyRunning ? AppBypassState.OnVpn : AppBypassState.NotRunning;
        }

        public static bool IsRunning(string exe)
        {
            try
            {
                string name = Path.GetFileNameWithoutExtension(exe ?? "");
                if (name.Length == 0) return false;
                return Process.GetProcessesByName(name).Length > 0;
            }
            catch { return false; }
        }

        /// <summary>The profile a bypass window uses when the app is already running.</summary>
        public static string IsolatedProfileDir(string exe)
        {
            return Path.Combine(Path.Combine(Paths.StateDir, "bypass-profile"),
                                Path.GetFileNameWithoutExtension(exe ?? "app"));
        }

        /// <summary>
        /// Asks the app to close so it can be started again pointed at the proxy.
        /// Chromium reads --proxy-server only at startup and a running instance
        /// hands the request to itself, so relaunching is the only way to move an
        /// existing profile onto the bypass.
        /// </summary>
        public static bool CloseRunning(string exe, int timeoutMs, out string reason)
        {
            reason = null;
            string name = Path.GetFileNameWithoutExtension(exe ?? "");
            if (name.Length == 0) return true;

            foreach (Process p in Process.GetProcessesByName(name))
            {
                try
                {
                    // Only the browser process has a window; the renderers go with it.
                    if (p.MainWindowHandle != IntPtr.Zero) p.CloseMainWindow();
                }
                catch { }
            }

            // Wait for every process to go, not just the windows: whatever still
            // holds the profile lock is what would swallow the proxy argument.
            int waited = 0;
            while (waited < timeoutMs)
            {
                if (Process.GetProcessesByName(name).Length == 0)
                {
                    Log.Info("Closed " + Path.GetFileName(exe) + " so it can be reopened outside the VPN.");
                    return true;
                }
                Thread.Sleep(250);
                waited += 250;
            }

            reason = HasVisibleWindow(name)
                ? "It still has a window open - it may be asking you to confirm closing, or holding " +
                  "an unsaved page."
                : "Its windows closed but the process is still running, which usually means " +
                  "\"Continue running background apps when " + Path.GetFileNameWithoutExtension(exe) +
                  " is closed\" is switched on in its settings. That process keeps the profile " +
                  "locked, so a relaunch would be ignored. Turn that setting off, or quit it from " +
                  "the tray, and try again.";

            Log.Warn(Path.GetFileName(exe) + " did not close within " + (timeoutMs / 1000) +
                     "s, so it was not relaunched. " + reason);
            return false;
        }

        private static bool HasVisibleWindow(string processName)
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName(processName))
                {
                    if (p.MainWindowHandle != IntPtr.Zero) return true;
                }
            }
            catch { }
            return false;
        }

        public static void Launch(string exe, int port, bool isolateProfile)
        {
            if (!File.Exists(exe)) throw new FileNotFoundException("The program is no longer at " + exe);
            if (!BypassProxy.IsRunning)
            {
                throw new InvalidOperationException(
                    "The bypass proxy is not running, so there is nothing to point the app at.");
            }

            string arguments = "";
            if (IsChromium(exe))
            {
                arguments = "--proxy-server=\"socks5://127.0.0.1:" + port + "\"";
                if (isolateProfile)
                {
                    string dir = IsolatedProfileDir(exe);
                    try { if (!Directory.Exists(dir)) Directory.CreateDirectory(dir); }
                    catch { }
                    arguments += " --user-data-dir=\"" + dir + "\"";
                }
            }

            ProcessStartInfo psi = new ProcessStartInfo(exe, arguments);
            psi.UseShellExecute = true;
            psi.WorkingDirectory = Path.GetDirectoryName(exe);

            Process.Start(psi);

            Log.Ok("Launched outside the VPN: " + Path.GetFileName(exe) +
                   (arguments.Length > 0 ? " " + arguments : " (no proxy argument - configure it in the app)"));
        }
    }
}
