using System;
using System.IO;
using System.Text;

namespace RestrictVpn
{
    internal static class Paths
    {
        public static string BaseDir
        {
            get { return AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'); }
        }

        public static string Exe
        {
            get { return System.Reflection.Assembly.GetExecutingAssembly().Location; }
        }

        public static string Config { get { return Path.Combine(BaseDir, "config.json"); } }
        public static string StateDir { get { return Path.Combine(BaseDir, "state"); } }
        public static string State { get { return Path.Combine(StateDir, "state.json"); } }
        public static string SplitState { get { return Path.Combine(StateDir, "splittunnel.json"); } }
        public static string LogDir { get { return Path.Combine(BaseDir, "logs"); } }
        public static string Log { get { return Path.Combine(LogDir, "restrictvpn.log"); } }

        public static void EnsureDirs()
        {
            try
            {
                if (!Directory.Exists(StateDir)) Directory.CreateDirectory(StateDir);
                if (!Directory.Exists(LogDir)) Directory.CreateDirectory(LogDir);
            }
            catch { }
        }
    }

    internal static class Log
    {
        public static event Action<string> Written;

        public static void Info(string message) { Write("INFO", message); }
        public static void Warn(string message) { Write("WARN", message); }
        public static void Error(string message) { Write("ERROR", message); }
        public static void Ok(string message) { Write("OK", message); }

        private static readonly object Gate = new object();

        private static void Write(string level, string message)
        {
            string line = string.Format("{0} [{1}] {2}",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), level, message);

            try
            {
                Paths.EnsureDirs();
                lock (Gate)
                {
                    File.AppendAllText(Paths.Log, line + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { }

            Action<string> handler = Written;
            if (handler != null)
            {
                try { handler(line); }
                catch { }
            }
        }
    }
}
