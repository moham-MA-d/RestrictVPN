using System;
using System.Diagnostics;
using System.Reflection;

namespace RestrictVpn
{
    /// <summary>
    /// Optional scheduled task that arms the kill switch at every boot, closing
    /// the window between Windows starting and the VPN connecting.
    ///
    /// A scheduled task rather than a Startup-folder shortcut, because arming
    /// needs administrator rights and Startup entries cannot elevate silently.
    /// </summary>
    internal static class BootTask
    {
        public const string TaskName = "RestrictVPN Arm At Boot";

        private static string ExePath
        {
            get { return Assembly.GetExecutingAssembly().Location; }
        }

        private static int Run(string arguments, out string output)
        {
            ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", arguments);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            using (Process p = Process.Start(psi))
            {
                output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit(20000);
                return p.ExitCode;
            }
        }

        public static bool IsInstalled()
        {
            try
            {
                string output;
                return Run("/Query /TN \"" + TaskName + "\"", out output) == 0;
            }
            catch { return false; }
        }

        public static void Install()
        {
            string output;
            string command = "\\\"" + ExePath + "\\\" --enable";
            int code = Run(
                "/Create /TN \"" + TaskName + "\" /TR \"" + command +
                "\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F", out output);

            if (code != 0)
            {
                throw new InvalidOperationException(
                    "Could not create the boot task (schtasks exit " + code + ").\r\n" + output.Trim());
            }
            Log.Ok("Boot task installed: the kill switch will arm at every startup.");
        }

        public static void Uninstall()
        {
            string output;
            int code = Run("/Delete /TN \"" + TaskName + "\" /F", out output);
            if (code != 0)
            {
                Log.Warn("Could not remove the boot task (schtasks exit " + code + "). " + output.Trim());
                return;
            }
            Log.Ok("Boot task removed.");
        }
    }
}
