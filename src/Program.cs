using System;
using System.Security.Principal;
using System.Windows.Forms;

namespace RestrictVpn
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Paths.EnsureDirs();
            Log.Info("RestrictVPN starting - " + BuildStamp());

            // The manifest requests administrator, so this should already hold.
            // Checked anyway: without it every firewall write fails deep inside COM.
            if (!IsElevated())
            {
                Message("RestrictVPN needs administrator rights to change firewall rules.\r\n\r\n" +
                        "Right-click RestrictVPN.exe and choose \"Run as administrator\".", true);
                return 2;
            }

            foreach (string a in args)
            {
                string v = a.TrimStart('-', '/').ToLowerInvariant();
                if (v == "quiet" || v == "silent") _quiet = true;
            }

            string command = ParseCommand(args);

            if (command != null)
            {
                return RunHeadless(command);
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                KillSwitch ks = new KillSwitch();
                Application.Run(new MainForm(ks));
                return 0;
            }
            catch (Exception ex)
            {
                Message("RestrictVPN failed to start.\r\n\r\n" + ex.Message, true);
                return 1;
            }
        }

        /// <summary>
        /// --enable / --disable / --recover run without any window, so the boot
        /// scheduled task and shortcuts can drive the kill switch directly.
        /// </summary>
        private static int RunHeadless(string command)
        {
            try
            {
                KillSwitch ks = new KillSwitch();
                AppConfig config = AppConfig.Load();

                switch (command)
                {
                    case "enable":
                        ks.Enable(config);
                        return 0;
                    case "disable":
                        ks.Disable();
                        return 0;
                    case "recover":
                        ks.Recover();
                        return 0;
                    case "status":
                        StatusInfo s = ks.GetStatus(config);
                        SplitTunnelService.PrimeSummary(config);
                        Message(s.Headline + "\r\n\r\n" + s.Detail +
                                "\r\n\r\nRules: " + s.RuleCount +
                                "\r\n" + SplitTunnelService.Summary, false);
                        return s.KillSwitchEnabled ? 0 : 1;
                    case "selftest":
                        return RunSelfTest(ks, config);
                    case "splitapply":
                        return RunSplitApply(config);
                    case "splitclear":
                        SplitTunnelService.Remove();
                        Message("Split tunnel routes removed.", false);
                        return 0;
                }
                return 0;
            }
            catch (Exception ex)
            {
                Log.Error(command + " failed: " + ex.Message);
                return 1;
            }
        }

        /// <summary>
        /// Reinstalls the split tunnel routes only. The firewall is untouched, so
        /// this is safe to run at any time - worst case a destination stays on the
        /// VPN.
        /// </summary>
        private static int RunSplitApply(AppConfig config)
        {
            if (!config.SplitTunnelEnabled)
            {
                Message("Split tunnel is switched off in config.json, so nothing was applied.", false);
                return 1;
            }

            SplitTunnelResult result = SplitTunnelService.Apply(config);
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            sb.AppendLine(SplitTunnelService.Summary);
            foreach (string problem in result.Problems) sb.AppendLine("  ! " + problem);
            Message(sb.ToString(), result.Problems.Count > 0);
            return result.Problems.Count > 0 ? 1 : 0;
        }

        /// <summary>
        /// Runs the probe and writes the outcome to the log and a result file, so
        /// it is usable both interactively and from a script.
        /// </summary>
        private static int RunSelfTest(KillSwitch ks, AppConfig config)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            int fatal = 0;

            foreach (CheckResult r in ks.SelfTest(config))
            {
                string mark = r.Passed ? "OK  " : (r.Fatal ? "FAIL" : "WARN");
                if (!r.Passed && r.Fatal) fatal++;
                string line = "[" + mark + "] " + r.Check + "  ::  " + r.Detail;
                sb.AppendLine(line);
                Log.Info("selftest " + line);
            }

            sb.AppendLine();
            sb.AppendLine(fatal > 0
                ? "RESULT: FAILED (" + fatal + " critical)"
                : "RESULT: PASSED - interface scoping works, nothing was changed.");

            try
            {
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(Paths.BaseDir, "selftest-result.txt"), sb.ToString());
            }
            catch { }

            Message(sb.ToString(), fatal > 0);
            return fatal > 0 ? 1 : 0;
        }

        private static string ParseCommand(string[] args)
        {
            foreach (string a in args)
            {
                string v = a.TrimStart('-', '/').ToLowerInvariant();
                if (v == "enable" || v == "arm") return "enable";
                if (v == "disable" || v == "disarm") return "disable";
                if (v == "recover") return "recover";
                if (v == "status") return "status";
                if (v == "selftest" || v == "test") return "selftest";
                if (v == "split-apply" || v == "splitapply") return "splitapply";
                if (v == "split-clear" || v == "splitclear") return "splitclear";
            }
            return null;
        }

        /// <summary>
        /// Which binary is actually running. Worth a line in every log: an old exe
        /// left behind by a build that could not replace a running instance looks
        /// exactly like a feature that does not work.
        /// </summary>
        internal static string BuildStamp()
        {
            try
            {
                string exe = Paths.Exe;
                return exe + "  (built " +
                       System.IO.File.GetLastWriteTime(exe).ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                       new System.IO.FileInfo(exe).Length + " bytes)";
            }
            catch { return "(build stamp unavailable)"; }
        }

        private static bool IsElevated()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        /// <summary>Set by --quiet, so scripted runs never leave a dialog on screen.</summary>
        private static bool _quiet;

        private static void Message(string text, bool error)
        {
            if (_quiet) return;
            MessageBox.Show(text, "RestrictVPN", MessageBoxButtons.OK,
                error ? MessageBoxIcon.Error : MessageBoxIcon.Information);
        }
    }
}
