using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace RestrictVpn
{
    internal class ProfilePolicy
    {
        public string Name;
        public string Enabled;
        public string Inbound;
        public string Outbound;
    }

    /// <summary>
    /// Reads and restores firewall profile defaults through the NetSecurity
    /// cmdlets rather than COM.
    ///
    /// Why both: COM is used for everything else because it is fast and
    /// dependency-free, but it cannot express "NotConfigured" - it reports the
    /// effective value instead. On a machine whose profiles have never been set
    /// explicitly (the normal case) a COM-based snapshot would therefore restore
    /// Allow/Block where NotConfigured used to be. Functionally the same, but it
    /// is not what was there before, and a tool that rewrites your firewall
    /// should put it back exactly.
    ///
    /// Every method degrades gracefully: on any failure the caller falls back to
    /// the COM path, so arming and disarming still work.
    /// </summary>
    internal static class PolicyStore
    {
        private const int TimeoutMs = 30000;

        private static bool RunPowerShell(string command, out string output)
        {
            output = "";
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("powershell.exe",
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" +
                    command.Replace("\"", "\\\"") + "\"");
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process p = Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(TimeoutMs))
                    {
                        try { p.Kill(); }
                        catch { }
                        return false;
                    }
                    output = stdout;
                    return p.ExitCode == 0 && stderr.Trim().Length == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Returns null if the cmdlets are unavailable or misbehave.</summary>
        public static List<ProfilePolicy> Read()
        {
            string output;
            string cmd =
                "Get-NetFirewallProfile -All | ForEach-Object { " +
                "$_.Name + '|' + $_.Enabled + '|' + $_.DefaultInboundAction + '|' + $_.DefaultOutboundAction }";

            if (!RunPowerShell(cmd, out output)) return null;

            List<ProfilePolicy> list = new List<ProfilePolicy>();
            foreach (string rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0) continue;

                string[] parts = line.Split('|');
                if (parts.Length != 4) continue;

                ProfilePolicy p = new ProfilePolicy();
                p.Name = parts[0].Trim();
                p.Enabled = parts[1].Trim();
                p.Inbound = parts[2].Trim();
                p.Outbound = parts[3].Trim();
                list.Add(p);
            }

            return list.Count > 0 ? list : null;
        }

        public static bool Restore(List<ProfilePolicy> profiles)
        {
            if (profiles == null || profiles.Count == 0) return false;

            StringBuilder cmd = new StringBuilder();
            foreach (ProfilePolicy p in profiles)
            {
                if (!IsSafeToken(p.Name) || !IsSafeToken(p.Enabled) ||
                    !IsSafeToken(p.Inbound) || !IsSafeToken(p.Outbound))
                {
                    return false;
                }

                cmd.Append("Set-NetFirewallProfile -Name ").Append(p.Name)
                   .Append(" -Enabled ").Append(p.Enabled)
                   .Append(" -DefaultInboundAction ").Append(p.Inbound)
                   .Append(" -DefaultOutboundAction ").Append(p.Outbound)
                   .Append("; ");
            }

            string output;
            return RunPowerShell(cmd.ToString(), out output);
        }

        /// <summary>
        /// The snapshot file is on disk and hand-editable, and its values are
        /// pasted into a PowerShell command, so only known-good tokens pass.
        /// </summary>
        private static bool IsSafeToken(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            foreach (char c in value)
            {
                if (!char.IsLetterOrDigit(c)) return false;
            }
            return true;
        }
    }
}
