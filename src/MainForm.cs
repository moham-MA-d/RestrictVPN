using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace RestrictVpn
{
    internal class MainForm : Form
    {
        // ------------------------------------------------------------- palette
        private static readonly Color ColBg = Theme.Bg;
        private static readonly Color ColPanel = Theme.Panel;
        private static readonly Color ColBorder = Theme.Border;
        private static readonly Color ColText = Theme.Text;
        private static readonly Color ColMuted = Theme.Muted;
        private static readonly Color ColGreen = Theme.Green;
        private static readonly Color ColAmber = Theme.Amber;
        private static readonly Color ColRed = Theme.Red;
        private static readonly Color ColAccent = Theme.Accent;

        // ------------------------------------------------------------- state
        private readonly KillSwitch _ks;
        private AppConfig _config;
        private readonly List<string> _listAliases = new List<string>();
        private int _tick;
        private int _cachedRuleCount;
        private Verdict _lastVerdict = (Verdict)(-1);
        private bool _suppressBootEvent;
        private volatile bool _splitBusy;
        private Icon _trayIcon;

        // ------------------------------------------------------------- controls
        private Panel _banner;
        private Label _lblHeadline;
        private Label _lblDetail;
        private Button _btnToggle;
        private Button _btnVerify, _btnRefresh, _btnRecover, _btnLog, _btnConfig, _btnSave, _btnSelfTest;
        private Button _btnSplit;
        private Label _lblSplit;
        private CheckBox _chkBoot, _chkLan, _chkDhcp, _chkVpnDns, _chkInbound;
        private CheckedListBox _clbAdapters;
        private TextBox _txtLog;
        private NotifyIcon _notify;
        private ToolStripMenuItem _menuToggle;
        private Timer _timer;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr handle);

        public MainForm(KillSwitch ks)
        {
            _ks = ks;
            _config = AppConfig.Load();

            BuildUi();
            BuildTray();

            Log.Written += OnLogWritten;

            LoadConfigIntoUi();
            SplitTunnelService.PrimeSummary(_config);
            RefreshStatus(true);

            // Split tunnel routes are added non-persistent, so a reboot wipes
            // them. Put them back on launch if the setting is still on.
            if (_config.SplitTunnelEnabled) ApplySplitTunnelRoutes("Restoring split tunnel routes.");
            else BypassProxy.Sync(_config);
        }

        // =====================================================================
        // UI construction
        // =====================================================================

        private void BuildUi()
        {
            Text = "RestrictVPN - VPN Kill Switch";

            // Absolute layout with autoscaling off: partial scaling grows the font
            // without growing the controls, which clips button text. Off means the
            // geometry below is honoured exactly, and the window stays resizable
            // with AutoScroll so nothing can become unreachable at any DPI.
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(880, 816);
            MinimumSize = new Size(700, 560);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            AutoScroll = true;
            BackColor = ColBg;
            ForeColor = ColText;
            Font = new Font("Segoe UI", 9f);
            Icon = SystemIcons.Shield;

            // --- banner ---
            _banner = new Panel();
            _banner.Location = new Point(0, 0);
            _banner.Size = new Size(880, 112);
            _banner.BackColor = ColRed;
            _banner.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_banner);

            _lblHeadline = MakeLabel("Checking...", 24, 20, 820, 40);
            _lblHeadline.Font = new Font("Segoe UI", 17f, FontStyle.Bold);
            _lblHeadline.ForeColor = Color.White;
            _banner.Controls.Add(_lblHeadline);

            _lblDetail = MakeLabel("", 26, 66, 820, 38);
            _lblDetail.ForeColor = Color.FromArgb(238, 238, 238);
            _banner.Controls.Add(_lblDetail);

            // --- primary actions ---
            _btnToggle = MakeButton("ARM KILL SWITCH", 24, 130, 300, 60, ColGreen);
            _btnToggle.Font = new Font("Segoe UI", 11.5f, FontStyle.Bold);
            _btnToggle.Click += OnToggleClick;
            Controls.Add(_btnToggle);

            // Safe rehearsal: proves interface scoping works before anything is armed.
            _btnSelfTest = MakeButton("Self test  (changes nothing)", 340, 130, 240, 32, ColPanel);
            _btnSelfTest.Click += OnSelfTestClick;
            Controls.Add(_btnSelfTest);

            _chkBoot = MakeCheck("Arm at Windows startup", 600, 134, 268);
            _chkBoot.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _chkBoot.CheckedChanged += OnBootCheckChanged;
            Controls.Add(_chkBoot);

            _btnVerify = MakeButton("Verify rules", 340, 168, 116, 32, ColPanel);
            _btnVerify.Click += OnVerifyClick;
            Controls.Add(_btnVerify);

            _btnRefresh = MakeButton("Refresh", 464, 168, 116, 32, ColPanel);
            _btnRefresh.Click += delegate { ReloadAdapters(); RefreshStatus(true); AppendLog("Refreshed."); };
            Controls.Add(_btnRefresh);

            _btnLog = MakeButton("Open log", 600, 168, 130, 32, ColPanel);
            _btnLog.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnLog.Click += delegate { OpenInNotepad(Paths.Log); };
            Controls.Add(_btnLog);

            _btnConfig = MakeButton("Open config", 738, 168, 130, 32, ColPanel);
            _btnConfig.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnConfig.Click += delegate { _config.Save(); OpenInNotepad(Paths.Config); };
            Controls.Add(_btnConfig);

            _btnRecover = MakeButton("Emergency recover", 340, 206, 240, 32, Color.FromArgb(88, 40, 40));
            _btnRecover.Click += OnRecoverClick;
            Controls.Add(_btnRecover);

            _btnSplit = MakeButton("Split tunnel...", 600, 206, 268, 32, ColPanel);
            _btnSplit.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnSplit.Click += OnSplitTunnelClick;
            Controls.Add(_btnSplit);

            // --- adapters ---
            Controls.Add(MakeHeader("Tunnel adapters traffic may leave through", 24, 250));
            Label hint = MakeLabel(
                "Tick every adapter your VPN uses. Anything not ticked is blocked while armed.    " +
                "*  =  currently carrying your internet traffic",
                24, 274, 830, 22);
            hint.ForeColor = ColMuted;
            Controls.Add(hint);

            _clbAdapters = new CheckedListBox();
            _clbAdapters.Location = new Point(24, 300);
            _clbAdapters.Size = new Size(832, 150);
            _clbAdapters.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _clbAdapters.BackColor = ColPanel;
            _clbAdapters.ForeColor = ColText;
            _clbAdapters.BorderStyle = BorderStyle.FixedSingle;
            _clbAdapters.CheckOnClick = true;
            _clbAdapters.Font = new Font("Consolas", 9f);
            _clbAdapters.IntegralHeight = false;
            Controls.Add(_clbAdapters);

            // --- options ---
            Controls.Add(MakeHeader("Options", 24, 464));

            _chkLan = MakeCheck("Allow local network (printers, NAS) - also reopens DNS to your router", 24, 488, 580);
            _chkDhcp = MakeCheck("Allow DHCP - needed for Wi-Fi and Ethernet to get an address", 24, 516, 580);
            _chkVpnDns = MakeCheck("Allow the VPN client to resolve its server hostname", 24, 544, 580);
            _chkInbound = MakeCheck("Block inbound traffic as well", 24, 572, 580);
            Controls.AddRange(new Control[] { _chkLan, _chkDhcp, _chkVpnDns, _chkInbound });

            _btnSave = MakeButton("Save settings", 640, 506, 216, 40, ColAccent);
            _btnSave.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnSave.Click += OnSaveClick;
            Controls.Add(_btnSave);

            _lblSplit = MakeLabel("Split tunnel: off", 24, 602, 832, 22);
            _lblSplit.ForeColor = ColMuted;
            _lblSplit.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_lblSplit);

            // --- activity ---
            Controls.Add(MakeHeader("Activity", 24, 630));

            _txtLog = new TextBox();
            _txtLog.Location = new Point(24, 654);
            _txtLog.Size = new Size(832, 138);
            _txtLog.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            _txtLog.Multiline = true;
            _txtLog.ReadOnly = true;
            _txtLog.ScrollBars = ScrollBars.Vertical;
            _txtLog.BackColor = ColPanel;
            _txtLog.ForeColor = ColMuted;
            _txtLog.BorderStyle = BorderStyle.FixedSingle;
            _txtLog.Font = new Font("Consolas", 8.5f);
            Controls.Add(_txtLog);

            _timer = new Timer();
            _timer.Interval = 2000;
            _timer.Tick += delegate
            {
                _tick++;
                // Rule enumeration walks every firewall rule on the machine, so
                // only do it occasionally; the cheap profile check runs each tick.
                RefreshStatus(_tick % 8 == 0);
                if (_tick % 15 == 0) MaybeReapplySplitTunnel();
            };
            _timer.Start();

            Resize += delegate
            {
                if (WindowState == FormWindowState.Minimized)
                {
                    Hide();
                    _notify.Visible = true;
                }
            };
        }

        private void BuildTray()
        {
            ContextMenuStrip menu = new ContextMenuStrip();

            ToolStripMenuItem open = new ToolStripMenuItem("Open RestrictVPN");
            open.Click += delegate { RestoreWindow(); };

            _menuToggle = new ToolStripMenuItem("Arm kill switch");
            _menuToggle.Click += OnToggleClick;

            ToolStripMenuItem recover = new ToolStripMenuItem("Emergency recover");
            recover.Click += OnRecoverClick;

            ToolStripMenuItem exit = new ToolStripMenuItem("Exit");
            exit.Click += delegate { _notify.Visible = false; Application.Exit(); };

            menu.Items.Add(open);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(_menuToggle);
            menu.Items.Add(recover);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(exit);

            _notify = new NotifyIcon();
            _notify.Text = "RestrictVPN";
            _notify.Icon = SystemIcons.Shield;
            _notify.ContextMenuStrip = menu;
            _notify.Visible = true;
            _notify.DoubleClick += delegate { RestoreWindow(); };
        }

        private void RestoreWindow()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        // =====================================================================
        // Status
        // =====================================================================

        private void RefreshStatus(bool enumerateRules)
        {
            try
            {
                StatusInfo s = _ks.GetStatus(_config, enumerateRules, _cachedRuleCount);
                _cachedRuleCount = s.RuleCount;

                _lblHeadline.Text = s.Headline;
                _lblDetail.Text = s.Detail;

                Color c;
                switch (s.Verdict)
                {
                    case Verdict.Protected: c = ColGreen; break;
                    case Verdict.Blocked: c = ColAmber; break;
                    default: c = ColRed; break;
                }
                _banner.BackColor = c;

                if (s.KillSwitchEnabled)
                {
                    _btnToggle.Text = "DISARM KILL SWITCH";
                    _btnToggle.BackColor = Color.FromArgb(120, 58, 58);
                    _menuToggle.Text = "Disarm kill switch";
                }
                else
                {
                    _btnToggle.Text = "ARM KILL SWITCH";
                    _btnToggle.BackColor = ColGreen;
                    _menuToggle.Text = "Arm kill switch";
                }

                SetTrayIcon(c, s.Headline + " - " + s.Detail);
                string split = SplitTunnelService.Summary;
                if (BypassProxy.IsRunning) split += "   |   " + BypassProxy.Status;
                _lblSplit.Text = split;
                _lblSplit.ForeColor = _config.SplitTunnelEnabled ? ColText : ColMuted;

                if (_lastVerdict != s.Verdict)
                {
                    if (_lastVerdict != (Verdict)(-1) && !Visible)
                    {
                        _notify.ShowBalloonTip(4000, "RestrictVPN", s.Headline + ": " + s.Detail,
                            s.Verdict == Verdict.Protected ? ToolTipIcon.Info : ToolTipIcon.Warning);
                    }
                    _lastVerdict = s.Verdict;
                }
            }
            catch (Exception ex)
            {
                _lblHeadline.Text = "ERROR";
                _lblDetail.Text = ex.Message;
                _banner.BackColor = ColRed;
            }
        }

        private void SetTrayIcon(Color color, string tip)
        {
            try
            {
                Icon old = _trayIcon;
                _trayIcon = MakeDotIcon(color);
                _notify.Icon = _trayIcon;

                // NotifyIcon.Text is capped at 63 characters by the shell.
                _notify.Text = tip.Length > 62 ? tip.Substring(0, 62) : tip;

                if (old != null) old.Dispose();
            }
            catch { }
        }

        private static Icon MakeDotIcon(Color color)
        {
            using (Bitmap bmp = new Bitmap(16, 16))
            {
                using (Graphics g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.Clear(Color.Transparent);
                    using (SolidBrush b = new SolidBrush(color)) g.FillEllipse(b, 1, 1, 13, 13);
                    using (Pen p = new Pen(Color.FromArgb(200, 20, 22, 26), 1.4f)) g.DrawEllipse(p, 1, 1, 13, 13);
                }
                IntPtr handle = bmp.GetHicon();
                try
                {
                    using (Icon tmp = Icon.FromHandle(handle))
                    {
                        return (Icon)tmp.Clone();
                    }
                }
                finally { DestroyIcon(handle); }
            }
        }

        // =====================================================================
        // Config binding
        // =====================================================================

        private void LoadConfigIntoUi()
        {
            _chkLan.Checked = _config.AllowLan;
            _chkDhcp.Checked = _config.AllowDhcp;
            _chkVpnDns.Checked = _config.AllowVpnClientDns;
            _chkInbound.Checked = _config.BlockInbound;

            _suppressBootEvent = true;
            _chkBoot.Checked = BootTask.IsInstalled();
            _suppressBootEvent = false;

            ReloadAdapters();

            Log.Info("Split tunnel config: " + SplitTunnelService.DescribeConfig(_config));
            AppendLog("VPN client programs allowed to reach the server: " + _config.VpnClientPrograms.Count);
            foreach (string p in _config.VpnClientPrograms)
            {
                AppendLog("   " + Path.GetFileName(p) + (File.Exists(p) ? "" : "   (MISSING)"));
            }
        }

        private void ReloadAdapters()
        {
            _clbAdapters.BeginUpdate();
            _clbAdapters.Items.Clear();
            _listAliases.Clear();

            List<AdapterInfo> candidates = AdapterService.GetTunnelCandidates();
            foreach (AdapterInfo a in candidates)
            {
                string ip = a.IPv4.Count > 0 ? string.Join(",", a.IPv4.ToArray()) : "-";

                // Leading marker rather than a trailing one: a trailing note gets
                // pushed off the right edge by long adapter descriptions.
                string label = string.Format("{0} {1,-28} {2,-9} {3,-16} {4}",
                    a.CarriesInternet ? "*" : " ",
                    Trunc(a.Alias, 28), Trunc(a.Status, 9), Trunc(ip, 16), Trunc(a.Description, 30));

                int idx = _clbAdapters.Items.Add(label);
                _listAliases.Add(a.Alias);
                if (_config.TunnelInterfaceAliases.Contains(a.Alias)) _clbAdapters.SetItemChecked(idx, true);
            }

            // Keep configured aliases whose adapter is missing right now, so
            // saving from the UI never silently drops them.
            foreach (string alias in _config.TunnelInterfaceAliases)
            {
                if (_listAliases.Contains(alias)) continue;
                int idx = _clbAdapters.Items.Add(
                    string.Format("  {0,-28} {1}", Trunc(alias, 28), "(not present)"));
                _listAliases.Add(alias);
                _clbAdapters.SetItemChecked(idx, true);
            }

            _clbAdapters.EndUpdate();
        }

        private static string Trunc(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Length <= max ? s : s.Substring(0, max - 1) + "~";
        }

        private AppConfig ReadUiIntoConfig()
        {
            List<string> selected = new List<string>();
            for (int i = 0; i < _clbAdapters.Items.Count; i++)
            {
                if (_clbAdapters.GetItemChecked(i)) selected.Add(_listAliases[i]);
            }

            _config.TunnelInterfaceAliases = selected;
            _config.AllowLan = _chkLan.Checked;
            _config.AllowDhcp = _chkDhcp.Checked;
            _config.AllowVpnClientDns = _chkVpnDns.Checked;
            _config.BlockInbound = _chkInbound.Checked;
            return _config;
        }

        // =====================================================================
        // Actions
        // =====================================================================

        private void OnToggleClick(object sender, EventArgs e)
        {
            try
            {
                StatusInfo s = _ks.GetStatus(_config);

                if (s.KillSwitchEnabled)
                {
                    if (MessageBox.Show(this,
                            "Disarm the kill switch?\r\n\r\nYour traffic will no longer be forced through the VPN, " +
                            "and apps will keep working - unprotected - if the VPN drops.",
                            "RestrictVPN", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    {
                        return;
                    }

                    Cursor = Cursors.WaitCursor;
                    _ks.Disable();
                }
                else
                {
                    AppConfig cfg = ReadUiIntoConfig();
                    if (cfg.TunnelInterfaceAliases.Count == 0)
                    {
                        MessageBox.Show(this,
                            "Tick at least one tunnel adapter first.\r\n\r\nArming with none selected would " +
                            "block the VPN itself, so nothing was changed.",
                            "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    string list = "  - " + string.Join("\r\n  - ", cfg.TunnelInterfaceAliases.ToArray());
                    if (MessageBox.Show(this,
                            "Arm the kill switch?\r\n\r\n" +
                            "Network traffic will only be allowed to leave through:\r\n" + list + "\r\n\r\n" +
                            "If the VPN drops, this PC loses internet entirely. That is the point.\r\n\r\n" +
                            "You can switch it off again whenever you like: this button becomes " +
                            "DISARM KILL SWITCH, and the tray icon has the same option. RestrictVPN " +
                            "edits your firewall locally, so disarming still works while the kill " +
                            "switch is blocking everything.",
                            "RestrictVPN", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    {
                        return;
                    }

                    Cursor = Cursors.WaitCursor;
                    cfg.Save();
                    _ks.Enable(cfg);
                }
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: " + ex.Message);
                MessageBox.Show(this, ex.Message, "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
                RefreshStatus(true);
            }
        }

        private void OnSelfTestClick(object sender, EventArgs e)
        {
            try
            {
                Cursor = Cursors.WaitCursor;
                AppConfig cfg = ReadUiIntoConfig();

                AppendLog("--- self test (creates a disabled probe rule, then deletes it) ---");
                int fatal = 0, warn = 0;
                foreach (CheckResult r in _ks.SelfTest(cfg))
                {
                    string mark = r.Passed ? "OK  " : (r.Fatal ? "FAIL" : "WARN");
                    if (!r.Passed) { if (r.Fatal) fatal++; else warn++; }
                    AppendLog("[" + mark + "] " + r.Check + "  ::  " + r.Detail);
                }

                string summary = fatal > 0
                    ? "Self test FAILED (" + fatal + " critical).\r\n\r\nArming would not protect you correctly. " +
                      "Check that the ticked adapters still exist."
                    : "Self test passed" + (warn > 0 ? " with " + warn + " warning(s)" : "") +
                      ".\r\n\r\nInterface scoping works on this machine, so arming will behave as expected.\r\n\r\n" +
                      "Nothing was changed - your firewall is untouched.";

                AppendLog(fatal > 0 ? "Self test FAILED." : "Self test passed. Nothing was changed.");
                MessageBox.Show(this, summary, "RestrictVPN - Self test",
                    MessageBoxButtons.OK, fatal > 0 ? MessageBoxIcon.Error : MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: " + ex.Message);
                MessageBox.Show(this, ex.Message, "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
            }
        }

        private void OnVerifyClick(object sender, EventArgs e)
        {
            try
            {
                AppendLog("--- rule integrity check ---");
                int fatal = 0, warn = 0;
                foreach (CheckResult r in _ks.Verify(_config))
                {
                    string mark = r.Passed ? "OK  " : (r.Fatal ? "FAIL" : "WARN");
                    if (!r.Passed) { if (r.Fatal) fatal++; else warn++; }
                    AppendLog("[" + mark + "] " + r.Check + "  ::  " + r.Detail);
                }
                AppendLog(fatal > 0
                    ? fatal + " critical check(s) failed - do not rely on this configuration."
                    : (warn > 0 ? "All critical checks passed (" + warn + " warning(s))." : "All checks passed."));
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: " + ex.Message);
            }
        }

        private void OnRecoverClick(object sender, EventArgs e)
        {
            if (MessageBox.Show(this,
                    "Emergency recovery?\r\n\r\nThis forces outbound traffic back to Allow and removes every " +
                    "RestrictVPN rule. Use it if you are locked out of the internet.",
                    "RestrictVPN", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                return;
            }

            try
            {
                Cursor = Cursors.WaitCursor;
                _ks.Recover();
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: " + ex.Message);
                MessageBox.Show(this, ex.Message, "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
                RefreshStatus(true);
            }
        }

        private void OnSaveClick(object sender, EventArgs e)
        {
            SaveAndApply(ReadUiIntoConfig());
        }

        /// <summary>
        /// Anything on the exclusion list that is running on the VPN right now is
        /// offered a restart onto the bypass, because saving the settings is the
        /// moment the user expects them to take effect. Apps that are already
        /// bypassing, or not running, are left alone rather than nagged about.
        /// </summary>
        private void OfferRestarts(AppConfig cfg)
        {
            if (!BypassProxy.IsRunning) return;

            foreach (string exe in cfg.SplitTunnelPrograms)
            {
                if (!File.Exists(exe)) continue;

                AppBypassState state = BypassLauncher.GetState(exe, BypassProxy.Port);
                if (state != AppBypassState.OnVpn) continue;

                LaunchOutsideVpn(exe);
            }
        }

        private void LaunchOutsideVpn(string exe)
        {
            string name = Path.GetFileName(exe);
            try
            {
                bool isolate = false;

                if (!BypassLauncher.IsChromium(exe))
                {
                    MessageBox.Show(this,
                        name + " is running on the VPN, and it cannot be told about a proxy on the " +
                        "command line.\r\n\r\n" +
                        "To take it off the VPN, set its SOCKS5 proxy to 127.0.0.1:" +
                        BypassProxy.Port + " in its own settings.",
                        "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                else if (BypassLauncher.IsRunning(exe))
                {
                    // Chromium reads --proxy-server only at startup, and a running
                    // instance hands the request to itself and drops the argument.
                    // Relaunching is the only way to move an existing profile onto
                    // the bypass, so offer to do exactly that.
                    int choice = ChoiceForm.Ask(this,
                        name + " is running on the VPN",
                        "It is on your exclusion list, but a browser only reads its proxy setting when " +
                        "it starts - so it has to be restarted before it can bypass the VPN.",
                        new string[]
                        {
                            "Close it and reopen outside the VPN  -  keeps your normal profile and tabs",
                            "Open a separate bypass window  -  its own profile, leaves this one running"
                        });

                    if (choice < 0)
                    {
                        AppendLog(name + " left as it is - still going through the VPN.");
                        return;
                    }

                    if (choice == 0)
                    {
                        AppendLog("Closing " + name + "...");
                        Cursor = Cursors.WaitCursor;
                        bool closed;
                        string reason;
                        try { closed = BypassLauncher.CloseRunning(exe, 15000, out reason); }
                        finally { Cursor = Cursors.Default; }

                        if (!closed)
                        {
                            MessageBox.Show(this,
                                name + " did not close, so it was left alone.\r\n\r\n" + reason,
                                "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }
                    }
                    else
                    {
                        isolate = true;
                    }
                }

                BypassLauncher.Launch(exe, BypassProxy.Port, isolate);
                AppendLog("Started " + name + " outside the VPN.");
            }
            catch (Exception ex)
            {
                Log.Error("Launch outside VPN failed for " + name + ": " + ex.Message);
                MessageBox.Show(this, ex.Message, "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnSplitTunnelClick(object sender, EventArgs e)
        {
            using (SplitTunnelForm dlg = new SplitTunnelForm(_config))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
            }
            SaveAndApply(ReadUiIntoConfig());
        }

        /// <summary>
        /// Writes the config, then makes the machine match it.
        ///
        /// While armed the whole policy is rebuilt, because the split tunnel's
        /// firewall holes are derived from the destinations that were actually
        /// routed - the two halves have to be built in one pass or they can
        /// disagree. Unarmed there are no rules to rebuild, so the routes alone
        /// are enough.
        /// </summary>
        private void SaveAndApply(AppConfig cfg)
        {
            try
            {
                Cursor = Cursors.WaitCursor;
                cfg.Save();
                AppendLog("Settings saved to config.json.");

                if (_ks.GetStatus(cfg).KillSwitchEnabled)
                {
                    AppendLog("Kill switch is armed - re-applying rules with the new settings.");
                    _ks.Enable(cfg);
                    AppendLog("Rules re-applied.");
                }
                else
                {
                    SplitTunnelService.Apply(cfg);
                }

                BypassProxy.Sync(cfg);
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: " + ex.Message);
                MessageBox.Show(this, ex.Message, "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
                RefreshStatus(true);
            }

            // After the settings are live, not inside the try: a failure to restart
            // a browser must not read as a failure to apply the policy.
            try { OfferRestarts(cfg); }
            catch (Exception ex) { AppendLog("ERROR: " + ex.Message); }
        }

        /// <summary>
        /// Reinstalls the routes without touching the firewall. Used on launch and
        /// when the physical path moves; the allow rules are scoped by address
        /// rather than by interface precisely so they survive that.
        /// </summary>
        private void ApplySplitTunnelRoutes(string reason)
        {
            if (_splitBusy) return;
            _splitBusy = true;
            AppendLog(reason);

            AppConfig cfg = _config;
            bool armed = false;
            try { armed = _ks.GetStatus(cfg, false, _cachedRuleCount).KillSwitchEnabled; }
            catch { }

            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    SplitTunnelResult result = SplitTunnelService.Apply(cfg);
                    BypassProxy.Sync(cfg);          // re-pin if the physical adapter moved
                    if (armed && result.Targets.Count > 0)
                    {
                        // A hostname exclusion can resolve to a different address
                        // than the live allow rule was built from. That fails
                        // closed - the destination is blocked, not leaked - but it
                        // still needs saying.
                        Log.Info("Split tunnel routes refreshed while armed. If a hostname exclusion " +
                                 "stops working, press Save settings to rebuild the firewall rules.");
                    }
                }
                catch (Exception ex)
                {
                    Log.Error("Split tunnel: " + ex.Message);
                }
                finally
                {
                    _splitBusy = false;
                }
            });
        }

        /// <summary>
        /// Notices when the physical path has moved out from under the routes -
        /// a different Wi-Fi network, a cable plugged in, a new lease.
        /// </summary>
        private void MaybeReapplySplitTunnel()
        {
            if (_splitBusy || !_config.SplitTunnelEnabled) return;
            try
            {
                if (!SplitTunnelService.NeedsReapply(_config)) return;
            }
            catch { return; }

            ApplySplitTunnelRoutes("Network path changed - re-applying split tunnel routes.");
        }

        private void OnBootCheckChanged(object sender, EventArgs e)
        {
            if (_suppressBootEvent) return;
            try
            {
                if (_chkBoot.Checked)
                {
                    if (MessageBox.Show(this,
                            "Arm at startup?\r\n\r\nAfter every restart this PC will have NO internet until the " +
                            "VPN connects. That is the strongest setting.",
                            "RestrictVPN", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    {
                        _suppressBootEvent = true;
                        _chkBoot.Checked = false;
                        _suppressBootEvent = false;
                        return;
                    }
                    BootTask.Install();
                }
                else
                {
                    BootTask.Uninstall();
                }
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: " + ex.Message);
                MessageBox.Show(this, ex.Message, "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                _suppressBootEvent = true;
                _chkBoot.Checked = BootTask.IsInstalled();
                _suppressBootEvent = false;
            }
        }

        // =====================================================================
        // Plumbing
        // =====================================================================

        private void OnLogWritten(string line)
        {
            if (IsDisposed) return;
            if (InvokeRequired)
            {
                try { BeginInvoke(new Action<string>(OnLogWritten), line); }
                catch { }
                return;
            }
            AppendRaw(line);
        }

        private void AppendLog(string message)
        {
            AppendRaw(DateTime.Now.ToString("HH:mm:ss") + "  " + message);
        }

        private void AppendRaw(string line)
        {
            if (_txtLog == null || _txtLog.IsDisposed) return;
            _txtLog.AppendText(line + Environment.NewLine);
        }

        private static void OpenInNotepad(string path)
        {
            try
            {
                if (!File.Exists(path)) File.WriteAllText(path, "");
                Process.Start("notepad.exe", "\"" + path + "\"");
            }
            catch { }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                // Closing hides to the tray so the state indicator stays visible.
                // Exit from the tray menu really quits.
                e.Cancel = true;
                Hide();
                _notify.Visible = true;
                return;
            }
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Log.Written -= OnLogWritten;
                BypassProxy.Stop();
                if (_timer != null) _timer.Stop();
                if (_notify != null) { _notify.Visible = false; _notify.Dispose(); }
                if (_trayIcon != null) _trayIcon.Dispose();
            }
            base.Dispose(disposing);
        }

        // ------------------------------------------------------------ factories

        private Label MakeLabel(string text, int x, int y, int w, int h)
        {
            Label l = new Label();
            l.Text = text;
            l.Location = new Point(x, y);
            l.Size = new Size(w, h);
            l.ForeColor = ColText;
            l.BackColor = Color.Transparent;
            return l;
        }

        private Label MakeHeader(string text, int x, int y)
        {
            Label l = MakeLabel(text, x, y, 520, 24);
            l.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            return l;
        }

        private Button MakeButton(string text, int x, int y, int w, int h, Color back)
        {
            Button b = new Button();
            b.Text = text;
            b.Location = new Point(x, y);
            b.Size = new Size(w, h);
            b.FlatStyle = FlatStyle.Flat;
            b.BackColor = back;
            b.ForeColor = ColText;
            b.FlatAppearance.BorderColor = ColBorder;
            b.UseVisualStyleBackColor = false;
            b.Cursor = Cursors.Hand;
            return b;
        }

        private CheckBox MakeCheck(string text, int x, int y, int w)
        {
            CheckBox c = new CheckBox();
            c.Text = text;
            c.Location = new Point(x, y);
            c.Size = new Size(w, 26);
            c.ForeColor = ColText;
            c.BackColor = Color.Transparent;
            return c;
        }
    }
}
