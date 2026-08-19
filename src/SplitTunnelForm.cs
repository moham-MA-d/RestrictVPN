using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace RestrictVpn
{
    /// <summary>The one place the window colours are defined.</summary>
    internal static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(24, 26, 31);
        public static readonly Color Panel = Color.FromArgb(33, 36, 43);
        public static readonly Color Border = Color.FromArgb(70, 76, 88);
        public static readonly Color Text = Color.FromArgb(226, 229, 234);
        public static readonly Color Muted = Color.FromArgb(140, 148, 160);
        public static readonly Color Green = Color.FromArgb(38, 145, 84);
        public static readonly Color Amber = Color.FromArgb(191, 138, 26);
        public static readonly Color Red = Color.FromArgb(186, 58, 58);
        public static readonly Color Accent = Color.FromArgb(52, 110, 205);

        public static Button Button(string text, int x, int y, int w, int h, Color back)
        {
            Button b = new Button();
            b.Text = text;
            b.Location = new Point(x, y);
            b.Size = new Size(w, h);
            b.FlatStyle = FlatStyle.Flat;
            b.BackColor = back;
            b.ForeColor = Text;
            b.FlatAppearance.BorderColor = Border;
            b.UseVisualStyleBackColor = false;
            b.Cursor = Cursors.Hand;
            return b;
        }

        public static Label Label(string text, int x, int y, int w, int h)
        {
            Label l = new Label();
            l.Text = text;
            l.Location = new Point(x, y);
            l.Size = new Size(w, h);
            l.ForeColor = Text;
            l.BackColor = Color.Transparent;
            return l;
        }
    }

    /// <summary>One line in the exclusion list.</summary>
    internal class Exclusion
    {
        public bool IsApp;
        public string Value;

        public Exclusion(bool isApp, string value) { IsApp = isApp; Value = value; }

        /// <summary>
        /// Destinations are simply on once saved. Apps are not, and the difference
        /// is the thing people get wrong - so an app says which side of the tunnel
        /// it is currently on rather than leaving it to be guessed.
        /// </summary>
        public string Display
        {
            get
            {
                if (!IsApp) return "NET   " + Value;

                string state;
                if (!File.Exists(Value)) state = "not found";
                else if (!BypassProxy.IsRunning) state = "needs the bypass proxy";
                else
                {
                    switch (BypassLauncher.GetState(Value, BypassProxy.Port))
                    {
                        case AppBypassState.Bypassing: state = "bypassing the VPN"; break;
                        case AppBypassState.OnVpn: state = "running ON the VPN - save to restart it"; break;
                        default: state = "not running"; break;
                    }
                }
                return "APP   " + Value + "      [" + state + "]";
            }
        }
    }

    /// <summary>
    /// Editor for the exclusion list. Changes nothing on its own - the caller
    /// saves the config and re-applies, so cancelling really cancels.
    /// </summary>
    internal class SplitTunnelForm : Form
    {
        private readonly AppConfig _config;
        private readonly List<Exclusion> _entries = new List<Exclusion>();
        private readonly List<string> _adapterAliases = new List<string>();

        private CheckBox _chkEnabled;
        private ComboBox _cboAdapter;
        private Label _lblDetected;
        private ListBox _list;
        private Button _btnRemove;
        private CheckBox _chkProxy;
        private TextBox _txtPort;
        private Label _lblProxyStatus;

        public SplitTunnelForm(AppConfig config)
        {
            _config = config;
            BuildUi();
            LoadFromConfig();
        }

        // =====================================================================
        // UI
        // =====================================================================

        private void BuildUi()
        {
            Text = "RestrictVPN - Split tunnel";
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(830, 726);
            MinimumSize = new Size(760, 600);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = false;
            MinimizeBox = false;
            AutoScroll = true;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = new Font("Segoe UI", 9f);
            Icon = SystemIcons.Shield;

            Label intro = Theme.Label(
                "Anything listed below leaves through your physical adapter instead of the VPN. " +
                "Everything else keeps going through the tunnel, and the kill switch still blocks " +
                "every path that is neither.",
                24, 20, 782, 40);
            intro.ForeColor = Theme.Muted;
            Controls.Add(intro);

            _chkEnabled = new CheckBox();
            _chkEnabled.Text = "Enable split tunnel";
            _chkEnabled.Location = new Point(24, 68);
            _chkEnabled.Size = new Size(300, 26);
            _chkEnabled.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            _chkEnabled.ForeColor = Theme.Text;
            _chkEnabled.BackColor = Color.Transparent;
            _chkEnabled.CheckedChanged += delegate { UpdateEnabledState(); };
            Controls.Add(_chkEnabled);

            // --- adapter ---
            Controls.Add(Theme.Label("Physical adapter excluded traffic should use:", 24, 106, 330, 24));

            _cboAdapter = new ComboBox();
            _cboAdapter.Location = new Point(360, 103);
            _cboAdapter.Size = new Size(446, 24);
            _cboAdapter.DropDownStyle = ComboBoxStyle.DropDownList;
            _cboAdapter.BackColor = Theme.Panel;
            _cboAdapter.ForeColor = Theme.Text;
            _cboAdapter.FlatStyle = FlatStyle.Flat;
            _cboAdapter.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _cboAdapter.SelectedIndexChanged += delegate { RefreshDetected(); };
            Controls.Add(_cboAdapter);

            _lblDetected = Theme.Label("", 24, 134, 782, 22);
            _lblDetected.ForeColor = Theme.Muted;
            _lblDetected.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_lblDetected);

            // --- list ---
            Label header = Theme.Label("Excluded destinations and apps", 24, 170, 400, 24);
            header.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            Controls.Add(header);

            Label hint = Theme.Label(
                "Destinations may be an IP (1.2.3.4), a range (192.168.50.0/24) or a hostname (example.com).",
                24, 194, 782, 22);
            hint.ForeColor = Theme.Muted;
            Controls.Add(hint);

            _list = new ListBox();
            _list.Location = new Point(24, 220);
            _list.Size = new Size(614, 224);
            _list.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _list.BackColor = Theme.Panel;
            _list.ForeColor = Theme.Text;
            _list.BorderStyle = BorderStyle.FixedSingle;
            _list.Font = new Font("Consolas", 9f);
            _list.IntegralHeight = false;
            _list.SelectedIndexChanged += delegate { _btnRemove.Enabled = _list.SelectedIndex >= 0; };
            Controls.Add(_list);

            Button addAddress = Theme.Button("Add IP / range / host...", 652, 220, 154, 34, Theme.Panel);
            addAddress.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            addAddress.Click += OnAddAddress;
            Controls.Add(addAddress);

            Button addApp = Theme.Button("Add app...", 652, 260, 154, 34, Theme.Panel);
            addApp.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            addApp.Click += OnAddApp;
            Controls.Add(addApp);

            _btnRemove = Theme.Button("Remove", 652, 300, 154, 34, Color.FromArgb(88, 40, 40));
            _btnRemove.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnRemove.Enabled = false;
            _btnRemove.Click += OnRemove;
            Controls.Add(_btnRemove);

            // --- bypass proxy ---
            _chkProxy = new CheckBox();
            _chkProxy.Text = "Run the bypass proxy - this is what makes an app exclusion actually work";
            _chkProxy.Location = new Point(24, 458);
            _chkProxy.Size = new Size(520, 26);
            _chkProxy.ForeColor = Theme.Text;
            _chkProxy.BackColor = Color.Transparent;
            _chkProxy.CheckedChanged += delegate { RefreshProxyStatus(); UpdateEnabledState(); };
            Controls.Add(_chkProxy);

            Label portLabel = Theme.Label("Port", 556, 461, 34, 22);
            portLabel.ForeColor = Theme.Muted;
            Controls.Add(portLabel);

            _txtPort = new TextBox();
            _txtPort.Location = new Point(594, 458);
            _txtPort.Size = new Size(62, 24);
            _txtPort.BackColor = Theme.Panel;
            _txtPort.ForeColor = Theme.Text;
            _txtPort.BorderStyle = BorderStyle.FixedSingle;
            _txtPort.Font = new Font("Consolas", 9.5f);
            Controls.Add(_txtPort);

            Button test = Theme.Button("Test bypass", 676, 456, 130, 28, Theme.Panel);
            test.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            test.Click += OnTestBypass;
            Controls.Add(test);

            _lblProxyStatus = Theme.Label("", 24, 488, 782, 22);
            _lblProxyStatus.ForeColor = Theme.Muted;
            Controls.Add(_lblProxyStatus);

            // --- honesty panel ---
            Panel note = new Panel();
            note.Location = new Point(24, 518);
            note.Size = new Size(782, 136);
            note.BackColor = Theme.Panel;
            note.BorderStyle = BorderStyle.FixedSingle;
            note.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(note);

            Label noteTitle = Theme.Label("How each kind of exclusion actually works", 14, 10, 700, 20);
            noteTitle.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            noteTitle.ForeColor = Theme.Amber;
            note.Controls.Add(noteTitle);

            Label noteText = Theme.Label(
                "A destination takes effect the moment you save: RestrictVPN adds a route, so those packets " +
                "leave through your physical adapter from then on.\r\n\r\n" +
                "An app has to be restarted. A browser reads its proxy setting once, when it starts, so an " +
                "app already running cannot be moved onto the bypass - saving offers to restart it for you, " +
                "keeping your normal profile and tabs. Chrome, Edge and Brave are handled automatically; " +
                "anything else needs 127.0.0.1 set as its SOCKS5 proxy by hand.",
                14, 32, 754, 98);
            noteText.ForeColor = Theme.Muted;
            note.Controls.Add(noteText);

            // --- buttons ---
            Button ok = Theme.Button("Save and apply", 610, 672, 196, 38, Theme.Accent);
            ok.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            ok.Click += OnSave;
            Controls.Add(ok);

            Button cancel = Theme.Button("Cancel", 490, 672, 108, 38, Theme.Panel);
            cancel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            CancelButton = cancel;
        }

        // =====================================================================
        // Binding
        // =====================================================================

        private void LoadFromConfig()
        {
            _chkEnabled.Checked = _config.SplitTunnelEnabled;
            _chkProxy.Checked = _config.BypassProxyEnabled;
            _txtPort.Text = (_config.BypassProxyPort > 0 ? _config.BypassProxyPort : 1080).ToString();

            foreach (string a in _config.SplitTunnelAddresses)
            {
                if (!string.IsNullOrEmpty(a)) _entries.Add(new Exclusion(false, a));
            }
            foreach (string exe in _config.SplitTunnelPrograms)
            {
                if (!string.IsNullOrEmpty(exe)) _entries.Add(new Exclusion(true, exe));
            }

            _cboAdapter.Items.Add("Auto-detect  (recommended)");
            _adapterAliases.Add("");

            foreach (Underlay u in RouteService.Candidates(_config))
            {
                _cboAdapter.Items.Add(u.Alias + "   -   " + u.Description);
                _adapterAliases.Add(u.Alias);
            }

            string pinned = (_config.SplitTunnelUnderlayAlias ?? "").Trim();
            int index = 0;
            if (pinned.Length > 0)
            {
                for (int i = 1; i < _adapterAliases.Count; i++)
                {
                    if (string.Equals(_adapterAliases[i], pinned, StringComparison.OrdinalIgnoreCase))
                    {
                        index = i;
                        break;
                    }
                }
                if (index == 0)
                {
                    // The pinned adapter is gone. Keep the name visible rather than
                    // silently resetting the choice the user made.
                    _cboAdapter.Items.Add(pinned + "   -   (not present)");
                    _adapterAliases.Add(pinned);
                    index = _adapterAliases.Count - 1;
                }
            }
            _cboAdapter.SelectedIndex = index;

            RefreshList();
            RefreshDetected();
            RefreshProxyStatus();
            UpdateEnabledState();
        }

        private void RefreshList()
        {
            int selected = _list.SelectedIndex;
            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (Exclusion e in _entries) _list.Items.Add(e.Display);
            _list.EndUpdate();

            if (selected >= 0 && selected < _list.Items.Count) _list.SelectedIndex = selected;
            _btnRemove.Enabled = _list.SelectedIndex >= 0;
        }

        private void RefreshDetected()
        {
            AppConfig probe = _config;
            string previous = probe.SplitTunnelUnderlayAlias;
            try
            {
                probe.SplitTunnelUnderlayAlias = SelectedAlias();
                Underlay u = RouteService.Find(probe);
                if (u == null)
                {
                    _lblDetected.Text = "No physical adapter with a default gateway is available right now.";
                    _lblDetected.ForeColor = Theme.Amber;
                }
                else
                {
                    _lblDetected.Text = "Using " + u.Alias +
                        "   IPv4 gateway " + (u.GatewayV4 ?? "none") +
                        "   IPv6 gateway " + (u.GatewayV6 ?? "none");
                    _lblDetected.ForeColor = Theme.Muted;
                }
            }
            finally
            {
                probe.SplitTunnelUnderlayAlias = previous;
            }
        }

        private void RefreshProxyStatus()
        {
            if (!_chkProxy.Checked)
            {
                _lblProxyStatus.Text = "Off. App exclusions will be firewall permissions only.";
                _lblProxyStatus.ForeColor = Theme.Muted;
                return;
            }

            _lblProxyStatus.Text = BypassProxy.IsRunning
                ? "Live: " + BypassProxy.Status + "."
                : "Starts when you save, and excluded apps are offered a restart onto it.";
            _lblProxyStatus.ForeColor = Theme.Text;
        }

        private void OnTestBypass(object sender, EventArgs e)
        {
            if (!BypassProxy.IsRunning)
            {
                MessageBox.Show(this,
                    "The bypass proxy is not running yet.\r\n\r\nTick \"Run the bypass proxy\" and " +
                    "press Save and apply, then test.",
                    "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Cursor = Cursors.WaitCursor;
            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                BypassCheck result;
                try { result = BypassProxy.Check(); }
                catch (Exception ex)
                {
                    result = new BypassCheck();
                    result.Error = ex.Message;
                }

                if (IsDisposed) return;
                try { BeginInvoke(new Action<BypassCheck>(ShowCheck), result); }
                catch { }
            });
        }

        private void ShowCheck(BypassCheck result)
        {
            Cursor = Cursors.Default;

            if (!string.IsNullOrEmpty(result.Error))
            {
                MessageBox.Show(this, result.Error, "RestrictVPN - Test bypass",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            MessageBox.Show(this,
                "Normal traffic leaves as:   " + result.Direct + "\r\n" +
                "Through the bypass proxy:   " + result.Bypassed + "\r\n\r\n" +
                (result.Working
                    ? "The bypass is working. Excluded apps started through it are seen as " +
                      result.Bypassed + " instead of " + result.Direct + "."
                    : "Both paths come out the same, so nothing is being bypassed. If the VPN is " +
                      "disconnected that is expected - there is nothing to bypass."),
                "RestrictVPN - Test bypass", MessageBoxButtons.OK,
                result.Working ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

            RefreshList();
        }

        private string SelectedAlias()
        {
            int i = _cboAdapter.SelectedIndex;
            if (i < 0 || i >= _adapterAliases.Count) return "";
            return _adapterAliases[i];
        }

        private void UpdateEnabledState()
        {
            bool on = _chkEnabled.Checked;
            _cboAdapter.Enabled = on;
            _list.Enabled = on;
            _chkProxy.Enabled = on;
            _txtPort.Enabled = on && _chkProxy.Checked;
            foreach (Control c in Controls)
            {
                Button b = c as Button;
                if (b == null) continue;
                if (b.Text.StartsWith("Add") || b.Text == "Remove") b.Enabled = on;
            }
            if (on) _btnRemove.Enabled = _list.SelectedIndex >= 0;
        }

        // =====================================================================
        // Actions
        // =====================================================================

        private void OnAddAddress(object sender, EventArgs e)
        {
            string value = PromptForm.Ask(this,
                "Add a destination to keep off the VPN",
                "An IP address, a CIDR range, or a hostname.\r\n\r\n" +
                "    1.2.3.4            a single host\r\n" +
                "    192.168.50.0/24    a whole range\r\n" +
                "    example.com        resolved now, and re-resolved every time the rules are applied",
                "");

            if (value == null) return;
            value = value.Trim();
            if (value.Length == 0) return;

            List<string> problems = new List<string>();
            AppConfig probe = new AppConfig();
            probe.SplitTunnelAddresses.Add(value);
            List<RouteTarget> parsed = SplitTunnelService.Resolve(probe, null, problems);

            if (parsed.Count == 0)
            {
                MessageBox.Show(this,
                    "That entry cannot be used:\r\n\r\n" + string.Join("\r\n", problems.ToArray()),
                    "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            foreach (Exclusion existing in _entries)
            {
                if (!existing.IsApp && string.Equals(existing.Value, value, StringComparison.OrdinalIgnoreCase))
                {
                    return;   // already listed
                }
            }

            _entries.Add(new Exclusion(false, value));
            RefreshList();

            if (problems.Count > 0)
            {
                MessageBox.Show(this,
                    "Added, with a note:\r\n\r\n" + string.Join("\r\n", problems.ToArray()),
                    "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void OnAddApp(object sender, EventArgs e)
        {
            using (OpenFileDialog dlg = new OpenFileDialog())
            {
                dlg.Title = "Choose the program to keep off the VPN";
                dlg.Filter = "Programs (*.exe)|*.exe|All files (*.*)|*.*";
                dlg.CheckFileExists = true;
                if (dlg.ShowDialog(this) != DialogResult.OK) return;

                string exe = dlg.FileName;
                foreach (Exclusion existing in _entries)
                {
                    if (existing.IsApp && string.Equals(existing.Value, exe, StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }

                _entries.Add(new Exclusion(true, exe));
                RefreshList();
            }
        }

        private void OnRemove(object sender, EventArgs e)
        {
            int i = _list.SelectedIndex;
            if (i < 0 || i >= _entries.Count) return;
            _entries.RemoveAt(i);
            RefreshList();
        }

        private void OnSave(object sender, EventArgs e)
        {
            List<string> addresses = new List<string>();
            List<string> programs = new List<string>();

            foreach (Exclusion entry in _entries)
            {
                if (entry.IsApp) programs.Add(entry.Value);
                else addresses.Add(entry.Value);
            }

            if (_chkEnabled.Checked && addresses.Count == 0 && programs.Count == 0)
            {
                if (MessageBox.Show(this,
                        "Split tunnel is switched on but nothing is excluded, so all traffic keeps " +
                        "using the VPN.\r\n\r\nSave anyway?",
                        "RestrictVPN", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                {
                    return;
                }
            }

            int port;
            if (!int.TryParse(_txtPort.Text.Trim(), out port) || port < 1 || port > 65535)
            {
                MessageBox.Show(this, "The bypass proxy port must be a number between 1 and 65535.",
                    "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (_chkEnabled.Checked && _chkProxy.Checked)
            {
                string reserved = BypassProxy.ExcludedRangeContaining(port);
                if (reserved != null)
                {
                    MessageBox.Show(this,
                        "Port " + port + " is inside the reserved range " + reserved + ".\r\n\r\n" +
                        "Windows hands these blocks to Hyper-V and WSL, so nothing can listen there. " +
                        "RestrictVPN will pick a free port automatically and save it here.",
                        "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }

            if (_chkEnabled.Checked && programs.Count > 0 && addresses.Count == 0 && !_chkProxy.Checked)
            {
                MessageBox.Show(this,
                    "You have excluded apps, no destinations, and the bypass proxy is off.\r\n\r\n" +
                    "In that combination nothing changes: an app exclusion is a firewall permission, and " +
                    "Windows still chooses the route by destination. Switch on the bypass proxy, or add " +
                    "the addresses that app talks to.",
                    "RestrictVPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            _config.BypassProxyEnabled = _chkProxy.Checked;
            _config.BypassProxyPort = port;
            _config.SplitTunnelEnabled = _chkEnabled.Checked;
            _config.SplitTunnelAddresses = addresses;
            _config.SplitTunnelPrograms = programs;
            _config.SplitTunnelUnderlayAlias = SelectedAlias();

            DialogResult = DialogResult.OK;
            Close();
        }
    }

    /// <summary>
    /// A dialog whose buttons say what they do. The choice here is between two
    /// things that both sound like "yes", so Yes/No/Cancel would be a guess.
    /// </summary>
    internal class ChoiceForm : Form
    {
        private int _picked = -1;

        /// <summary>Returns the index of the option chosen, or -1 if cancelled.</summary>
        public static int Ask(IWin32Window owner, string title, string description, string[] options)
        {
            using (ChoiceForm f = new ChoiceForm(title, description, options))
            {
                f.ShowDialog(owner);
                return f._picked;
            }
        }

        private ChoiceForm(string title, string description, string[] options)
        {
            int height = 150 + options.Length * 52;

            Text = "RestrictVPN";
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(600, height);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = new Font("Segoe UI", 9f);

            Label caption = Theme.Label(title, 20, 18, 560, 24);
            caption.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            Controls.Add(caption);

            Label detail = Theme.Label(description, 20, 46, 560, 56);
            detail.ForeColor = Theme.Muted;
            Controls.Add(detail);

            int y = 110;
            for (int i = 0; i < options.Length; i++)
            {
                int index = i;
                Button b = Theme.Button(options[i], 20, y, 560, 44,
                                        i == 0 ? Theme.Accent : Theme.Panel);
                b.TextAlign = ContentAlignment.MiddleLeft;
                b.Padding = new Padding(12, 0, 0, 0);
                b.Click += delegate { _picked = index; Close(); };
                Controls.Add(b);
                y += 52;
            }

            Button cancel = Theme.Button("Cancel", 460, y + 4, 120, 32, Theme.Panel);
            cancel.Click += delegate { _picked = -1; Close(); };
            Controls.Add(cancel);
            CancelButton = cancel;
        }
    }

    /// <summary>WinForms has no input box, so here is the smallest possible one.</summary>
    internal class PromptForm : Form
    {
        private TextBox _input;

        /// <summary>Returns null when cancelled.</summary>
        public static string Ask(IWin32Window owner, string title, string description, string initial)
        {
            using (PromptForm f = new PromptForm(title, description, initial))
            {
                return f.ShowDialog(owner) == DialogResult.OK ? f._input.Text : null;
            }
        }

        private PromptForm(string title, string description, string initial)
        {
            Text = "RestrictVPN - " + title;
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(560, 250);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = new Font("Segoe UI", 9f);

            Label caption = Theme.Label(title, 20, 18, 520, 24);
            caption.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            Controls.Add(caption);

            Label detail = Theme.Label(description, 20, 48, 520, 100);
            detail.ForeColor = Theme.Muted;
            detail.Font = new Font("Consolas", 8.5f);
            Controls.Add(detail);

            _input = new TextBox();
            _input.Location = new Point(20, 156);
            _input.Size = new Size(520, 26);
            _input.Text = initial ?? "";
            _input.BackColor = Theme.Panel;
            _input.ForeColor = Theme.Text;
            _input.BorderStyle = BorderStyle.FixedSingle;
            _input.Font = new Font("Consolas", 10f);
            Controls.Add(_input);

            Button ok = Theme.Button("Add", 420, 198, 120, 34, Theme.Accent);
            ok.DialogResult = DialogResult.OK;
            Controls.Add(ok);

            Button cancel = Theme.Button("Cancel", 292, 198, 120, 34, Theme.Panel);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;
        }
    }
}
