<#
    .SYNOPSIS
    RestrictVPN desktop UI - a single window to arm, disarm and inspect the
    VPN kill switch. Must run elevated; launch it via RestrictVPN.cmd.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

Import-Module (Join-Path $PSScriptRoot 'RestrictVpn.psm1') -Force

$IsElevated = Test-RvAdmin

# ---------------------------------------------------------------- palette

$ColBg      = [System.Drawing.Color]::FromArgb(24, 26, 31)
$ColPanel   = [System.Drawing.Color]::FromArgb(33, 36, 43)
$ColText    = [System.Drawing.Color]::FromArgb(226, 229, 234)
$ColMuted   = [System.Drawing.Color]::FromArgb(140, 148, 160)
$ColGreen   = [System.Drawing.Color]::FromArgb(46, 160, 92)
$ColAmber   = [System.Drawing.Color]::FromArgb(200, 145, 30)
$ColRed     = [System.Drawing.Color]::FromArgb(196, 62, 62)
$ColAccent  = [System.Drawing.Color]::FromArgb(58, 118, 214)

$FontBase   = New-Object System.Drawing.Font('Segoe UI', 9)
$FontBold   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$FontBanner = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$FontMono   = New-Object System.Drawing.Font('Consolas', 8.5)

# ---------------------------------------------------------------- helpers

function New-Label {
    param($Text, $X, $Y, $W = 200, $H = 20, $Font = $null, $Color = $null)
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.Font      = if ($Font)  { $Font }  else { $FontBase }
    $l.ForeColor = if ($Color) { $Color } else { $ColText }
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}

function New-Button {
    param($Text, $X, $Y, $W = 120, $H = 30, $Color = $null)
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.Font      = $FontBase
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.BackColor = if ($Color) { $Color } else { $ColPanel }
    $b.ForeColor = $ColText
    $b.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(70, 76, 88)
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    return $b
}

function New-Check {
    param($Text, $X, $Y, $W = 300)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text      = $Text
    $c.Location  = New-Object System.Drawing.Point($X, $Y)
    $c.Size      = New-Object System.Drawing.Size($W, 22)
    $c.Font      = $FontBase
    $c.ForeColor = $ColText
    $c.BackColor = [System.Drawing.Color]::Transparent
    return $c
}

# ---------------------------------------------------------------- form

$form              = New-Object System.Windows.Forms.Form
$form.Text         = 'RestrictVPN - VPN Kill Switch'
$form.Size         = New-Object System.Drawing.Size(760, 720)
$form.StartPosition = 'CenterScreen'
$form.BackColor    = $ColBg
$form.Font         = $FontBase
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox  = $false

# --- status banner -------------------------------------------------------

$banner = New-Object System.Windows.Forms.Panel
$banner.Location  = New-Object System.Drawing.Point(0, 0)
$banner.Size      = New-Object System.Drawing.Size(760, 96)
$banner.BackColor = $ColRed
$form.Controls.Add($banner)

$lblVerdict = New-Label -Text 'Checking...' -X 24 -Y 18 -W 700 -H 32 -Font $FontBanner -Color ([System.Drawing.Color]::White)
$banner.Controls.Add($lblVerdict)

$lblDetail = New-Label -Text '' -X 26 -Y 54 -W 700 -H 32 -Color ([System.Drawing.Color]::FromArgb(235, 235, 235))
$banner.Controls.Add($lblDetail)

# --- main toggle ---------------------------------------------------------

$btnToggle = New-Button -Text 'ARM KILL SWITCH' -X 24 -Y 116 -W 260 -H 52 -Color $ColGreen
$btnToggle.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($btnToggle)

$btnVerify = New-Button -Text 'Verify rules' -X 300 -Y 116 -W 120 -H 24
$form.Controls.Add($btnVerify)

$btnRefresh = New-Button -Text 'Refresh' -X 430 -Y 116 -W 100 -H 24
$form.Controls.Add($btnRefresh)

$btnRecover = New-Button -Text 'Emergency recover' -X 300 -Y 144 -W 160 -H 24 -Color ([System.Drawing.Color]::FromArgb(90, 40, 40))
$form.Controls.Add($btnRecover)

$btnLog = New-Button -Text 'Open log' -X 470 -Y 144 -W 100 -H 24
$form.Controls.Add($btnLog)

# --- adapters ------------------------------------------------------------

$form.Controls.Add((New-Label -Text 'Tunnel adapters traffic may leave through' -X 24 -Y 186 -W 400 -Font $FontBold))
$form.Controls.Add((New-Label -Text 'Tick every adapter your VPN uses. Everything unticked is blocked.' -X 24 -Y 206 -W 500 -Color $ColMuted))

$clbAdapters = New-Object System.Windows.Forms.CheckedListBox
$clbAdapters.Location      = New-Object System.Drawing.Point(24, 230)
$clbAdapters.Size          = New-Object System.Drawing.Size(700, 132)
$clbAdapters.BackColor     = $ColPanel
$clbAdapters.ForeColor     = $ColText
$clbAdapters.BorderStyle   = 'FixedSingle'
$clbAdapters.CheckOnClick  = $true
$clbAdapters.Font          = $FontMono
$form.Controls.Add($clbAdapters)

# --- options -------------------------------------------------------------

$form.Controls.Add((New-Label -Text 'Options' -X 24 -Y 374 -W 200 -Font $FontBold))

$chkLan     = New-Check -Text 'Allow local network (printers, NAS) - reopens DNS to your router' -X 24 -Y 398 -W 480
$chkDhcp    = New-Check -Text 'Allow DHCP (needed for Wi-Fi/Ethernet to get an address)'         -X 24 -Y 422 -W 480
$chkVpnDns  = New-Check -Text 'Allow the VPN client to resolve its server hostname'              -X 24 -Y 446 -W 480
$chkInbound = New-Check -Text 'Block inbound traffic as well'                                    -X 24 -Y 470 -W 480
$form.Controls.AddRange(@($chkLan, $chkDhcp, $chkVpnDns, $chkInbound))

$btnSave = New-Button -Text 'Save settings' -X 540 -Y 420 -W 130 -H 30 -Color $ColAccent
$form.Controls.Add($btnSave)

$btnConfig = New-Button -Text 'Edit config.json' -X 540 -Y 456 -W 130 -H 24
$form.Controls.Add($btnConfig)

# --- output --------------------------------------------------------------

$form.Controls.Add((New-Label -Text 'Activity' -X 24 -Y 502 -W 200 -Font $FontBold))

$txtOut = New-Object System.Windows.Forms.TextBox
$txtOut.Location   = New-Object System.Drawing.Point(24, 524)
$txtOut.Size       = New-Object System.Drawing.Size(700, 140)
$txtOut.Multiline  = $true
$txtOut.ScrollBars = 'Vertical'
$txtOut.ReadOnly   = $true
$txtOut.BackColor  = $ColPanel
$txtOut.ForeColor  = $ColMuted
$txtOut.Font       = $FontMono
$txtOut.BorderStyle = 'FixedSingle'
$form.Controls.Add($txtOut)

# ---------------------------------------------------------------- logic

function Write-Out {
    param([string]$Text)
    $stamp = Get-Date -Format 'HH:mm:ss'
    $txtOut.AppendText("[$stamp] $Text" + [Environment]::NewLine)
}

function Sync-AdapterList {
    param($Config)
    $clbAdapters.Items.Clear()
    $script:AdapterAliases = @()

    $candidates = @(Get-RvCandidateTunnelAdapter | Sort-Object Name)
    $selected   = @($Config.TunnelInterfaceAliases)

    foreach ($c in $candidates) {
        $label = '{0,-34} {1,-13} {2}' -f $c.Name, $c.Status, $c.InterfaceDescription
        $idx = $clbAdapters.Items.Add($label)
        $script:AdapterAliases += $c.Name
        if ($selected -contains $c.Name) { $clbAdapters.SetItemChecked($idx, $true) }
    }

    # Keep aliases that are configured but whose adapter is currently absent,
    # so saving from the GUI never silently drops them.
    foreach ($alias in $selected) {
        if ($script:AdapterAliases -notcontains $alias) {
            $idx = $clbAdapters.Items.Add(('{0,-34} {1}' -f $alias, '(not present)'))
            $script:AdapterAliases += $alias
            $clbAdapters.SetItemChecked($idx, $true)
        }
    }
}

function Update-Ui {
    try {
        $cfg = Get-RvConfig
        $s   = Get-RvStatus -Config $cfg

        $lblVerdict.Text = $s.Verdict.Split('-')[0].Trim()
        $lblDetail.Text  = ($s.Verdict -split '-', 2)[-1].Trim()

        if ($s.KillSwitchEnabled -and $s.VpnTunnelActive) {
            $banner.BackColor  = $ColGreen
        } elseif ($s.KillSwitchEnabled) {
            $banner.BackColor  = $ColAmber
        } else {
            $banner.BackColor  = $ColRed
        }

        if ($s.KillSwitchEnabled) {
            $btnToggle.Text      = 'DISARM KILL SWITCH'
            $btnToggle.BackColor = [System.Drawing.Color]::FromArgb(120, 60, 60)
        } else {
            $btnToggle.Text      = 'ARM KILL SWITCH'
            $btnToggle.BackColor = $ColGreen
        }

        $script:CurrentStatus = $s
    }
    catch {
        $lblVerdict.Text = 'Error'
        $lblDetail.Text  = $_.Exception.Message
        $banner.BackColor = $ColRed
    }
}

function Read-UiConfig {
    $cfg = Get-RvConfig

    $checked = @()
    for ($i = 0; $i -lt $clbAdapters.Items.Count; $i++) {
        if ($clbAdapters.GetItemChecked($i)) { $checked += $script:AdapterAliases[$i] }
    }

    $cfg['TunnelInterfaceAliases'] = @($checked)
    $cfg['AllowLan']               = [bool]$chkLan.Checked
    $cfg['AllowDhcp']              = [bool]$chkDhcp.Checked
    $cfg['AllowVpnClientDns']      = [bool]$chkVpnDns.Checked
    $cfg['BlockInbound']           = [bool]$chkInbound.Checked
    return $cfg
}

function Initialize-Ui {
    $cfg = Get-RvConfig
    Sync-AdapterList -Config $cfg
    $chkLan.Checked     = [bool]$cfg.AllowLan
    $chkDhcp.Checked    = [bool]$cfg.AllowDhcp
    $chkVpnDns.Checked  = [bool]$cfg.AllowVpnClientDns
    $chkInbound.Checked = [bool]$cfg.BlockInbound

    $programs = @($cfg.VpnClientPrograms)
    Write-Out ("VPN client programs allowed to reach the server: $($programs.Count)")
    foreach ($p in $programs) { Write-Out ("  " + (Split-Path -Leaf $p)) }

    if (-not $IsElevated) {
        Write-Out 'NOT RUNNING AS ADMINISTRATOR - arming and disarming are disabled.'
        Write-Out 'Close this window and start RestrictVPN.cmd instead.'
        $btnToggle.Enabled = $false
        $btnRecover.Enabled = $false
        $btnSave.Enabled = $false
    }
    Update-Ui
}

# ---------------------------------------------------------------- events

$btnToggle.Add_Click({
    try {
        $s = Get-RvStatus
        if ($s.KillSwitchEnabled) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "Disarm the kill switch?`n`nYour traffic will no longer be forced through the VPN, and apps will keep working if the VPN drops.",
                'RestrictVPN', 'YesNo', 'Warning')
            if ($answer -ne 'Yes') { return }

            $form.Cursor = 'WaitCursor'
            Disable-RvKillSwitch
            Write-Out 'Kill switch DISARMED. Normal internet access restored.'
        }
        else {
            $cfg = Read-UiConfig
            if (@($cfg.TunnelInterfaceAliases).Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Tick at least one tunnel adapter first, otherwise arming would block the VPN itself.',
                    'RestrictVPN', 'OK', 'Warning') | Out-Null
                return
            }

            $list   = ($cfg.TunnelInterfaceAliases | ForEach-Object { "  - $_" }) -join "`n"
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "Arm the kill switch?`n`nAfter this, the only way out of this PC is through:`n$list`n`nIf the VPN drops, this machine loses internet entirely. That is intended.`n`nIf anything goes wrong, run Recover.cmd as Administrator.",
                'RestrictVPN', 'YesNo', 'Warning')
            if ($answer -ne 'Yes') { return }

            $form.Cursor = 'WaitCursor'
            Save-RvConfig -Config $cfg
            Enable-RvKillSwitch -Config $cfg
            Write-Out 'Kill switch ARMED. All traffic now requires the VPN tunnel.'

            foreach ($r in @(Test-RvRuleIntegrity -Config $cfg)) {
                $mark = if ($r.Passed) { 'OK  ' } else { 'FAIL' }
                Write-Out ("  [$mark] " + $r.Check)
            }
        }
    }
    catch {
        Write-Out ('ERROR: ' + $_.Exception.Message)
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'RestrictVPN', 'OK', 'Error') | Out-Null
    }
    finally {
        $form.Cursor = 'Default'
        Update-Ui
    }
})

$btnVerify.Add_Click({
    try {
        Write-Out '--- rule integrity check ---'
        $results = @(Test-RvRuleIntegrity)
        foreach ($r in $results) {
            $mark = if ($r.Passed) { 'OK  ' } else { 'FAIL' }
            Write-Out ("[$mark] $($r.Check) :: $($r.Detail)")
        }
        $failed = @($results | Where-Object { -not $_.Passed }).Count
        Write-Out $(if ($failed -eq 0) { 'All checks passed.' } else { "$failed check(s) failed." })
    }
    catch { Write-Out ('ERROR: ' + $_.Exception.Message) }
})

$btnRefresh.Add_Click({
    $cfg = Get-RvConfig
    Sync-AdapterList -Config $cfg
    Update-Ui
    Write-Out 'Refreshed.'
})

$btnSave.Add_Click({
    try {
        $cfg = Read-UiConfig
        Save-RvConfig -Config $cfg
        Write-Out 'Settings saved to config.json.'
        if ((Get-RvStatus).KillSwitchEnabled) {
            Write-Out 'Kill switch is armed - re-applying rules with the new settings.'
            Enable-RvKillSwitch -Config $cfg
            Write-Out 'Rules re-applied.'
        }
        Update-Ui
    }
    catch { Write-Out ('ERROR: ' + $_.Exception.Message) }
})

$btnRecover.Add_Click({
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Emergency recovery?`n`nThis forces outbound traffic back to Allow and removes every RestrictVPN rule. Use it if you are locked out of the internet.",
        'RestrictVPN', 'YesNo', 'Warning')
    if ($answer -ne 'Yes') { return }
    try {
        Reset-RvFirewall
        Write-Out 'Emergency recovery complete - internet access restored.'
        Update-Ui
    }
    catch { Write-Out ('ERROR: ' + $_.Exception.Message) }
})

$btnLog.Add_Click({
    $path = Get-RvLogPath
    if (Test-Path $path) { Start-Process notepad.exe -ArgumentList $path }
    else { Write-Out 'No log file yet.' }
})

$btnConfig.Add_Click({
    Get-RvConfig | Out-Null
    Start-Process notepad.exe -ArgumentList (Get-RvConfigPath)
})

# Poll so the banner tracks the VPN going up and down on its own.
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({ Update-Ui })
$timer.Start()

$form.Add_Shown({ Initialize-Ui })
$form.Add_FormClosed({ $timer.Stop() })

[void]$form.ShowDialog()
