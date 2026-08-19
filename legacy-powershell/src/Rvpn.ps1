<#
    .SYNOPSIS
    RestrictVPN command line - arm or disarm the VPN kill switch.

    .EXAMPLE
    .\Rvpn.ps1 status
    .\Rvpn.ps1 detect
    .\Rvpn.ps1 enable
    .\Rvpn.ps1 disable
    .\Rvpn.ps1 verify
    .\Rvpn.ps1 recover
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'enable', 'disable', 'detect', 'verify', 'recover', 'config', 'log', 'help')]
    [string]$Action = 'status',

    # Skip the confirmation prompt on enable/disable/recover.
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'RestrictVpn.psm1') -Force

function Write-Banner {
    param([string]$Text, [string]$Color = 'Cyan')
    $bar = '=' * 68
    Write-Host ''
    Write-Host $bar -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host $bar -ForegroundColor $Color
}

function Show-Status {
    $s = Get-RvStatus

    $color = if ($s.KillSwitchEnabled -and $s.VpnTunnelActive) { 'Green' }
             elseif ($s.KillSwitchEnabled)                     { 'Yellow' }
             else                                              { 'Red' }
    Write-Banner -Text $s.Verdict -Color $color

    Write-Host ''
    Write-Host ('  Kill switch : {0}' -f $(if ($s.KillSwitchEnabled) { 'ARMED' } else { 'off' }))
    Write-Host ('  VPN tunnel  : {0}' -f $(if ($s.VpnTunnelActive) { 'UP (carrying default route)' } else { 'DOWN' }))
    Write-Host ('  Rules       : {0}' -f $s.RuleCount)

    Write-Host ''
    Write-Host '  Firewall profiles' -ForegroundColor Cyan
    $s.Profiles | ForEach-Object {
        Write-Host ('    {0,-8} enabled={1,-5} outbound={2,-14} inbound={3}' -f `
            $_.Name, $_.Enabled, $_.DefaultOutboundAction, $_.DefaultInboundAction)
    }

    Write-Host ''
    Write-Host '  Tunnel adapters (allow-listed)' -ForegroundColor Cyan
    if ($s.Tunnels.Count -eq 0) {
        Write-Host '    (none configured - run: Rvpn.ps1 detect)' -ForegroundColor Yellow
    }
    $s.Tunnels | ForEach-Object {
        $route = if ($_.HasDefaultRoute) { 'default-route' } else { 'no-route' }
        $ip    = if ($_.IPv4Addresses.Count -gt 0) { $_.IPv4Addresses -join ',' } else { '-' }
        Write-Host ('    {0,-32} {1,-12} {2,-16} {3}' -f $_.Alias, $_.Status, $ip, $route)
    }

    Write-Host ''
    Write-Host ('  Config: {0}' -f $s.ConfigPath) -ForegroundColor DarkGray
    Write-Host ('  Log   : {0}' -f $s.LogPath) -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Detect {
    Write-Banner -Text 'Tunnel adapter candidates on this machine'
    $candidates = @(Get-RvCandidateTunnelAdapter)
    if ($candidates.Count -eq 0) {
        Write-Host '  No VPN-like adapters found. Is the VPN client installed?' -ForegroundColor Yellow
        return
    }
    $candidates | Format-Table Name, Status, InterfaceDescription -AutoSize | Out-String -Width 160 | Write-Host

    $cfg     = Get-RvConfig
    $current = @($cfg.TunnelInterfaceAliases)
    Write-Host '  Currently allow-listed:' -ForegroundColor Cyan
    if ($current.Count -eq 0) { Write-Host '    (none)' -ForegroundColor Yellow }
    $current | ForEach-Object { Write-Host "    $_" }
    Write-Host ''
    Write-Host '  Edit config.json to change the allow-list, or use the GUI.' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Verify {
    Write-Banner -Text 'Rule integrity check'
    $results = @(Test-RvRuleIntegrity)
    foreach ($r in $results) {
        if     ($r.Passed) { $mark = '[ OK ]'; $color = 'Green' }
        elseif ($r.Fatal)  { $mark = '[FAIL]'; $color = 'Red' }
        else               { $mark = '[WARN]'; $color = 'Yellow' }
        Write-Host ('  {0} {1}' -f $mark, $r.Check) -ForegroundColor $color
        Write-Host ('         {0}' -f $r.Detail) -ForegroundColor DarkGray
    }

    $fatal = @($results | Where-Object { $_.Fatal -and -not $_.Passed }).Count
    $warn  = @($results | Where-Object { -not $_.Fatal -and -not $_.Passed }).Count
    Write-Host ''
    if ($fatal -gt 0) {
        Write-Host "  $fatal critical check(s) failed - do not rely on this configuration." -ForegroundColor Red
    } elseif ($warn -gt 0) {
        Write-Host "  All critical checks passed ($warn warning(s))." -ForegroundColor Yellow
    } else {
        Write-Host '  All checks passed.' -ForegroundColor Green
    }
    Write-Host ''
}

function Confirm-Action {
    param([string]$Question)
    if ($Force) { return $true }
    Write-Host ''
    $answer = Read-Host "$Question [y/N]"
    return ($answer -match '^(y|yes)$')
}

try {
    switch ($Action) {

        'status' { Show-Status }

        'detect' { Show-Detect }

        'verify' { Show-Verify }

        'enable' {
            Assert-RvAdmin
            $cfg     = Get-RvConfig
            $aliases = @($cfg.TunnelInterfaceAliases)

            Write-Banner -Text 'Arming the kill switch' -Color Yellow
            Write-Host ''
            Write-Host '  After this, the ONLY way out of this machine is:' -ForegroundColor Yellow
            $aliases | ForEach-Object { Write-Host "    - the tunnel adapter '$_'" }
            Write-Host '    - the VPN client reaching its server'
            if ($cfg.AllowDhcp) { Write-Host '    - DHCP' }
            if ($cfg.AllowLan)  { Write-Host '    - your local network' }
            Write-Host ''
            Write-Host '  If the VPN drops, this machine has no internet. That is the point.' -ForegroundColor Yellow
            Write-Host '  To undo: run  Rvpn.ps1 disable   (or Recover.cmd if anything goes wrong).' -ForegroundColor DarkGray

            if (-not (Confirm-Action -Question 'Arm the kill switch now?')) {
                Write-Host 'Cancelled.' -ForegroundColor DarkGray
                return
            }
            Enable-RvKillSwitch -Config $cfg
            Show-Verify
            Show-Status
        }

        'disable' {
            Assert-RvAdmin
            Write-Banner -Text 'Disarming the kill switch' -Color Yellow
            Write-Host ''
            Write-Host '  Your traffic will no longer be forced through the VPN.' -ForegroundColor Yellow
            if (-not (Confirm-Action -Question 'Disarm the kill switch?')) {
                Write-Host 'Cancelled.' -ForegroundColor DarkGray
                return
            }
            Disable-RvKillSwitch
            Show-Status
        }

        'recover' {
            Assert-RvAdmin
            Write-Banner -Text 'Emergency recovery' -Color Red
            Write-Host ''
            Write-Host '  Forces outbound back to Allow and removes all RestrictVPN rules.' -ForegroundColor Yellow
            if (-not (Confirm-Action -Question 'Run emergency recovery?')) {
                Write-Host 'Cancelled.' -ForegroundColor DarkGray
                return
            }
            Reset-RvFirewall
            Show-Status
        }

        'config' {
            $path = Get-RvConfigPath
            Get-RvConfig | Out-Null   # create it if missing
            Write-Host "Opening $path" -ForegroundColor Cyan
            Start-Process notepad.exe -ArgumentList $path
        }

        'log' {
            $path = Get-RvLogPath
            if (Test-Path $path) { Get-Content $path -Tail 60 }
            else { Write-Host 'No log yet.' -ForegroundColor DarkGray }
        }

        'help' {
            Write-Banner -Text 'RestrictVPN'
            Write-Host @'

  Rvpn.ps1 status    Show kill switch state, tunnel state and firewall policy
  Rvpn.ps1 detect    List VPN-like adapters and the current allow-list
  Rvpn.ps1 enable    Arm the kill switch (default-deny outbound)
  Rvpn.ps1 disable   Disarm and restore the previous firewall policy
  Rvpn.ps1 verify    Check that the live rules bound to the right adapters
  Rvpn.ps1 recover   Emergency restore of internet access
  Rvpn.ps1 config    Open config.json
  Rvpn.ps1 log       Tail the activity log

  Add -Force to skip confirmation prompts.

'@
        }
    }
}
catch {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    Write-Host 'If you have lost internet access, run Recover.cmd as Administrator.' -ForegroundColor Yellow
    exit 1
}
