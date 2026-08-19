# RestrictVpn.psm1 - Core engine for the RestrictVPN kill switch.
#
# Fail-closed Windows Firewall policy: default-deny outbound on every profile,
# with a narrow allow-list for the VPN tunnel adapter(s) and the VPN client.
# If the tunnel drops, nothing has a permitted path out, so nothing leaks.
#
# ASCII only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Root       = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$script:ConfigPath = Join-Path $script:Root 'config.json'
$script:StatePath  = Join-Path $script:Root 'state\state.json'
$script:LogPath    = Join-Path $script:Root 'logs\restrictvpn.log'
$script:RuleGroup  = 'RestrictVPN Kill Switch'
$script:RulePrefix = 'RestrictVPN'

# Interface descriptions that identify a VPN tunnel adapter rather than a real NIC.
$script:TunnelDescriptionPatterns = @(
    'TAP-Windows Adapter*'
    '*Wintun*'
    'OpenVPN Data Channel Offload*'
    '*OpenVPN*'
    '*WireGuard*'
)

# Folders searched for VPN client executables when generating the first config.
$script:VpnProgramSearchPaths = @(
    "$env:ProgramFiles\OpenVPN Connect"
    "${env:ProgramFiles(x86)}\OpenVPN Connect"
    "$env:ProgramFiles\OpenVPN\bin"
    "${env:ProgramFiles(x86)}\OpenVPN\bin"
    "$env:LOCALAPPDATA\Programs\OpenVPN Connect"
)

#region ------------------------------------------------------------- utilities

function Write-RvLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        $dir = Split-Path -Parent $script:LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
    } catch { }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line -ForegroundColor Gray }
    }
}

function Test-RvAdmin {
    [CmdletBinding()]
    param()
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RvAdmin {
    [CmdletBinding()]
    param()
    if (-not (Test-RvAdmin)) {
        throw 'Administrator rights are required. Launch RestrictVPN.cmd, or re-run from an elevated prompt.'
    }
}

# PowerShell 5.1 has no ConvertFrom-Json -AsHashtable, so convert by hand.
function ConvertTo-RvHashtable {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject }
    $h = @{}
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

# Normalize scalar / array / null into a clean string array.
function ConvertTo-RvStringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_.Trim() -ne '' })
}

#endregion

#region ---------------------------------------------------------- adapter info

function Get-RvCandidateTunnelAdapter {
    <#
        .SYNOPSIS
        Every adapter on this machine that looks like a VPN tunnel interface.
    #>
    [CmdletBinding()]
    param()

    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)
    foreach ($a in $adapters) {
        # WAN Miniport pseudo-adapters are never a tunnel we can pin rules to.
        if ($a.InterfaceDescription -like 'WAN Miniport*') { continue }

        $isTunnel = $false
        foreach ($pattern in $script:TunnelDescriptionPatterns) {
            if ($a.InterfaceDescription -like $pattern) { $isTunnel = $true; break }
        }
        if (-not $isTunnel) { continue }

        [pscustomobject]@{
            Name                 = [string]$a.Name
            InterfaceDescription = [string]$a.InterfaceDescription
            Status               = [string]$a.Status
            InterfaceIndex       = [int]$a.InterfaceIndex
        }
    }
}

function Get-RvTunnelStatus {
    <#
        .SYNOPSIS
        Live state of the configured tunnel adapters: present, up, addressed,
        and - the part that actually matters - owning a default route.
    #>
    [CmdletBinding()]
    param([string[]]$Alias)

    $result = foreach ($name in $Alias) {
        $adapter  = Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue
        $ips      = @()
        $hasRoute = $false

        if ($adapter) {
            $ips = @(Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     Where-Object { $_.IPAddress -notlike '169.254.*' } |
                     Select-Object -ExpandProperty IPAddress)

            # An adapter can sit "Up" with a stale address long after the tunnel
            # died. Only a default route proves it is carrying traffic.
            $defaultPrefixes = @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0')
            $routes = @(Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue |
                        Where-Object { $defaultPrefixes -contains $_.DestinationPrefix })
            $hasRoute = $routes.Count -gt 0
        }

        [pscustomobject]@{
            Alias           = $name
            Present         = [bool]$adapter
            Status          = if ($adapter) { [string]$adapter.Status } else { 'Not Present' }
            IPv4Addresses   = $ips
            HasDefaultRoute = $hasRoute
        }
    }
    return @($result)
}

#endregion

#region ---------------------------------------------------------------- config

function New-RvDefaultConfig {
    [CmdletBinding()]
    param()

    $tunnels = @(Get-RvCandidateTunnelAdapter |
                 Where-Object { $_.Status -ne 'Not Present' } |
                 Select-Object -ExpandProperty Name)

    $programs = @()
    foreach ($dir in $script:VpnProgramSearchPaths) {
        if (Test-Path $dir) {
            $programs += @(Get-ChildItem -Path $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty FullName)
        }
    }

    return [ordered]@{
        '_comment'                   = 'RestrictVPN config. TunnelInterfaceAliases is the allow-list of adapters traffic may leave through. While the kill switch is on, every other outbound path is blocked.'
        TunnelInterfaceAliases       = @($tunnels)
        VpnClientPrograms            = @($programs | Sort-Object -Unique)
        VpnServerEndpoints           = @()
        AllowLan                     = $false
        AllowDhcp                    = $true
        AllowVpnClientDns            = $true
        ExtraAllowedInterfaceAliases = @()
        AllowedPrograms              = @()
        BlockInbound                 = $true
    }
}

function Get-RvConfig {
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:ConfigPath)) {
        $cfg = New-RvDefaultConfig
        Save-RvConfig -Config $cfg
        Write-RvLog -Message "Created default config at $script:ConfigPath" -Level 'INFO'
        return $cfg
    }

    $raw = Get-Content -Path $script:ConfigPath -Raw -Encoding UTF8
    $cfg = ConvertTo-RvHashtable (ConvertFrom-Json $raw)

    # Backfill anything a hand-edited or older config is missing.
    $defaults = New-RvDefaultConfig
    foreach ($key in $defaults.Keys) {
        if (-not $cfg.ContainsKey($key)) { $cfg[$key] = $defaults[$key] }
    }
    return $cfg
}

function Save-RvConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)

    $dir = Split-Path -Parent $script:ConfigPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ($Config | ConvertTo-Json -Depth 6) | Set-Content -Path $script:ConfigPath -Encoding UTF8
}

function Get-RvConfigPath { return $script:ConfigPath }
function Get-RvLogPath    { return $script:LogPath }

#endregion

#region ----------------------------------------------------------------- state

function Save-RvPreviousPolicy {
    [CmdletBinding()]
    param()

    # Capture the pre-kill-switch policy exactly once, so a repeated Enable
    # cannot overwrite the real "before" snapshot with our own Block policy.
    if (Test-Path $script:StatePath) { return }

    $snapshot = @{
        CapturedAt = (Get-Date -Format 'o')
        Profiles   = @()
    }
    foreach ($p in Get-NetFirewallProfile -All) {
        $snapshot.Profiles += @{
            Name                  = [string]$p.Name
            Enabled               = [string]$p.Enabled
            DefaultInboundAction  = [string]$p.DefaultInboundAction
            DefaultOutboundAction = [string]$p.DefaultOutboundAction
        }
    }

    $dir = Split-Path -Parent $script:StatePath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ($snapshot | ConvertTo-Json -Depth 5) | Set-Content -Path $script:StatePath -Encoding UTF8
    Write-RvLog -Message 'Saved pre-kill-switch firewall policy snapshot.' -Level 'INFO'
}

function Restore-RvPreviousPolicy {
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:StatePath)) {
        Write-RvLog -Message 'No snapshot found; restoring Windows defaults (outbound Allow, inbound Block).' -Level 'WARN'
        Set-NetFirewallProfile -All -DefaultOutboundAction Allow -DefaultInboundAction Block
        return
    }

    $snapshot = ConvertFrom-Json (Get-Content -Path $script:StatePath -Raw -Encoding UTF8)
    foreach ($p in $snapshot.Profiles) {
        # Enabled is restored too: arming force-enables the firewall, and
        # disarming should leave the machine exactly as it was found.
        Set-NetFirewallProfile -Name $p.Name `
            -Enabled               $p.Enabled `
            -DefaultInboundAction  $p.DefaultInboundAction `
            -DefaultOutboundAction $p.DefaultOutboundAction
    }
    Remove-Item -Path $script:StatePath -Force -ErrorAction SilentlyContinue
    Write-RvLog -Message 'Restored previous firewall policy from snapshot.' -Level 'OK'
}

#endregion

#region ----------------------------------------------------------------- rules

function Remove-RvRule {
    [CmdletBinding()]
    param()
    $existing = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        $existing | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-RvLog -Message "Removed $($existing.Count) existing RestrictVPN rule(s)." -Level 'INFO'
    }
}

function New-RvRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Parameters
    )
    $splat = @{
        DisplayName = "$script:RulePrefix - $Name"
        Group       = $script:RuleGroup
        Profile     = 'Any'
        Enabled     = 'True'
    }
    foreach ($k in $Parameters.Keys) { $splat[$k] = $Parameters[$k] }

    New-NetFirewallRule @splat | Out-Null
    Write-RvLog -Message "Rule created: $Name" -Level 'INFO'
}

function Build-RvRuleSet {
    <#
        .SYNOPSIS
        Create the full allow-list. Called while the firewall is still
        permissive, so a failure here leaves the machine online, not bricked.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)

    $tunnelAliases = ConvertTo-RvStringArray $Config.TunnelInterfaceAliases
    if ($tunnelAliases.Count -eq 0) {
        throw 'No tunnel adapters configured. Run "detect" or set TunnelInterfaceAliases in config.json - otherwise the kill switch would block the VPN itself.'
    }

    $extraAliases = ConvertTo-RvStringArray $Config.ExtraAllowedInterfaceAliases
    $allAliases   = @(@($tunnelAliases) + @($extraAliases) | Select-Object -Unique)

    # 1. The tunnel itself: anything egressing via the VPN adapter is fine.
    New-RvRule -Name 'Allow VPN Tunnel (outbound)' -Parameters @{
        Direction      = 'Outbound'
        Action         = 'Allow'
        InterfaceAlias = $allAliases
        Description    = 'Permit all outbound traffic that leaves through the VPN tunnel adapter(s).'
    }
    New-RvRule -Name 'Allow VPN Tunnel (inbound)' -Parameters @{
        Direction      = 'Inbound'
        Action         = 'Allow'
        InterfaceAlias = $allAliases
        Description    = 'Permit inbound traffic arriving on the VPN tunnel adapter(s).'
    }

    # 2. The VPN client must still reach the server over the physical NIC,
    #    otherwise the tunnel could never come back up after a drop.
    $programs  = ConvertTo-RvStringArray $Config.VpnClientPrograms
    $endpoints = ConvertTo-RvStringArray $Config.VpnServerEndpoints
    foreach ($exe in $programs) {
        if (-not (Test-Path $exe)) {
            Write-RvLog -Message "VPN client program not found, skipping: $exe" -Level 'WARN'
            continue
        }
        $params = @{
            Direction   = 'Outbound'
            Action      = 'Allow'
            Program     = $exe
            Description = 'Permit the VPN client to reach the VPN server so the tunnel can be established.'
        }
        if ($endpoints.Count -gt 0) { $params['RemoteAddress'] = $endpoints }
        New-RvRule -Name "Allow VPN client $(Split-Path -Leaf $exe)" -Parameters $params
    }

    # 3. DHCP. Without it the physical NIC never gets a lease and nothing works.
    if ($Config.AllowDhcp) {
        New-RvRule -Name 'Allow DHCP (IPv4)' -Parameters @{
            Direction   = 'Outbound'
            Action      = 'Allow'
            Protocol    = 'UDP'
            LocalPort   = '68'
            RemotePort  = '67'
            Description = 'Permit DHCPv4 so the physical adapter can obtain a lease.'
        }
        New-RvRule -Name 'Allow DHCP (IPv6)' -Parameters @{
            Direction   = 'Outbound'
            Action      = 'Allow'
            Protocol    = 'UDP'
            LocalPort   = '546'
            RemotePort  = '547'
            Description = 'Permit DHCPv6 so the physical adapter can obtain a lease.'
        }
    }

    # 4. Optional: let the VPN client resolve its server hostname. This is the
    #    single deliberate plaintext DNS query allowed outside the tunnel, and
    #    it is unnecessary when the server is pinned to literal IPs.
    if ($Config.AllowVpnClientDns -and $endpoints.Count -eq 0) {
        foreach ($exe in $programs) {
            if (-not (Test-Path $exe)) { continue }
            New-RvRule -Name "Allow DNS for $(Split-Path -Leaf $exe)" -Parameters @{
                Direction   = 'Outbound'
                Action      = 'Allow'
                Program     = $exe
                Protocol    = 'UDP'
                RemotePort  = '53'
                Description = 'Permit the VPN client to resolve the VPN server hostname.'
            }
        }
    }

    # 5. Optional LAN access (printers, NAS). Off by default: it reopens DNS to
    #    your router, which hands your browsing back to the ISP.
    if ($Config.AllowLan) {
        New-RvRule -Name 'Allow LAN (outbound)' -Parameters @{
            Direction     = 'Outbound'
            Action        = 'Allow'
            RemoteAddress = @('LocalSubnet', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '224.0.0.0/4', '255.255.255.255')
            Description   = 'Permit local network traffic (printers, NAS, router admin).'
        }
    }

    # 6. Escape hatch for specific apps the user trusts outside the tunnel.
    foreach ($exe in (ConvertTo-RvStringArray $Config.AllowedPrograms)) {
        if (-not (Test-Path $exe)) {
            Write-RvLog -Message "Allowed program not found, skipping: $exe" -Level 'WARN'
            continue
        }
        New-RvRule -Name "Allow program $(Split-Path -Leaf $exe)" -Parameters @{
            Direction   = 'Outbound'
            Action      = 'Allow'
            Program     = $exe
            Description = 'User-approved program permitted outside the tunnel.'
        }
    }
}

#endregion

#region -------------------------------------------------------------- commands

function Enable-RvKillSwitch {
    [CmdletBinding()]
    param($Config)

    Assert-RvAdmin
    if (-not $Config) { $Config = Get-RvConfig }

    Write-RvLog -Message '=== Enabling kill switch ===' -Level 'INFO'
    Save-RvPreviousPolicy

    # Build allow rules BEFORE flipping to default-deny. If rule creation throws,
    # the machine stays online and the user can fix the config.
    Remove-RvRule
    Build-RvRuleSet -Config $Config

    # Preflight: read the rules back and confirm the tunnel allow-list actually
    # bound to real adapters. Without this check a mistyped or renamed adapter
    # would produce a rule that matches nothing, and flipping to default-deny
    # below would take the machine offline with no way back except Recover.cmd.
    $failed = @(Test-RvRuleIntegrity -Config $Config | Where-Object { $_.Fatal -and -not $_.Passed })
    if ($failed.Count -gt 0) {
        Remove-RvRule
        $detail = ($failed | ForEach-Object { "$($_.Check): $($_.Detail)" }) -join '; '
        Write-RvLog -Message "Preflight failed, aborting without touching firewall policy. $detail" -Level 'ERROR'
        throw "Preflight check failed, so the kill switch was NOT armed and your internet is untouched. $detail"
    }

    $inbound = if ($Config.BlockInbound) { 'Block' } else { 'NotConfigured' }
    Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block -DefaultInboundAction $inbound

    Write-RvLog -Message 'Kill switch ENABLED. All outbound traffic now requires the VPN tunnel.' -Level 'OK'
}

function Disable-RvKillSwitch {
    [CmdletBinding()]
    param()

    Assert-RvAdmin
    Write-RvLog -Message '=== Disabling kill switch ===' -Level 'INFO'

    Restore-RvPreviousPolicy
    Remove-RvRule

    Write-RvLog -Message 'Kill switch DISABLED. Normal (unprotected) internet access restored.' -Level 'OK'
}

function Reset-RvFirewall {
    <#
        .SYNOPSIS
        Emergency recovery. Unconditionally restores outbound access and drops
        our rules, without trusting the snapshot file to be valid.
    #>
    [CmdletBinding()]
    param()

    Assert-RvAdmin
    Write-RvLog -Message '=== EMERGENCY RECOVERY ===' -Level 'WARN'
    Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Allow -DefaultInboundAction Block
    Remove-RvRule
    Remove-Item -Path $script:StatePath -Force -ErrorAction SilentlyContinue
    Write-RvLog -Message 'Outbound access forced back to Allow and RestrictVPN rules removed.' -Level 'OK'
}

function Get-RvStatus {
    [CmdletBinding()]
    param($Config)

    if (-not $Config) { $Config = Get-RvConfig }

    $profiles = @(Get-NetFirewallProfile -All | ForEach-Object {
        [pscustomobject]@{
            Name                  = [string]$_.Name
            Enabled               = [bool]$_.Enabled
            DefaultInboundAction  = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
        }
    })

    $rules      = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue)
    $allBlocked = ($profiles.Count -gt 0) -and
                  (@($profiles | Where-Object { $_.DefaultOutboundAction -ne 'Block' }).Count -eq 0)
    $enabled    = $allBlocked -and ($rules.Count -gt 0)

    $tunnels = Get-RvTunnelStatus -Alias (ConvertTo-RvStringArray $Config.TunnelInterfaceAliases)
    $vpnUp   = @($tunnels | Where-Object { $_.HasDefaultRoute }).Count -gt 0

    $verdict =
        if     ($enabled -and $vpnUp) { 'PROTECTED - VPN up, kill switch armed' }
        elseif ($enabled)             { 'BLOCKED - VPN down, kill switch armed (no internet, as intended)' }
        elseif ($vpnUp)               { 'AT RISK - VPN up but kill switch is OFF (traffic leaks if the VPN drops)' }
        else                          { 'UNPROTECTED - VPN down and kill switch OFF' }

    return [pscustomobject]@{
        KillSwitchEnabled = $enabled
        VpnTunnelActive   = $vpnUp
        Verdict           = $verdict
        Profiles          = $profiles
        RuleCount         = $rules.Count
        Rules             = @($rules | Select-Object -ExpandProperty DisplayName)
        Tunnels           = $tunnels
        ConfigPath        = $script:ConfigPath
        LogPath           = $script:LogPath
    }
}

function Test-RvRuleIntegrity {
    <#
        .SYNOPSIS
        Read the live rules back out of Windows Firewall and confirm the
        interface filters really bound to the adapters we asked for. Guards
        against a silently empty allow-list, which would mean no internet at all.
    #>
    [CmdletBinding()]
    param($Config)

    if (-not $Config) { $Config = Get-RvConfig }
    $expected = @(@(ConvertTo-RvStringArray $Config.TunnelInterfaceAliases) +
                  @(ConvertTo-RvStringArray $Config.ExtraAllowedInterfaceAliases) |
                  Select-Object -Unique)

    $results = @()
    $rule = @(Get-NetFirewallRule -Group $script:RuleGroup -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName -like '*Allow VPN Tunnel (outbound)*' })

    if ($rule.Count -eq 0) {
        return @([pscustomobject]@{
            Check  = 'Tunnel allow rule exists'
            Passed = $false
            Fatal  = $true
            Detail = 'Rule not found - the kill switch is not armed.'
        })
    }
    $results += [pscustomobject]@{
        Check = 'Tunnel allow rule exists'; Passed = $true; Fatal = $true; Detail = $rule[0].DisplayName
    }

    # Fatal: if the interface filter did not bind, the "allow the tunnel" rule
    # matches nothing, and switching to default-deny would kill all traffic.
    $bound = @($rule[0] | Get-NetFirewallInterfaceFilter | Select-Object -ExpandProperty InterfaceAlias)
    foreach ($alias in $expected) {
        $ok = $bound -contains $alias
        $results += [pscustomobject]@{
            Check  = "Interface filter bound: $alias"
            Passed = $ok
            Fatal  = $true
            Detail = if ($ok) { 'Bound' } else { "NOT bound. Live filters: $($bound -join ', ')" }
        }
    }

    # Non-fatal: a missing client binary only means that one path was skipped.
    foreach ($exe in (ConvertTo-RvStringArray $Config.VpnClientPrograms)) {
        $results += [pscustomobject]@{
            Check  = "VPN client present: $(Split-Path -Leaf $exe)"
            Passed = (Test-Path $exe)
            Fatal  = $false
            Detail = $exe
        }
    }
    return $results
}

#endregion

Export-ModuleMember -Function @(
    'Write-RvLog', 'Test-RvAdmin', 'Assert-RvAdmin'
    'Get-RvConfig', 'Save-RvConfig', 'New-RvDefaultConfig', 'Get-RvConfigPath', 'Get-RvLogPath'
    'Get-RvCandidateTunnelAdapter', 'Get-RvTunnelStatus'
    'Enable-RvKillSwitch', 'Disable-RvKillSwitch', 'Reset-RvFirewall'
    'Get-RvStatus', 'Test-RvRuleIntegrity', 'Remove-RvRule'
)
