<#
    RestrictVPN - emergency recovery.

    Deliberately standalone: it does not load RestrictVPN.exe or any module, so
    it still works if the app itself will not start. This is the escape hatch.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Requesting administrator rights...' -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
        )
    }
    catch {
        Write-Host 'Administrator approval was declined. Cannot restore the firewall.' -ForegroundColor Red
        Start-Sleep -Seconds 4
    }
    exit
}

Write-Host ''
Write-Host '  RestrictVPN - Emergency Recovery' -ForegroundColor Cyan
Write-Host '  --------------------------------' -ForegroundColor Cyan
Write-Host ''

try {
    Write-Host '  Restoring outbound traffic to Allow...'
    Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Allow -DefaultInboundAction Block

    foreach ($group in 'RestrictVPN Kill Switch', 'RestrictVPN Self Test') {
        $rules = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
        if ($rules.Count -gt 0) {
            Write-Host ("  Removing {0} rule(s) from '{1}'..." -f $rules.Count, $group)
            $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }
    }

    # Split tunnel routes are the other thing this app installs. They are added
    # non-persistent, so a reboot clears them anyway - but a stale route pointing
    # at a gateway that is no longer there would look exactly like "still broken".
    $split = Join-Path $PSScriptRoot 'state\splittunnel.json'
    if (Test-Path $split) {
        try {
            $data = Get-Content $split -Raw | ConvertFrom-Json
            foreach ($route in @($data.Routes)) {
                if (-not $route.Cidr) { continue }
                $family = 'ipv4'
                if ($route.IsV6) { $family = 'ipv6' }
                Write-Host ("  Removing split tunnel route {0}..." -f $route.Cidr)
                & netsh.exe interface $family delete route "prefix=$($route.Cidr)" `
                    "interface=$($route.IfIndex)" "nexthop=$($route.Gateway)" store=active | Out-Null
            }
        }
        catch {
            Write-Host '  (splittunnel.json could not be read; a reboot clears the routes)' -ForegroundColor DarkGray
        }
        Remove-Item $split -Force -ErrorAction SilentlyContinue
    }

    $state = Join-Path $PSScriptRoot 'state\state.json'
    if (Test-Path $state) { Remove-Item $state -Force -ErrorAction SilentlyContinue }

    Write-Host ''
    Write-Host '  Internet access restored.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  If something is still broken, the last resort is:' -ForegroundColor DarkGray
    Write-Host '      netsh advfirewall reset' -ForegroundColor DarkGray
    Write-Host '  (that wipes ALL firewall rules, including other software''s)' -ForegroundColor DarkGray
}
catch {
    Write-Host ''
    Write-Host ("  FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host ''
    Write-Host '  Run this manually from an elevated PowerShell:' -ForegroundColor Yellow
    Write-Host '      Set-NetFirewallProfile -All -DefaultOutboundAction Allow' -ForegroundColor Yellow
}

Write-Host ''
Read-Host '  Press Enter to close'
