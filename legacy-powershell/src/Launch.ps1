<#
    .SYNOPSIS
    Elevation shim. Re-launches itself as Administrator, then hands off to the
    requested entry point. Everything RestrictVPN does needs admin rights.
#>
[CmdletBinding()]
param(
    [ValidateSet('Gui', 'Cli', 'Recover', 'Install', 'Uninstall')]
    [string]$Target = 'Gui',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest = @()
)

$ErrorActionPreference = 'Stop'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$elevated  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $elevated) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Target', $Target)
    if ($Rest.Count -gt 0) { $argList += $Rest }

    # The GUI draws its own window, so the relaunched console can stay hidden.
    $style = if ($Target -eq 'Gui') { 'Hidden' } else { 'Normal' }

    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle $style -ArgumentList $argList
    }
    catch {
        Write-Host 'Administrator approval was declined. RestrictVPN cannot change firewall rules without it.' -ForegroundColor Red
        Start-Sleep -Seconds 4
        exit 1
    }
    exit 0
}

switch ($Target) {
    'Gui'     { & (Join-Path $PSScriptRoot 'Gui.ps1') }
    'Cli'     { & (Join-Path $PSScriptRoot 'Rvpn.ps1') @Rest;  Write-Host ''; Read-Host 'Press Enter to close' }
    'Recover' { & (Join-Path $PSScriptRoot 'Rvpn.ps1') recover -Force; Write-Host ''; Read-Host 'Press Enter to close' }
    'Install' { & (Join-Path $PSScriptRoot 'Install.ps1') @Rest; Write-Host ''; Read-Host 'Press Enter to close' }
    'Uninstall' {
        & (Join-Path $PSScriptRoot 'Install.ps1') -Remove
        Write-Host ''; Read-Host 'Press Enter to close'
    }
}
