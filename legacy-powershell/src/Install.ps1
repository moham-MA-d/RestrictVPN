<#
    .SYNOPSIS
    Optional integration: desktop shortcut plus a scheduled task that arms the
    kill switch at boot, so the machine is never briefly exposed after a
    restart or crash.

    .PARAMETER Remove
    Undo everything this script created.
#>
[CmdletBinding()]
param(
    [switch]$ArmAtBoot,
    [switch]$Shortcut,
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'RestrictVpn.psm1') -Force
Assert-RvAdmin

$Root      = Split-Path -Parent $PSScriptRoot
$TaskName  = 'RestrictVPN - Arm kill switch at boot'
$CliScript = Join-Path $PSScriptRoot 'Rvpn.ps1'

function Remove-BootTask {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-RvLog -Message 'Removed boot task.' -Level 'OK'
    } else {
        Write-Host 'No boot task installed.' -ForegroundColor DarkGray
    }
}

function Install-BootTask {
    Remove-BootTask

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" enable -Force' -f $CliScript)

    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5))

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description 'Re-applies the RestrictVPN kill switch at every boot so the machine is never exposed before the VPN connects.' | Out-Null

    Write-RvLog -Message 'Installed boot task: kill switch will arm at every startup.' -Level 'OK'
}

function Remove-Shortcut {
    $path = Join-Path ([Environment]::GetFolderPath('Desktop')) 'RestrictVPN.lnk'
    if (Test-Path $path) {
        Remove-Item $path -Force
        Write-Host 'Removed desktop shortcut.' -ForegroundColor Green
    } else {
        Write-Host 'No desktop shortcut found.' -ForegroundColor DarkGray
    }
}

function Install-Shortcut {
    $target = Join-Path $Root 'RestrictVPN.cmd'
    $path   = Join-Path ([Environment]::GetFolderPath('Desktop')) 'RestrictVPN.lnk'

    $shell = New-Object -ComObject WScript.Shell
    $lnk   = $shell.CreateShortcut($path)
    $lnk.TargetPath       = $target
    $lnk.WorkingDirectory = $Root
    $lnk.Description      = 'RestrictVPN kill switch'
    $lnk.IconLocation     = "$env:SystemRoot\System32\SecurityHealthSystray.exe,0"
    $lnk.Save()

    Write-Host "Created desktop shortcut: $path" -ForegroundColor Green
}

if ($Remove) {
    Remove-BootTask
    Remove-Shortcut
    Write-Host ''
    Write-Host 'Note: this did NOT disarm the kill switch. Run Rvpn.ps1 disable for that.' -ForegroundColor Yellow
    return
}

# With no switches, do both - that is what someone running "install" expects.
if (-not $ArmAtBoot -and -not $Shortcut) { $ArmAtBoot = $true; $Shortcut = $true }

if ($Shortcut)  { Install-Shortcut }
if ($ArmAtBoot) {
    Write-Host ''
    Write-Host 'Arm-at-boot means: after every restart this PC has NO internet until' -ForegroundColor Yellow
    Write-Host 'the VPN connects. That is the strongest setting, and the one you asked for.' -ForegroundColor Yellow
    Install-BootTask
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
