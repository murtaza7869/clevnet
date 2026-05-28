<#
.SYNOPSIS
    Reports the last 5 digits of the installed MS Office 2024 product key.

.DESCRIPTION
    Uses ospp.vbs (Office Software Protection Platform) to extract the partial
    product key, license status, and license name. Useful for identifying which
    volume license key is in use on a given machine.

.NOTES
    - Must be run as Administrator (or via RMM in SYSTEM context)
    - Works with Office 2024 Volume License (MAK/KMS) and Retail
    - ospp.vbs lives in the Office program folder; script auto-detects 32/64-bit
#>

# ── Configuration ─────────────────────────────────────────────────────────────
$OutputToFile = $false          # Set to $true to write a CSV log
$OutputPath   = "C:\Temp\OfficeKeyAudit.csv"
# ──────────────────────────────────────────────────────────────────────────────

function Get-OfficePath {
    $candidates = @(
        "${env:ProgramFiles}\Microsoft Office\Office16",
        "${env:ProgramFiles(x86)}\Microsoft Office\Office16",
        "${env:ProgramFiles}\Microsoft Office\root\Office16",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16"
    )
    foreach ($path in $candidates) {
        if (Test-Path "$path\ospp.vbs") {
            return $path
        }
    }
    return $null
}

function Get-OfficeKeyInfo {
    $officePath = Get-OfficePath

    if (-not $officePath) {
        Write-Warning "Could not locate ospp.vbs. Is Office 2024 installed?"
        return $null
    }

    Write-Host "Found Office installation at: $officePath" -ForegroundColor Cyan

    # Run ospp.vbs /dstatus and capture output
    $rawOutput = & cscript.exe //NoLogo "$officePath\ospp.vbs" /dstatus 2>&1

    $results   = @()
    $current   = @{}

    foreach ($line in $rawOutput) {
        $line = $line.Trim()

        # Each product block starts with a NAME line
        if ($line -match "^-+$") {
            # Separator — save previous block if it had data
            if ($current.Keys.Count -gt 0) {
                $results += [PSCustomObject]$current
                $current  = @{}
            }
        }
        elseif ($line -match "^LICENSE NAME:\s*(.+)$") {
            $current["LicenseName"] = $matches[1].Trim()
        }
        elseif ($line -match "^LICENSE DESCRIPTION:\s*(.+)$") {
            $current["LicenseDescription"] = $matches[1].Trim()
        }
        elseif ($line -match "^PRODUCT ID:\s*(.+)$") {
            $current["ProductID"] = $matches[1].Trim()
        }
        elseif ($line -match "Last 5 characters of installed product key:\s*(.{5})") {
            $current["Last5"] = $matches[1].Trim()
        }
        elseif ($line -match "^LICENSE STATUS:\s*(.+)$") {
            $current["LicenseStatus"] = $matches[1].Trim()
        }
    }

    # Capture final block
    if ($current.Keys.Count -gt 0) {
        $results += [PSCustomObject]$current
    }

    return $results
}

# ── Main ──────────────────────────────────────────────────────────────────────

$computerName = $env:COMPUTERNAME
$timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Office 2024 License Key Audit"         -ForegroundColor Yellow
Write-Host "  Computer : $computerName"              -ForegroundColor Yellow
Write-Host "  Time     : $timestamp"                 -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

$keyInfo = Get-OfficeKeyInfo

if ($keyInfo) {
    # Filter to Office 2024 entries only (skip non-Office / runtime components)
    $officeEntries = $keyInfo | Where-Object {
        $_.LicenseName -match "2024" -or $_.LicenseDescription -match "2024"
    }

    if (-not $officeEntries) {
        Write-Warning "ospp.vbs ran but no Office 2024 license entries were found."
        Write-Host "All detected entries:" -ForegroundColor Gray
        $keyInfo | Format-Table -AutoSize
    }
    else {
        foreach ($entry in $officeEntries) {
            Write-Host "Product      : $($entry.LicenseName)"        -ForegroundColor Green
            Write-Host "Description  : $($entry.LicenseDescription)"
            Write-Host "Last 5 of Key: " -NoNewline
            Write-Host "$($entry.Last5)" -ForegroundColor Cyan
            Write-Host "Status       : $($entry.LicenseStatus)"
            Write-Host ""
        }

        # Add computer name + timestamp for CSV export
        $exportData = $officeEntries | Select-Object @{N="ComputerName";E={$computerName}},
                                                     @{N="Timestamp";   E={$timestamp}},
                                                     LicenseName,
                                                     Last5,
                                                     LicenseStatus,
                                                     LicenseDescription

        if ($OutputToFile) {
            if (-not (Test-Path (Split-Path $OutputPath))) {
                New-Item -ItemType Directory -Path (Split-Path $OutputPath) -Force | Out-Null
            }
            $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Append
            Write-Host "Results appended to: $OutputPath" -ForegroundColor Gray
        }

        # Always return the object (useful when called from RMM)
        return $exportData
    }
}
else {
    Write-Error "No license information could be retrieved."
}
