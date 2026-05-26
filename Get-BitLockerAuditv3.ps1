<#
.SYNOPSIS
    BitLocker Audit + Key Export Script for RMM Deployment
.DESCRIPTION
    - Collects full BitLocker status and recovery keys for all fixed drives
    - Saves per-machine TXT report to \\BackupServer\Bitlocker\Keys\HOSTNAME\
    - Appends a row to master CSV at \\BackupServer\Bitlocker\MasterBitlocker.csv
    - Optionally authenticates to the share with stored credentials
    - Designed for SYSTEM context via RMM (no AD / Entra key escrow)
    - Pure ASCII output - safe for all RMM log capture pipelines
.NOTES
    Compatible : Windows 10/11, Server 2016+
    Context    : SYSTEM or Administrator
    Methods    : BitLocker PS module (primary), WMI Win32_EncryptableVolume (fallback)
#>

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
#  CONFIGURATION  -  Edit these values before deploying
# ============================================================

# Share paths
$ShareRoot      = "\\BackupServer\Bitlocker"
$KeysFolder     = "$ShareRoot\Keys"
$MasterCSV      = "$ShareRoot\MasterBitlocker.csv"

# Credentials to authenticate to the share.
# Leave both as empty strings "" if the SYSTEM account already has access
# (e.g. the share grants access to Domain Computers or Everyone).
$ShareUser      = "BackupServer\BitlockerSvc"   # e.g. "DOMAIN\svcaccount" or "SERVER\localuser"
$SharePassword  = "YourPasswordHere"            # plain text - secure this script file accordingly

# Set to $true to also print the full recovery key to the RMM console log.
# Set to $false to keep keys off the console and only write them to the share.
$PrintKeyToConsole = $true

# ============================================================
#  END OF CONFIGURATION
# ============================================================


# ------------------------------------------------------------
#  HELPER FUNCTIONS
# ------------------------------------------------------------

function Write-Section {
    param([string]$Title)
    $line = "=" * 60
    Write-Output ""
    Write-Output $line
    Write-Output "  $Title"
    Write-Output $line
}

function Write-SubSection {
    param([string]$Title)
    Write-Output ""
    Write-Output "  -- $Title --"
}

# Append a line to a file, retrying if it is locked by another agent
function Append-FileSafe {
    param(
        [string]$Path,
        [string]$Content,
        [int]$MaxRetries = 10,
        [int]$RetryDelayMs = 500
    )
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append,
                                             [System.IO.FileAccess]::Write,
                                             [System.IO.FileShare]::None)
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.WriteLine($Content)
            $writer.Close()
            $stream.Close()
            return $true
        } catch {
            $attempt++
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }
    Write-Output "  !! ERROR: Could not write to $Path after $MaxRetries attempts (file locked)."
    return $false
}

# Escape a value for CSV (wrap in quotes, double any internal quotes)
function ConvertTo-CsvField {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    $escaped = $Value -replace '"', '""'
    return "`"$escaped`""
}


# ============================================================
#  SECTION 1: SYSTEM INFORMATION
# ============================================================
Write-Section "SYSTEM INFORMATION"

$hostname    = $env:COMPUTERNAME
$os          = Get-WmiObject Win32_OperatingSystem
$cs          = Get-WmiObject Win32_ComputerSystem
$bios        = Get-WmiObject Win32_BIOS
$cpu         = Get-WmiObject Win32_Processor | Select-Object -First 1
$ramGB       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
$osCaption   = $os.Caption
$osBuild     = $os.BuildNumber
$osVersion   = $os.Version
$lastBoot    = $os.ConvertToDateTime($os.LastBootUpTime)
$uptime      = (Get-Date) - $lastBoot
$uptimeStr   = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$privateIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Sort-Object InterfaceIndex | Select-Object -First 1).IPAddress

if (-not $privateIP) {
    $privateIP = (Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -and $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object -First 1 -ExpandProperty IPAddress |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ", "
}
if (-not $privateIP) { $privateIP = "Unknown" }

$tpmObj     = Get-WmiObject -Namespace "root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
$tpmPresent = if ($tpmObj) { "Present" }                                                           else { "Not Found" }
$tpmReady   = if ($tpmObj) { if ($tpmObj.IsEnabled_InitialValue) { "Enabled and Ready" } else { "Present but NOT Enabled" } } else { "N/A" }
$tpmVersion = if ($tpmObj) { ($tpmObj.SpecVersion -replace ",.*","").Trim() }                      else { "N/A" }

Write-Output "  Hostname        : $hostname"
Write-Output "  Private IP      : $privateIP"
Write-Output "  OS              : $osCaption"
Write-Output "  Build / Version : $osBuild / $osVersion"
Write-Output "  Manufacturer    : $($cs.Manufacturer)"
Write-Output "  Model           : $($cs.Model)"
Write-Output "  CPU             : $($cpu.Name.Trim())"
Write-Output "  RAM             : $ramGB GB"
Write-Output "  BIOS Serial     : $($bios.SerialNumber)"
Write-Output "  Last Boot       : $lastBoot"
Write-Output "  Uptime          : $uptimeStr"
Write-Output "  TPM Status      : $tpmPresent"
Write-Output "  TPM Ready       : $tpmReady"
Write-Output "  TPM Version     : $tpmVersion"
Write-Output "  Report Run At   : $runDate"


# ============================================================
#  SECTION 2: BITLOCKER MODULE CHECK
# ============================================================
Write-Section "BITLOCKER MODULE AVAILABILITY"

$blModuleAvailable = $false
try {
    Import-Module BitLocker -ErrorAction Stop
    $blModuleAvailable = $true
    Write-Output "  BitLocker PowerShell module : AVAILABLE"
} catch {
    Write-Output "  BitLocker PowerShell module : NOT AVAILABLE - using WMI fallback"
}


# ============================================================
#  SECTION 3: COLLECT BITLOCKER DATA PER VOLUME
# ============================================================
Write-Section "BITLOCKER VOLUME STATUS"

# We build two things simultaneously:
#   $volumeReports  - list of hashtables, one per volume (for TXT + CSV output)
#   Console output  - printed as we go

$volumeReports = @()
$fixedDrives   = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

if (-not $fixedDrives) {
    Write-Output "  No fixed drives detected."
} else {

    foreach ($drive in $fixedDrives) {
        $driveLetter = $drive.DeviceID
        $driveSizeGB = [math]::Round($drive.Size     / 1GB, 1)
        $driveFreeGB = [math]::Round($drive.FreeSpace / 1GB, 1)

        Write-SubSection "Drive: $driveLetter  ($driveSizeGB GB total | $driveFreeGB GB free)"

        # Initialise report record for this volume
        $rec = [ordered]@{
            Hostname           = $hostname
            IPAddress          = $privateIP
            OS                 = $osCaption
            Build              = $osBuild
            Manufacturer       = $cs.Manufacturer
            Model              = $cs.Model
            BIOSSerial         = $bios.SerialNumber
            Drive              = $driveLetter
            DriveSizeGB        = $driveSizeGB
            Protection         = "Unknown"
            VolumeStatus       = "Unknown"
            EncryptionPercent  = ""
            EncryptionMethod   = ""
            LockStatus         = ""
            AutoUnlock         = ""
            KeyProtectorTypes  = ""
            RecoveryKey        = ""
            Warnings           = ""
            TPMPresent         = $tpmPresent
            TPMVersion         = $tpmVersion
            ReportDate         = $runDate
        }

        # -- Primary: BitLocker PS Module --
        if ($blModuleAvailable) {
            $blVol = Get-BitLockerVolume -MountPoint $driveLetter -ErrorAction SilentlyContinue

            if ($blVol) {
                $rec.Protection        = "$($blVol.ProtectionStatus)"
                $rec.VolumeStatus      = "$($blVol.VolumeStatus)"
                $rec.EncryptionPercent = "$($blVol.EncryptionPercentage)"
                $rec.EncryptionMethod  = "$($blVol.EncryptionMethod)"
                $rec.LockStatus        = "$($blVol.LockStatus)"
                $rec.AutoUnlock        = "$($blVol.AutoUnlockEnabled)"

                Write-Output "  BitLocker Protection  : $($rec.Protection)"
                Write-Output "  Volume Status         : $($rec.VolumeStatus)"
                Write-Output "  Encryption Percent    : $($rec.EncryptionPercent)%"
                Write-Output "  Encryption Method     : $($rec.EncryptionMethod)"
                Write-Output "  Lock Status           : $($rec.LockStatus)"
                Write-Output "  Auto-Unlock Enabled   : $($rec.AutoUnlock)"

                $kpTypes     = @()
                $recoveryKeys = @()
                $warnings    = @()

                if ($blVol.KeyProtector -and $blVol.KeyProtector.Count -gt 0) {
                    Write-Output ""
                    Write-Output "  Key Protectors: $($blVol.KeyProtector.Count) found"

                    foreach ($kp in $blVol.KeyProtector) {
                        $kpType = $kp.KeyProtectorType

                        $kpDesc = switch ($kpType) {
                            "Tpm"               { "TPM (hardware-bound, no PIN)" }
                            "TpmPin"            { "TPM + PIN" }
                            "TpmStartupKey"     { "TPM + USB Startup Key" }
                            "TpmPinStartupKey"  { "TPM + PIN + USB Startup Key" }
                            "RecoveryPassword"  { "Recovery Password (48-digit)" }
                            "Password"          { "Password (non-TPM)" }
                            "ExternalKey"       { "External Key / USB Startup Key" }
                            "PublicKey"         { "Certificate / Smart Card" }
                            "Sid"               { "Active Directory SID Protector" }
                            "DuWk"              { "Data Recovery Agent (DRA)" }
                            default             { "$kpType" }
                        }

                        $kpTypes += $kpDesc
                        Write-Output "    Type : $kpDesc"
                        Write-Output "    ID   : $($kp.KeyProtectorId)"

                        if ($kpType -eq "RecoveryPassword" -and $kp.RecoveryPassword) {
                            $rp = $kp.RecoveryPassword
                            $recoveryKeys += $rp

                            if ($PrintKeyToConsole) {
                                Write-Output "    Recovery Key : $rp"
                            } else {
                                $rpPreview = ($rp -split "-")[0] + "-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
                                Write-Output "    Recovery Key : $rpPreview  (full key saved to share)"
                            }
                        }
                        Write-Output ""
                    }

                    # Risk: no recovery password
                    $hasRecovery = $blVol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
                    if (-not $hasRecovery) {
                        $w = "No Recovery Password protector found - drive may be unrecoverable if TPM is cleared"
                        $warnings += $w
                        Write-Output "  !! WARNING: $w"
                    }

                } else {
                    $warnings += "No key protectors found"
                    Write-Output "  Key Protectors        : NONE FOUND"
                    if ($blVol.ProtectionStatus -eq "On") {
                        $w = "BitLocker ON but no key protectors - protection may be suspended or incomplete"
                        $warnings += $w
                        Write-Output "  !! WARNING: $w"
                    }
                }

                # Suspended check
                if ($blVol.VolumeStatus -eq "FullyEncrypted" -and $blVol.ProtectionStatus -eq "Off") {
                    $w = "Drive encrypted but protection SUSPENDED (pending firmware update or manual suspend)"
                    $warnings += $w
                    Write-Output "  !! NOTICE: $w"
                }

                $rec.KeyProtectorTypes = $kpTypes    -join " | "
                $rec.RecoveryKey       = $recoveryKeys -join " | "
                $rec.Warnings          = $warnings   -join " | "

            } else {
                $rec.Protection  = "Not Configured"
                $rec.VolumeStatus = "N/A"
                Write-Output "  BitLocker Protection  : NOT CONFIGURED"
            }

        # -- Fallback: WMI Win32_EncryptableVolume --
        } else {
            $wmiVol = Get-WmiObject `
                -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" `
                -Class Win32_EncryptableVolume `
                -Filter "DriveLetter='$driveLetter'" `
                -ErrorAction SilentlyContinue

            if ($wmiVol) {
                $protStr = switch ($wmiVol.ProtectionStatus) {
                    0       { "Off" }
                    1       { "On" }
                    2       { "Unknown" }
                    default { "Code $($wmiVol.ProtectionStatus)" }
                }
                $convStr = switch ($wmiVol.ConversionStatus) {
                    0       { "Fully Decrypted" }
                    1       { "Fully Encrypted" }
                    2       { "Encrypting In Progress" }
                    3       { "Decrypting In Progress" }
                    4       { "Encryption Paused" }
                    5       { "Decryption Paused" }
                    default { "Unknown ($($wmiVol.ConversionStatus))" }
                }
                $encMethodCode = 0
                $null = $wmiVol.GetEncryptionMethod([ref]$encMethodCode)
                $encMethodStr = switch ($encMethodCode) {
                    0 { "None" }       1 { "AES 128-bit" }   2 { "AES 256-bit" }
                    3 { "Hardware" }   4 { "XTS-AES 128" }   5 { "XTS-AES 256" }
                    default { "Unknown ($encMethodCode)" }
                }

                $rec.Protection        = $protStr
                $rec.VolumeStatus      = $convStr
                $rec.EncryptionPercent = "$($wmiVol.EncryptionPercentage)"
                $rec.EncryptionMethod  = $encMethodStr

                Write-Output "  BitLocker Protection  : $protStr  (WMI)"
                Write-Output "  Volume Status         : $convStr"
                Write-Output "  Encryption Percent    : $($wmiVol.EncryptionPercentage)%"
                Write-Output "  Encryption Method     : $encMethodStr"

                $kpIds = $null
                $null  = $wmiVol.GetKeyProtectors(0, [ref]$kpIds)
                $kpTypes     = @()
                $recoveryKeys = @()
                $warnings    = @()

                if ($kpIds -and $kpIds.Count -gt 0) {
                    Write-Output "  Key Protectors        : $($kpIds.Count) found"
                    foreach ($kpId in $kpIds) {
                        $kpTypeCode = 0
                        $null = $wmiVol.GetKeyProtectorType($kpId, [ref]$kpTypeCode)
                        $kpTypeStr = switch ($kpTypeCode) {
                            0  { "Unknown" }              1  { "TPM" }
                            2  { "External Key" }         3  { "Numerical Password (Recovery)" }
                            4  { "TPM + PIN" }            5  { "TPM + Startup Key" }
                            6  { "TPM + PIN + Startup Key" } 7 { "Public Key" }
                            8  { "Passphrase" }           9  { "TPM Certificate" }
                            10 { "CNG Provider" }
                            default { "Type $kpTypeCode" }
                        }
                        $kpTypes += $kpTypeStr

                        # Retrieve recovery password via WMI if available
                        if ($kpTypeCode -eq 3) {
                            $rpWmi = $null
                            $null  = $wmiVol.GetKeyProtectorNumericalPassword($kpId, [ref]$rpWmi)
                            if ($rpWmi) {
                                $recoveryKeys += $rpWmi
                                Write-Output "    - $kpTypeStr  (ID: $kpId)"
                                if ($PrintKeyToConsole) {
                                    Write-Output "      Recovery Key : $rpWmi"
                                } else {
                                    $rpPreview = ($rpWmi -split "-")[0] + "-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
                                    Write-Output "      Recovery Key : $rpPreview  (full key saved to share)"
                                }
                            } else {
                                Write-Output "    - $kpTypeStr  (ID: $kpId)  Key: Unable to retrieve via WMI"
                            }
                        } else {
                            Write-Output "    - $kpTypeStr  (ID: $kpId)"
                        }
                    }
                } else {
                    $warnings += "No key protectors found (WMI)"
                    Write-Output "  Key Protectors        : NONE"
                }

                $rec.KeyProtectorTypes = $kpTypes     -join " | "
                $rec.RecoveryKey       = $recoveryKeys -join " | "
                $rec.Warnings          = $warnings     -join " | "

            } else {
                $rec.Protection   = "Disabled / Not Configured"
                $rec.VolumeStatus = "N/A"
                Write-Output "  BitLocker Protection  : DISABLED / Not Configured (WMI)"
            }
        }

        $volumeReports += $rec
    }
}


# ============================================================
#  SECTION 4: GROUP POLICY / REGISTRY SETTINGS
# ============================================================
Write-Section "BITLOCKER POLICY AND REGISTRY SETTINGS"

$blPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

if (Test-Path $blPolicyPath) {
    $fve = Get-ItemProperty -Path $blPolicyPath -ErrorAction SilentlyContinue

    function Get-RegVal {
        param($obj, $name, $desc, $map)
        $val = $obj.$name
        if ($null -ne $val) {
            if ($map -and $map.ContainsKey([int]$val)) {
                $display = "$val - $($map[[int]$val])"
            } else {
                $display = "$val"
            }
            Write-Output ("  {0,-44}: {1}" -f $desc, $display)
        }
    }

    Write-Output "  Registry Path: $blPolicyPath"
    Write-Output ""
    Get-RegVal $fve "EncryptionMethodWithXtsOs"         "OS Drive Encryption Method"             @{3="AES-CBC 128"; 4="AES-CBC 256"; 6="XTS-AES 128"; 7="XTS-AES 256"}
    Get-RegVal $fve "EncryptionMethodWithXtsFdv"        "Fixed Drive Encryption Method"          @{3="AES-CBC 128"; 4="AES-CBC 256"; 6="XTS-AES 128"; 7="XTS-AES 256"}
    Get-RegVal $fve "EncryptionMethodWithXtsRdv"        "Removable Drive Encryption Method"      @{3="AES-CBC 128"; 4="AES-CBC 256"; 6="XTS-AES 128"; 7="XTS-AES 256"}
    Get-RegVal $fve "UseTPM"                            "Require TPM"                            @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseTPMPIN"                         "Require TPM + PIN"                      @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseTPMKey"                         "Require TPM + Startup Key"              @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseTPMKeyPIN"                      "Require TPM + Key + PIN"                @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseAdvancedStartup"                "Require Additional Auth at Startup"     @{0="Disabled"; 1="Enabled"}
    Get-RegVal $fve "EnableBDEWithNoTPM"                "Allow BitLocker Without TPM"            @{0="No"; 1="Yes"}
    Get-RegVal $fve "RecoveryKeyUsagePolicy"            "Recovery Key Usage Policy"              @{0="Not Configured"; 1="Required"; 2="Prohibited"}
    Get-RegVal $fve "RecoveryPasswordUsagePolicy"       "Recovery Password Usage Policy"         @{0="Not Configured"; 1="Required"; 2="Prohibited"}
    Get-RegVal $fve "ActiveDirectoryBackup"             "Backup Recovery Key to AD"              @{0="No"; 1="Yes"}
    Get-RegVal $fve "RequireActiveDirectoryBackup"      "Require AD Backup Before Enabling"      @{0="No"; 1="Yes"}
    Get-RegVal $fve "OmitRecoveryPage"                  "Hide Recovery Page in Setup Wizard"     @{0="Show"; 1="Hide"}
    Get-RegVal $fve "FDVEncryptionType"                 "Fixed Drive Encryption Type"            @{0="Not Configured"; 1="Full Encryption"; 2="Used Space Only"}
    Get-RegVal $fve "RDVDenyWriteAccess"                "Deny Write Access to Non-BL USB"        @{0="No"; 1="Yes"}
    Get-RegVal $fve "RDVEncryptionType"                 "Removable Drive Encryption Type"        @{0="Not Configured"; 1="Full Encryption"; 2="Used Space Only"}
    Get-RegVal $fve "MinimumPIN"                        "Minimum PIN Length"                     $null
    Get-RegVal $fve "UseEnhancedPin"                    "Allow Enhanced PINs (alphanumeric)"     @{0="No"; 1="Yes"}
} else {
    Write-Output "  No BitLocker Group Policy registry keys found."
    Write-Output "  Path checked: $blPolicyPath"
}


# ============================================================
#  SECTION 5: SUMMARY TABLE
# ============================================================
Write-Section "SUMMARY"

Write-Output "  Host : $hostname"
Write-Output "  IP   : $privateIP"
Write-Output "  OS   : $osCaption  (Build $osBuild)"
Write-Output ""
Write-Output ("  {0,-8}  {1,-12}  {2,-22}  {3,-18}  {4}" -f "Drive","Protection","Volume Status","Method / Pct","Key Protectors")
Write-Output ("  {0,-8}  {1,-12}  {2,-22}  {3,-18}  {4}" -f "-----","----------","-------------","------------","-------------------")

foreach ($rec in $volumeReports) {
    $encCol = "$($rec.EncryptionMethod) $($rec.EncryptionPercent)%"
    Write-Output ("  {0,-8}  {1,-12}  {2,-22}  {3,-18}  {4}" -f `
        $rec.Drive, $rec.Protection, $rec.VolumeStatus, $encCol, $rec.KeyProtectorTypes)
}


# ============================================================
#  SECTION 6: EXPORT TO NETWORK SHARE
# ============================================================
Write-Section "EXPORTING TO NETWORK SHARE"

$shareConnected = $false
$shareDrive     = $null

# -- Step 1: Authenticate to share --
if ($ShareUser -ne "" -and $SharePassword -ne "") {
    Write-Output "  Connecting to share as: $ShareUser"

    # Disconnect any existing connection to avoid conflicts
    $null = & net use "$ShareRoot" /delete /yes 2>$null

    $netUseResult = & net use "$ShareRoot" /user:$ShareUser $SharePassword 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "  Share connection       : SUCCESS"
        $shareConnected = $true
    } else {
        Write-Output "  !! Share connection FAILED: $netUseResult"
        Write-Output "     Check ShareUser / SharePassword in script config."
    }
} else {
    Write-Output "  No credentials configured - assuming SYSTEM has share access."
    $shareConnected = $true
}

if ($shareConnected) {

    # -- Step 2: Create per-machine folder --
    $machineFolder = "$KeysFolder\$hostname"
    if (-not (Test-Path $machineFolder)) {
        $null = New-Item -ItemType Directory -Path $machineFolder -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $machineFolder) {
        Write-Output "  Machine folder         : $machineFolder  [OK]"
    } else {
        Write-Output "  !! Could not create folder: $machineFolder"
    }

    # -- Step 3: Build TXT report content --
    $txtLines = @()
    $txtLines += "=" * 60
    $txtLines += "  BITLOCKER AUDIT REPORT"
    $txtLines += "=" * 60
    $txtLines += "  Hostname        : $hostname"
    $txtLines += "  IP Address      : $privateIP"
    $txtLines += "  OS              : $osCaption"
    $txtLines += "  Build           : $osBuild"
    $txtLines += "  Manufacturer    : $($cs.Manufacturer)"
    $txtLines += "  Model           : $($cs.Model)"
    $txtLines += "  BIOS Serial     : $($bios.SerialNumber)"
    $txtLines += "  TPM Status      : $tpmPresent"
    $txtLines += "  TPM Version     : $tpmVersion"
    $txtLines += "  Report Date     : $runDate"
    $txtLines += ""

    foreach ($rec in $volumeReports) {
        $txtLines += "=" * 60
        $txtLines += "  Drive : $($rec.Drive)  ($($rec.DriveSizeGB) GB)"
        $txtLines += "=" * 60
        $txtLines += "  Protection Status   : $($rec.Protection)"
        $txtLines += "  Volume Status       : $($rec.VolumeStatus)"
        $txtLines += "  Encryption Percent  : $($rec.EncryptionPercent)%"
        $txtLines += "  Encryption Method   : $($rec.EncryptionMethod)"
        $txtLines += "  Lock Status         : $($rec.LockStatus)"
        $txtLines += "  Auto-Unlock         : $($rec.AutoUnlock)"
        $txtLines += "  Key Protector Types : $($rec.KeyProtectorTypes)"
        $txtLines += ""

        if ($rec.RecoveryKey -ne "") {
            $keys = $rec.RecoveryKey -split " \| "
            $txtLines += "  RECOVERY KEY(S):"
            foreach ($k in $keys) {
                $txtLines += "    $k"
            }
        } else {
            $txtLines += "  RECOVERY KEY(S): None found / Not applicable"
        }

        if ($rec.Warnings -ne "") {
            $txtLines += ""
            $txtLines += "  WARNINGS:"
            $rec.Warnings -split " \| " | ForEach-Object { $txtLines += "    !! $_" }
        }
        $txtLines += ""
    }

    $txtLines += "=" * 60
    $txtLines += "  End of Report"
    $txtLines += "=" * 60

    # -- Step 4: Write per-machine TXT file --
    # Filename includes date so repeated runs don't overwrite (one file per run)
    $dateStamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $txtFile   = "$machineFolder\BitLocker_${hostname}_${dateStamp}.txt"

    try {
        $txtLines | Set-Content -Path $txtFile -Encoding ASCII -ErrorAction Stop
        Write-Output "  TXT report written     : $txtFile  [OK]"
    } catch {
        Write-Output "  !! Failed to write TXT report: $_"
    }

    # -- Step 5: Append to master CSV --
    # Write header row if the file does not yet exist
    $csvHeader = "Hostname,IPAddress,OS,Build,Manufacturer,Model,BIOSSerial," +
                 "Drive,DriveSizeGB,Protection,VolumeStatus,EncryptionPercent," +
                 "EncryptionMethod,LockStatus,AutoUnlock,KeyProtectorTypes," +
                 "RecoveryKey,Warnings,TPMPresent,TPMVersion,ReportDate"

    if (-not (Test-Path $MasterCSV)) {
        try {
            $csvHeader | Set-Content -Path $MasterCSV -Encoding ASCII -ErrorAction Stop
            Write-Output "  Master CSV created     : $MasterCSV  [OK]"
        } catch {
            Write-Output "  !! Failed to create master CSV: $_"
        }
    }

    # Append one row per volume
    foreach ($rec in $volumeReports) {
        $csvRow = (
            (ConvertTo-CsvField $rec.Hostname),
            (ConvertTo-CsvField $rec.IPAddress),
            (ConvertTo-CsvField $rec.OS),
            (ConvertTo-CsvField $rec.Build),
            (ConvertTo-CsvField $rec.Manufacturer),
            (ConvertTo-CsvField $rec.Model),
            (ConvertTo-CsvField $rec.BIOSSerial),
            (ConvertTo-CsvField $rec.Drive),
            (ConvertTo-CsvField "$($rec.DriveSizeGB)"),
            (ConvertTo-CsvField $rec.Protection),
            (ConvertTo-CsvField $rec.VolumeStatus),
            (ConvertTo-CsvField "$($rec.EncryptionPercent)"),
            (ConvertTo-CsvField $rec.EncryptionMethod),
            (ConvertTo-CsvField $rec.LockStatus),
            (ConvertTo-CsvField $rec.AutoUnlock),
            (ConvertTo-CsvField $rec.KeyProtectorTypes),
            (ConvertTo-CsvField $rec.RecoveryKey),
            (ConvertTo-CsvField $rec.Warnings),
            (ConvertTo-CsvField $rec.TPMPresent),
            (ConvertTo-CsvField $rec.TPMVersion),
            (ConvertTo-CsvField $rec.ReportDate)
        ) -join ","

        $appended = Append-FileSafe -Path $MasterCSV -Content $csvRow
        if ($appended) {
            Write-Output "  Master CSV row appended: $hostname  $($rec.Drive)  [OK]"
        }
    }

    # -- Step 6: Disconnect share if we connected with credentials --
    if ($ShareUser -ne "" -and $SharePassword -ne "") {
        $null = & net use "$ShareRoot" /delete /yes 2>$null
        Write-Output "  Share disconnected     : [OK]"
    }

} else {
    Write-Output "  Skipping file export - share not accessible."
}

Write-Output ""
Write-Output "  Script completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("=" * 60)
