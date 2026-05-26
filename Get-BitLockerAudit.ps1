#Requires -RunAsAdministrator
<#
.SYNOPSIS
    BitLocker Audit Script for RMM Deployment
.DESCRIPTION
    Collects comprehensive BitLocker status and configuration details for all fixed drives.
    Designed to run under SYSTEM context via RMM tools (Faronics DeepFreeze Cloud, etc.)
    Outputs clean, structured text suitable for RMM console log capture.
.NOTES
    - Requires SYSTEM or Administrator context
    - Compatible with Windows 10/11 and Windows Server 2016+
    - Uses Get-BitLockerVolume (BitLocker module) with WMI fallback
#>

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ─────────────────────────────────────────────
#  HELPER: Section Banner
# ─────────────────────────────────────────────
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
    Write-Output "  $("-" * ($Title.Length + 6))"
}

# ─────────────────────────────────────────────
#  SECTION 1: System Identity
# ─────────────────────────────────────────────
Write-Section "SYSTEM INFORMATION"

$hostname   = $env:COMPUTERNAME
$os         = Get-WmiObject Win32_OperatingSystem
$cs         = Get-WmiObject Win32_ComputerSystem
$bios       = Get-WmiObject Win32_BIOS
$cpu        = Get-WmiObject Win32_Processor | Select-Object -First 1
$ramGB      = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
$osCaption  = $os.Caption
$osBuild    = $os.BuildNumber
$osVersion  = $os.Version
$lastBoot   = $os.ConvertToDateTime($os.LastBootUpTime)
$uptime     = (Get-Date) - $lastBoot
$uptimeStr  = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes

# Private IP (first non-loopback, non-APIPA IPv4)
$privateIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Sort-Object InterfaceIndex |
    Select-Object -First 1).IPAddress

if (-not $privateIP) {
    # WMI fallback for older OS / minimal environments
    $privateIP = (Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -and $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object -First 1 -ExpandProperty IPAddress |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ", "
}

$tpmObj    = Get-WmiObject -Namespace "root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
$tpmPresent = if ($tpmObj) { "Present" } else { "Not Found / WMI Unavailable" }
$tpmReady   = if ($tpmObj) { if ($tpmObj.IsEnabled_InitialValue) { "Enabled & Ready" } else { "Present but NOT Enabled" } } else { "N/A" }
$tpmVersion = if ($tpmObj) { $tpmObj.SpecVersion -replace ",.*","" } else { "N/A" }

Write-Output "  Hostname       : $hostname"
Write-Output "  Private IP     : $privateIP"
Write-Output "  OS             : $osCaption"
Write-Output "  Build / Version: $osBuild / $osVersion"
Write-Output "  Manufacturer   : $($cs.Manufacturer)"
Write-Output "  Model          : $($cs.Model)"
Write-Output "  CPU            : $($cpu.Name.Trim())"
Write-Output "  RAM            : $ramGB GB"
Write-Output "  BIOS Serial    : $($bios.SerialNumber)"
Write-Output "  Last Boot      : $lastBoot"
Write-Output "  Uptime         : $uptimeStr"
Write-Output "  TPM Status     : $tpmPresent"
Write-Output "  TPM Ready      : $tpmReady"
Write-Output "  TPM Version    : $tpmVersion"

# ─────────────────────────────────────────────
#  SECTION 2: BitLocker Module Check
# ─────────────────────────────────────────────
Write-Section "BITLOCKER MODULE AVAILABILITY"

$blModuleAvailable = $false
try {
    Import-Module BitLocker -ErrorAction Stop
    $blModuleAvailable = $true
    Write-Output "  BitLocker PowerShell module  : AVAILABLE"
} catch {
    Write-Output "  BitLocker PowerShell module  : NOT AVAILABLE (will use WMI fallback)"
}

# ─────────────────────────────────────────────
#  SECTION 3: BitLocker Per-Volume Detail
# ─────────────────────────────────────────────
Write-Section "BITLOCKER VOLUME STATUS"

# Identify fixed drives (DriveType 3 = Local Disk)
$fixedDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

if (-not $fixedDrives) {
    Write-Output "  No fixed drives detected."
} else {
    foreach ($drive in $fixedDrives) {
        $driveLetter = $drive.DeviceID   # e.g. "C:"
        $driveSizeGB = [math]::Round($drive.Size / 1GB, 1)
        $driveFreeGB = [math]::Round($drive.FreeSpace / 1GB, 1)

        Write-SubSection "Drive: $driveLetter  ($driveSizeGB GB total, $driveFreeGB GB free)"

        # ── Method 1: BitLocker PS Module ──
        if ($blModuleAvailable) {
            $blVol = Get-BitLockerVolume -MountPoint $driveLetter -ErrorAction SilentlyContinue

            if ($blVol) {
                $protStatus   = $blVol.ProtectionStatus      # On / Off / Unknown
                $encStatus    = $blVol.VolumeStatus          # FullyEncrypted, FullyDecrypted, etc.
                $encPercent   = $blVol.EncryptionPercentage
                $encMethod    = $blVol.EncryptionMethod       # AES128, XtsAes256, etc.
                $lockStatus   = $blVol.LockStatus            # Locked / Unlocked
                $autoUnlock   = $blVol.AutoUnlockEnabled
                $autoUnlockKey= $blVol.AutoUnlockKeyStored
                $keyProtectors= $blVol.KeyProtector

                # ── Overall Status ──
                $blEnabled = $protStatus -eq "On"

                Write-Output "  BitLocker Protection : $(if ($blEnabled) {'ENABLED ✔'} else {'DISABLED ✘'})"
                Write-Output "  Volume Status        : $encStatus"
                Write-Output "  Encryption %         : $encPercent%"
                Write-Output "  Encryption Method    : $encMethod"
                Write-Output "  Lock Status          : $lockStatus"
                Write-Output "  Auto-Unlock Enabled  : $autoUnlock"
                Write-Output "  Auto-Unlock Key Stored: $autoUnlockKey"

                # ── Key Protectors ──
                if ($keyProtectors -and $keyProtectors.Count -gt 0) {
                    Write-Output ""
                    Write-Output "  Key Protectors ($($keyProtectors.Count) found):"
                    foreach ($kp in $keyProtectors) {
                        $kpType = $kp.KeyProtectorType
                        $kpId   = $kp.KeyProtectorId

                        # Friendly description per protector type
                        $kpDesc = switch ($kpType) {
                            "Tpm"                      { "TPM (hardware-bound, no PIN)" }
                            "TpmPin"                   { "TPM + PIN" }
                            "TpmStartupKey"            { "TPM + USB Startup Key" }
                            "TpmPinStartupKey"         { "TPM + PIN + USB Startup Key" }
                            "RecoveryPassword"         { "Recovery Password (48-digit)" }
                            "Password"                 { "Password (non-TPM)" }
                            "ExternalKey"              { "External Key / USB Startup Key" }
                            "PublicKey"                { "Certificate / Smart Card" }
                            "Sid"                      { "Active Directory SID protector (AD backup)" }
                            "DuWk"                     { "Data Recovery Agent (DRA)" }
                            default                    { $kpType }
                        }

                        Write-Output "    - Type : $kpDesc"
                        Write-Output "      ID   : $kpId"

                        # For Recovery Password: show redacted preview
                        if ($kpType -eq "RecoveryPassword") {
                            $rp = $kp.RecoveryPassword
                            if ($rp) {
                                # Show first block only (XXXXXX-XXXXXX-...)
                                $rpPreview = ($rp -split "-")[0] + "-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
                                Write-Output "      Recovery Password (redacted): $rpPreview"
                                Write-Output "      NOTE: Retrieve full key from AD/AAD/MBAM or local escrow."
                            }
                        }

                        # Flag if no recovery password protector found (risk indicator)
                    }

                    # ── Risk: No Recovery Password ──
                    $hasRecoveryKey = $keyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
                    if (-not $hasRecoveryKey) {
                        Write-Output ""
                        Write-Output "  ⚠ WARNING: No Recovery Password protector found on $driveLetter"
                        Write-Output "    If TPM is cleared or hardware changes, drive may be unrecoverable!"
                    }

                } else {
                    Write-Output "  Key Protectors       : NONE FOUND"
                    if ($blEnabled) {
                        Write-Output "  ⚠ WARNING: BitLocker is ON but no key protectors detected. Protection may be suspended."
                    }
                }

                # ── Protection Suspended Check ──
                if ($encStatus -eq "FullyEncrypted" -and $protStatus -eq "Off") {
                    Write-Output ""
                    Write-Output "  ⚠ NOTICE: Drive is fully encrypted but protection is SUSPENDED."
                    Write-Output "    BitLocker is paused (e.g., pending firmware update or manual suspend)."
                }

            } else {
                Write-Output "  BitLocker Protection : NOT CONFIGURED (volume not returned by Get-BitLockerVolume)"
            }

        # ── Method 2: WMI Fallback (Win32_EncryptableVolume) ──
        } else {
            $wmiVol = Get-WmiObject -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" `
                                    -Class Win32_EncryptableVolume `
                                    -Filter "DriveLetter='$driveLetter'" `
                                    -ErrorAction SilentlyContinue

            if ($wmiVol) {
                # ProtectionStatus: 0=Off, 1=On, 2=Unknown
                $protCode = $wmiVol.ProtectionStatus
                $protStr  = switch ($protCode) { 0 {"DISABLED ✘"} 1 {"ENABLED ✔"} 2 {"UNKNOWN"} default {"N/A ($protCode)"} }

                # ConversionStatus: 0=FullyDecrypted, 1=FullyEncrypted, 2=EncryptInProgress, 3=DecryptInProgress, 4=EncryptionPaused, 5=DecryptionPaused
                $convCode = $wmiVol.ConversionStatus
                $convStr  = switch ($convCode) {
                    0 {"Fully Decrypted"}  1 {"Fully Encrypted"}
                    2 {"Encrypting..."}    3 {"Decrypting..."}
                    4 {"Encryption Paused"} 5 {"Decryption Paused"}
                    default {"Unknown ($convCode)"}
                }

                $encPct   = $wmiVol.EncryptionPercentage
                $null     = $wmiVol.GetEncryptionMethod([ref]$encMethodCode)
                $encMethodStr = switch ($encMethodCode) {
                    0 {"None"} 1 {"AES 128-bit"} 2 {"AES 256-bit"}
                    3 {"Hardware Encryption"} 4 {"XTS-AES 128-bit"} 5 {"XTS-AES 256-bit"}
                    default {"Unknown ($encMethodCode)"}
                }

                Write-Output "  BitLocker Protection : $protStr"
                Write-Output "  Conversion Status    : $convStr"
                Write-Output "  Encryption %         : $encPct%"
                Write-Output "  Encryption Method    : $encMethodStr  (WMI)"

                # Key Protectors via WMI
                $kpIds = $null
                $null = $wmiVol.GetKeyProtectors(0, [ref]$kpIds)
                if ($kpIds -and $kpIds.Count -gt 0) {
                    Write-Output "  Key Protectors       : $($kpIds.Count) found"
                    foreach ($kpId in $kpIds) {
                        $kpTypeCode = $null
                        $null = $wmiVol.GetKeyProtectorType($kpId, [ref]$kpTypeCode)
                        $kpTypeStr = switch ($kpTypeCode) {
                            0 {"Unknown"} 1 {"TPM"} 2 {"External Key"} 3 {"Numerical Password (Recovery)"}
                            4 {"TPM + PIN"} 5 {"TPM + Startup Key"} 6 {"TPM + PIN + Startup Key"}
                            7 {"Public Key"} 8 {"Passphrase"} 9 {"TPM Certificate"} 10 {"CNG Provider"}
                            default {"Type $kpTypeCode"}
                        }
                        Write-Output "    - $kpTypeStr  (ID: $kpId)"
                    }
                } else {
                    Write-Output "  Key Protectors       : NONE"
                }

            } else {
                Write-Output "  BitLocker Protection : DISABLED / Not Configured"
                Write-Output "  (WMI: Win32_EncryptableVolume not available for $driveLetter)"
            }
        }

        Write-Output ""
    }
}

# ─────────────────────────────────────────────
#  SECTION 4: BitLocker Group Policy / Registry
# ─────────────────────────────────────────────
Write-Section "BITLOCKER POLICY & REGISTRY SETTINGS"

$blPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (Test-Path $blPolicyPath) {
    $fve = Get-ItemProperty -Path $blPolicyPath -ErrorAction SilentlyContinue

    function Get-RegVal ($obj, $name, $desc, $map) {
        $val = $obj.$name
        if ($null -ne $val) {
            $display = if ($map -and $map.ContainsKey([int]$val)) { "$val ($($map[[int]$val]))" } else { $val }
            Write-Output ("  {0,-42}: {1}" -f $desc, $display)
        }
    }

    Write-Output "  Registry Path: $blPolicyPath"
    Write-Output ""

    # Encryption method
    Get-RegVal $fve "EncryptionMethodWithXtsOs"    "OS Drive Encryption Method"        @{3="AES-CBC 128"; 4="AES-CBC 256"; 6="XTS-AES 128"; 7="XTS-AES 256"}
    Get-RegVal $fve "EncryptionMethodWithXtsFdv"   "Fixed Drive Encryption Method"     @{3="AES-CBC 128"; 4="AES-CBC 256"; 6="XTS-AES 128"; 7="XTS-AES 256"}
    Get-RegVal $fve "EncryptionMethodWithXtsRdv"   "Removable Drive Encryption Method" @{3="AES-CBC 128"; 4="AES-CBC 256"; 6="XTS-AES 128"; 7="XTS-AES 256"}

    # TPM startup options
    Get-RegVal $fve "UseTPM"                        "Require TPM"                       @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseTPMPIN"                     "Require TPM + PIN"                 @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseTPMKey"                     "Require TPM + Startup Key"         @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseTPMKeyPIN"                  "Require TPM + Key + PIN"           @{0="Do Not Allow"; 1="Require"; 2="Allow"}
    Get-RegVal $fve "UseAdvancedStartup"            "Require Additional Auth at Startup" @{0="Disabled"; 1="Enabled"}
    Get-RegVal $fve "EnableBDEWithNoTPM"            "Allow BitLocker Without TPM"       @{0="No"; 1="Yes"}

    # Recovery options
    Get-RegVal $fve "RecoveryKeyUsagePolicy"        "Recovery Key Usage"                @{0="Not Configured"; 1="Required"; 2="Prohibited"}
    Get-RegVal $fve "RecoveryPasswordUsagePolicy"   "Recovery Password Usage"           @{0="Not Configured"; 1="Required"; 2="Prohibited"}
    Get-RegVal $fve "ActiveDirectoryBackup"         "Backup to Active Directory"        @{0="No"; 1="Yes"}
    Get-RegVal $fve "RequireActiveDirectoryBackup"  "Require AD Backup Before Enable"   @{0="No"; 1="Yes"}
    Get-RegVal $fve "ActiveDirectoryInfoToStore"    "AD Backup Type"                    @{1="Recovery Password Only"; 2="Recovery Password + Key Package"}
    Get-RegVal $fve "OmitRecoveryPage"              "Hide Recovery Page in Setup"       @{0="Show"; 1="Hide"}

    # Fixed / Removable drive policies
    Get-RegVal $fve "FDVEncryptionType"             "Fixed Drive Encryption Type"       @{0="Not Configured"; 1="Full Encryption"; 2="Used Space Only"}
    Get-RegVal $fve "RDVDenyWriteAccess"            "Deny Write to Non-BitLocker USB"   @{0="No"; 1="Yes"}
    Get-RegVal $fve "RDVEncryptionType"             "Removable Drive Encryption Type"   @{0="Not Configured"; 1="Full Encryption"; 2="Used Space Only"}

    # PIN complexity
    Get-RegVal $fve "MinimumPIN"                    "Minimum PIN Length"                $null
    Get-RegVal $fve "UseEnhancedPin"                "Allow Enhanced PINs"               @{0="No"; 1="Yes"}

} else {
    Write-Output "  No BitLocker Group Policy registry keys found."
    Write-Output "  (Path not present: $blPolicyPath)"
    Write-Output "  BitLocker may be configured manually or via MDM/Intune."
}

# ─────────────────────────────────────────────
#  SECTION 5: Intune / MDM BitLocker (if applicable)
# ─────────────────────────────────────────────
Write-Section "MDM / INTUNE BITLOCKER STATUS"

$mdmPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker"
if (Test-Path $mdmPath) {
    Write-Output "  MDM BitLocker policy keys present:"
    $mdmProps = Get-ItemProperty -Path $mdmPath -ErrorAction SilentlyContinue
    $mdmProps.PSObject.Properties |
        Where-Object { $_.Name -notmatch "^PS" } |
        ForEach-Object { Write-Output ("  {0,-45}: {1}" -f $_.Name, $_.Value) }
} else {
    Write-Output "  No MDM/Intune BitLocker policy keys found at:"
    Write-Output "  $mdmPath"
}

# Check AAD / Entra join status (relevant for cloud key escrow)
$dsregPath = "$env:SystemRoot\System32\dsregcmd.exe"
if (Test-Path $dsregPath) {
    $dsreg = & $dsregPath /status 2>$null
    $aadJoined   = ($dsreg | Select-String "AzureAdJoined\s*:\s*YES") -ne $null
    $domJoined   = ($dsreg | Select-String "DomainJoined\s*:\s*YES") -ne $null
    Write-Output ""
    Write-Output "  Entra ID (AAD) Joined : $(if ($aadJoined) {'YES — BitLocker keys may be escrowed to AAD'} else {'No'})"
    Write-Output "  Domain Joined         : $(if ($domJoined) {'YES — Recovery key may be in AD'} else {'No'})"
}

# ─────────────────────────────────────────────
#  SECTION 6: Summary Table
# ─────────────────────────────────────────────
Write-Section "SUMMARY"
Write-Output "  Host      : $hostname"
Write-Output "  IP        : $privateIP"
Write-Output "  OS        : $osCaption  (Build $osBuild)"
Write-Output ""

if ($blModuleAvailable) {
    $allVols = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($allVols) {
        Write-Output ("  {0,-8}  {1,-18}  {2,-22}  {3,-16}  {4}" -f "Drive","Protection","Volume Status","Encryption","Key Protectors")
        Write-Output ("  {0,-8}  {1,-18}  {2,-22}  {3,-16}  {4}" -f "-----","----------","-------------","-----------","--------------")
        foreach ($v in $allVols) {
            $kpTypes = if ($v.KeyProtector) { ($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", " } else { "None" }
            Write-Output ("  {0,-8}  {1,-18}  {2,-22}  {3,-16}  {4}" -f `
                $v.MountPoint,
                $v.ProtectionStatus,
                $v.VolumeStatus,
                "$($v.EncryptionPercentage)% $($v.EncryptionMethod)",
                $kpTypes)
        }
    }
} else {
    Write-Output "  (BitLocker module unavailable — see per-volume details above for WMI-based results)"
}

Write-Output ""
Write-Output "  Script completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "=" * 60
