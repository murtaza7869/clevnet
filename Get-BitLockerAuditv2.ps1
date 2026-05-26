#Requires -RunAsAdministrator
<#
.SYNOPSIS
    BitLocker Audit Script for RMM Deployment
.DESCRIPTION
    Collects comprehensive BitLocker status and configuration for all fixed drives.
    Designed to run under SYSTEM context via RMM tools.
    Pure ASCII output - safe for all RMM log capture pipelines.
.NOTES
    Compatible: Windows 10/11, Server 2016+
    Context:    SYSTEM or Administrator
    Methods:    BitLocker PS module (primary), WMI Win32_EncryptableVolume (fallback)
#>

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

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

# ============================================================
#  SECTION 1: SYSTEM INFORMATION
# ============================================================
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

# Private IP - primary method
$privateIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Sort-Object InterfaceIndex |
    Select-Object -First 1).IPAddress

# WMI fallback
if (-not $privateIP) {
    $privateIP = (Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -and $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object -First 1 -ExpandProperty IPAddress |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ", "
}

if (-not $privateIP) { $privateIP = "Unable to determine" }

# TPM info
$tpmObj     = Get-WmiObject -Namespace "root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
$tpmPresent = if ($tpmObj) { "Present" } else { "Not Found / WMI Unavailable" }
$tpmReady   = if ($tpmObj) { if ($tpmObj.IsEnabled_InitialValue) { "Enabled and Ready" } else { "Present but NOT Enabled" } } else { "N/A" }
$tpmVersion = if ($tpmObj) { ($tpmObj.SpecVersion -replace ",.*","").Trim() } else { "N/A" }

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

# ============================================================
#  SECTION 2: BITLOCKER MODULE AVAILABILITY
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
#  SECTION 3: BITLOCKER VOLUME STATUS (PER DRIVE)
# ============================================================
Write-Section "BITLOCKER VOLUME STATUS"

$fixedDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

if (-not $fixedDrives) {
    Write-Output "  No fixed drives detected."
} else {

    foreach ($drive in $fixedDrives) {
        $driveLetter = $drive.DeviceID
        $driveSizeGB = [math]::Round($drive.Size / 1GB, 1)
        $driveFreeGB = [math]::Round($drive.FreeSpace / 1GB, 1)

        Write-SubSection "Drive: $driveLetter  ($driveSizeGB GB total | $driveFreeGB GB free)"

        # --------------------------------------------------
        # Primary: BitLocker PS Module
        # --------------------------------------------------
        if ($blModuleAvailable) {
            $blVol = Get-BitLockerVolume -MountPoint $driveLetter -ErrorAction SilentlyContinue

            if ($blVol) {
                $protStatus    = $blVol.ProtectionStatus
                $encStatus     = $blVol.VolumeStatus
                $encPercent    = $blVol.EncryptionPercentage
                $encMethod     = $blVol.EncryptionMethod
                $lockStatus    = $blVol.LockStatus
                $autoUnlock    = $blVol.AutoUnlockEnabled
                $autoUnlockKey = $blVol.AutoUnlockKeyStored
                $keyProtectors = $blVol.KeyProtector

                if ($protStatus -eq "On") {
                    $blEnabledStr = "ENABLED"
                } else {
                    $blEnabledStr = "DISABLED"
                }

                Write-Output "  BitLocker Protection  : $blEnabledStr"
                Write-Output "  Volume Status         : $encStatus"
                Write-Output "  Encryption Percent    : $encPercent%"
                Write-Output "  Encryption Method     : $encMethod"
                Write-Output "  Lock Status           : $lockStatus"
                Write-Output "  Auto-Unlock Enabled   : $autoUnlock"
                Write-Output "  Auto-Unlock Key Stored: $autoUnlockKey"

                # Key Protectors
                if ($keyProtectors -and $keyProtectors.Count -gt 0) {
                    Write-Output ""
                    Write-Output "  Key Protectors: $($keyProtectors.Count) found"

                    foreach ($kp in $keyProtectors) {
                        $kpType = $kp.KeyProtectorType
                        $kpId   = $kp.KeyProtectorId

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

                        Write-Output "    Type : $kpDesc"
                        Write-Output "    ID   : $kpId"

                        if ($kpType -eq "RecoveryPassword") {
                            $rp = $kp.RecoveryPassword
                            if ($rp) {
                                $rpFirst   = ($rp -split "-")[0]
                                $rpPreview = "$rpFirst-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
                                Write-Output "    Recovery Password (redacted) : $rpPreview"
                                Write-Output "    NOTE: Retrieve full key from AD / AAD / MBAM or local escrow."
                            }
                        }
                        Write-Output ""
                    }

                    # Risk: no recovery password protector
                    $hasRecovery = $keyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
                    if (-not $hasRecovery) {
                        Write-Output "  !! WARNING: No Recovery Password protector on $driveLetter"
                        Write-Output "     If TPM is cleared or hardware changes, drive may be UNRECOVERABLE."
                    }

                } else {
                    Write-Output "  Key Protectors        : NONE FOUND"
                    if ($protStatus -eq "On") {
                        Write-Output "  !! WARNING: BitLocker is ON but no key protectors detected."
                        Write-Output "     Protection may be suspended or in an incomplete state."
                    }
                }

                # Suspended check
                if ($encStatus -eq "FullyEncrypted" -and $protStatus -eq "Off") {
                    Write-Output ""
                    Write-Output "  !! NOTICE: Drive is fully encrypted but protection is SUSPENDED."
                    Write-Output "     BitLocker paused - pending firmware update or manual suspend."
                }

            } else {
                Write-Output "  BitLocker Protection  : NOT CONFIGURED"
            }

        # --------------------------------------------------
        # Fallback: WMI Win32_EncryptableVolume
        # --------------------------------------------------
        } else {
            $wmiVol = Get-WmiObject `
                -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" `
                -Class Win32_EncryptableVolume `
                -Filter "DriveLetter='$driveLetter'" `
                -ErrorAction SilentlyContinue

            if ($wmiVol) {
                $protCode = $wmiVol.ProtectionStatus
                $protStr  = switch ($protCode) {
                    0       { "DISABLED" }
                    1       { "ENABLED" }
                    2       { "UNKNOWN" }
                    default { "N/A (code: $protCode)" }
                }

                $convCode = $wmiVol.ConversionStatus
                $convStr  = switch ($convCode) {
                    0       { "Fully Decrypted" }
                    1       { "Fully Encrypted" }
                    2       { "Encrypting In Progress" }
                    3       { "Decrypting In Progress" }
                    4       { "Encryption Paused" }
                    5       { "Decryption Paused" }
                    default { "Unknown (code: $convCode)" }
                }

                $encPct       = $wmiVol.EncryptionPercentage
                $encMethodCode = 0
                $null = $wmiVol.GetEncryptionMethod([ref]$encMethodCode)
                $encMethodStr = switch ($encMethodCode) {
                    0       { "None" }
                    1       { "AES 128-bit" }
                    2       { "AES 256-bit" }
                    3       { "Hardware Encryption" }
                    4       { "XTS-AES 128-bit" }
                    5       { "XTS-AES 256-bit" }
                    default { "Unknown (code: $encMethodCode)" }
                }

                Write-Output "  BitLocker Protection  : $protStr  (WMI)"
                Write-Output "  Conversion Status     : $convStr"
                Write-Output "  Encryption Percent    : $encPct%"
                Write-Output "  Encryption Method     : $encMethodStr"

                $kpIds = $null
                $null  = $wmiVol.GetKeyProtectors(0, [ref]$kpIds)

                if ($kpIds -and $kpIds.Count -gt 0) {
                    Write-Output "  Key Protectors        : $($kpIds.Count) found"
                    foreach ($kpId in $kpIds) {
                        $kpTypeCode = 0
                        $null = $wmiVol.GetKeyProtectorType($kpId, [ref]$kpTypeCode)
                        $kpTypeStr = switch ($kpTypeCode) {
                            0       { "Unknown" }
                            1       { "TPM" }
                            2       { "External Key" }
                            3       { "Numerical Password (Recovery)" }
                            4       { "TPM + PIN" }
                            5       { "TPM + Startup Key" }
                            6       { "TPM + PIN + Startup Key" }
                            7       { "Public Key" }
                            8       { "Passphrase" }
                            9       { "TPM Certificate" }
                            10      { "CNG Provider" }
                            default { "Type code $kpTypeCode" }
                        }
                        Write-Output "    - $kpTypeStr  (ID: $kpId)"
                    }
                } else {
                    Write-Output "  Key Protectors        : NONE"
                }

            } else {
                Write-Output "  BitLocker Protection  : DISABLED / Not Configured"
                Write-Output "  (WMI: Win32_EncryptableVolume not available for $driveLetter)"
            }
        }
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
    Get-RegVal $fve "ActiveDirectoryInfoToStore"        "AD Backup Type"                         @{1="Recovery Password Only"; 2="Recovery Password + Key Package"}
    Get-RegVal $fve "OmitRecoveryPage"                  "Hide Recovery Page in Setup Wizard"     @{0="Show"; 1="Hide"}
    Get-RegVal $fve "FDVEncryptionType"                 "Fixed Drive Encryption Type"            @{0="Not Configured"; 1="Full Encryption"; 2="Used Space Only"}
    Get-RegVal $fve "RDVDenyWriteAccess"                "Deny Write Access to Non-BL USB Drives" @{0="No"; 1="Yes"}
    Get-RegVal $fve "RDVEncryptionType"                 "Removable Drive Encryption Type"        @{0="Not Configured"; 1="Full Encryption"; 2="Used Space Only"}
    Get-RegVal $fve "MinimumPIN"                        "Minimum PIN Length"                     $null
    Get-RegVal $fve "UseEnhancedPin"                    "Allow Enhanced PINs (alphanumeric)"     @{0="No"; 1="Yes"}

} else {
    Write-Output "  No BitLocker Group Policy registry keys found."
    Write-Output "  Path not present: $blPolicyPath"
    Write-Output "  BitLocker may be configured manually or via MDM/Intune."
}

# ============================================================
#  SECTION 5: MDM / INTUNE STATUS + DIRECTORY JOIN
# ============================================================
Write-Section "MDM / INTUNE AND DIRECTORY JOIN STATUS"

$mdmPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker"
if (Test-Path $mdmPath) {
    Write-Output "  MDM BitLocker policy keys found at:"
    Write-Output "  $mdmPath"
    Write-Output ""
    $mdmProps = Get-ItemProperty -Path $mdmPath -ErrorAction SilentlyContinue
    $mdmProps.PSObject.Properties |
        Where-Object { $_.Name -notmatch "^PS" } |
        ForEach-Object {
            Write-Output ("  {0,-45}: {1}" -f $_.Name, $_.Value)
        }
} else {
    Write-Output "  No MDM/Intune BitLocker policy keys found."
    Write-Output "  Path checked: $mdmPath"
}

Write-Output ""

# Directory join status
$dsregExe = "$env:SystemRoot\System32\dsregcmd.exe"
if (Test-Path $dsregExe) {
    $dsreg      = & $dsregExe /status 2>$null
    $aadJoined  = ($dsreg | Select-String "AzureAdJoined\s*:\s*YES") -ne $null
    $domJoined  = ($dsreg | Select-String "DomainJoined\s*:\s*YES") -ne $null
    $aadStr     = if ($aadJoined) { "YES - Recovery keys may be escrowed to Entra ID / AAD" } else { "No" }
    $domStr     = if ($domJoined) { "YES - Recovery key may be backed up in Active Directory" } else { "No" }
    Write-Output "  Entra ID (AAD) Joined : $aadStr"
    Write-Output "  Domain Joined         : $domStr"
} else {
    Write-Output "  dsregcmd.exe not found - cannot determine join status."
}

# ============================================================
#  SECTION 6: SUMMARY TABLE
# ============================================================
Write-Section "SUMMARY"

Write-Output "  Host : $hostname"
Write-Output "  IP   : $privateIP"
Write-Output "  OS   : $osCaption  (Build $osBuild)"
Write-Output ""

if ($blModuleAvailable) {
    $allVols = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($allVols) {
        $col1 = "Drive"
        $col2 = "Protection"
        $col3 = "Volume Status"
        $col4 = "Enc Method / Pct"
        $col5 = "Key Protector Types"
        Write-Output ("  {0,-8}  {1,-12}  {2,-22}  {3,-20}  {4}" -f $col1,$col2,$col3,$col4,$col5)
        Write-Output ("  {0,-8}  {1,-12}  {2,-22}  {3,-20}  {4}" -f "-----","----------","-------------","----------------","-------------------")
        foreach ($v in $allVols) {
            if ($v.KeyProtector) {
                $kpTypes = ($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
            } else {
                $kpTypes = "None"
            }
            $encCol = "$($v.EncryptionMethod) $($v.EncryptionPercentage)%"
            Write-Output ("  {0,-8}  {1,-12}  {2,-22}  {3,-20}  {4}" -f `
                $v.MountPoint,
                $v.ProtectionStatus,
                $v.VolumeStatus,
                $encCol,
                $kpTypes)
        }
    } else {
        Write-Output "  No BitLocker volumes returned by Get-BitLockerVolume."
    }
} else {
    Write-Output "  BitLocker PS module unavailable - see per-volume WMI details above."
}

Write-Output ""
Write-Output "  Script completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("=" * 60)
