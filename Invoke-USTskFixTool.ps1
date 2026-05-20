#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads, extracts, and executes USTskFixTool.exe with the /fix argument,
    then outputs the resulting log file. Intended for RMM deployment as SYSTEM.

.NOTES
    Version : 1.0
    Run As  : Local System (SYSTEM) via RMM
#>

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$DownloadURL  = "https://www.dropbox.com/scl/fi/ovl51ehuex48n39p71m1k/USTskFixTool_1.0.2111.4.zip?download=1"
$WorkDir      = "C:\Windows\Temp"
$ZipPath      = Join-Path $WorkDir "USTskFixTool.zip"
$ExeName      = "USTskFixTool.exe"
$LogName      = "USTskFixTool.log"
$ExePath      = Join-Path $WorkDir $ExeName
$LogPath      = Join-Path $WorkDir $LogName

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Write-Output $line
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 – DOWNLOAD
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Starting USTskFixTool deployment."
Write-Log "Download URL : $DownloadURL"
Write-Log "Destination  : $ZipPath"

try {
    # Remove stale zip if present
    if (Test-Path $ZipPath) {
        Remove-Item $ZipPath -Force
        Write-Log "Removed existing zip at $ZipPath."
    }

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($DownloadURL, $ZipPath)

    if (-not (Test-Path $ZipPath)) {
        throw "Zip file not found after download attempt."
    }

    $zipSize = (Get-Item $ZipPath).Length
    Write-Log "Download complete. File size: $zipSize bytes."
}
catch {
    Write-Log "DOWNLOAD FAILED: $_" "ERROR"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 – EXTRACT
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Extracting zip to $WorkDir ..."

try {
    # Remove existing exe so we can verify fresh extraction
    if (Test-Path $ExePath) {
        Remove-Item $ExePath -Force
        Write-Log "Removed existing $ExeName."
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $WorkDir)

    if (-not (Test-Path $ExePath)) {
        # Fallback: exe might be in a sub-folder inside the zip; do a recursive search
        $found = Get-ChildItem -Path $WorkDir -Filter $ExeName -Recurse -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) {
            Move-Item -Path $found.FullName -Destination $ExePath -Force
            Write-Log "Moved $ExeName from sub-folder to $WorkDir."
        } else {
            throw "$ExeName not found anywhere after extraction."
        }
    }

    Write-Log "Extraction complete. Executable ready at $ExePath."
}
catch {
    Write-Log "EXTRACTION FAILED: $_" "ERROR"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 – EXECUTE
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Executing: $ExePath /fix"

# Remove any pre-existing log so we can confirm a fresh one was written
if (Test-Path $LogPath) {
    Remove-Item $LogPath -Force
    Write-Log "Removed pre-existing log at $LogPath."
}

try {
    $proc = Start-Process -FilePath $ExePath `
                          -ArgumentList "/fix" `
                          -WorkingDirectory $WorkDir `
                          -Wait `
                          -PassThru `
                          -NoNewWindow

    $exitCode = $proc.ExitCode
    Write-Log "Process exited with code: $exitCode."

    if ($exitCode -ne 0) {
        Write-Log "Non-zero exit code returned by $ExeName. Review the log below." "WARN"
    }
}
catch {
    Write-Log "EXECUTION FAILED: $_" "ERROR"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 – DISPLAY LOG
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Reading tool log: $LogPath"
Write-Output ""
Write-Output "═══════════════════════════════════════════════════════════════"
Write-Output "  USTskFixTool Log Output"
Write-Output "═══════════════════════════════════════════════════════════════"

if (Test-Path $LogPath) {
    $logContent = Get-Content -Path $LogPath -Raw
    if ([string]::IsNullOrWhiteSpace($logContent)) {
        Write-Output "(Log file exists but is empty.)"
    } else {
        Write-Output $logContent
    }
} else {
    Write-Output "(Log file not found at $LogPath — the tool may not have written one.)"
    Write-Log "Log file missing after execution." "WARN"
}

Write-Output "═══════════════════════════════════════════════════════════════"
Write-Output ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 – CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Cleaning up downloaded zip."
try {
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    Write-Log "Zip removed."
}
catch {
    Write-Log "Could not remove zip: $_" "WARN"
}

Write-Log "USTskFixTool deployment finished."
exit $exitCode
