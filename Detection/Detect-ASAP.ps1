<#
.SYNOPSIS
    Intune detection script for ASAP Utilities (Excel add-in) install/version compliance.

.DESCRIPTION
    Detects ASAP Utilities by scanning the machine-wide add-in (.xll) paths, per-user profile
    installs, and the Windows Uninstall registry entry. Normalizes and compares the detected
    version against an expected minimum. Writes structured JSON to stdout for auditability and
    returns exit codes Intune understands:

        Exit 0 → Compliant (installed version >= expected)
        Exit 1 → Needs remediation (missing, malformed version, comparison error, or outdated)

.PARAMETER AppDisplayName
    Friendly app name used for logging and registry matching. Consumed by:
    - Get-SafeFileName (default LogFile derivation)
    - Write-LogEntry (message prefix)
    - Get-RegistryAppEntries (when RegistryDisplayName not specified)
    - JSON output (AppName)
    - Main evaluation/summary messages

.PARAMETER MachinePaths
    One or more absolute paths OR path patterns (files or directories) searched in machine scope.
    Consumed by:
    - Machine scan section (enumerates candidates)
    - Get-FileVersionInfoSafe (version collection)
    - Write-LogEntry (scan/evaluation messages)

.PARAMETER PerUserRelativePaths
    One or more relative paths under C:\Users\<profile> resolved in SYSTEM context.
    Consumed by:
    - Get-PerUserAppPaths (resolves candidates across profiles)
    - Per-user scan section (iterates returned file paths)
    - Get-FileVersionInfoSafe (version collection)
    - Write-LogEntry (scan/evaluation messages)

.PARAMETER ExpectedVersion
    Minimum acceptable version string used to decide compliance (installed >= expected).
    Consumed by:
    - Compare-Versions (evaluation)
    - Main evaluation loop (compliant/outdated determination)
    - JSON output (ExpectedVersion)

.PARAMETER RegistryDisplayName
    Display name substring for Uninstall registry scanning (defaults to AppDisplayName).
    Consumed by:
    - Get-RegistryAppEntries (filters entries)
    - Registry scan section (DisplayVersion collection)
    - Write-LogEntry (registry hit messages)

.PARAMETER UseMachineScan
    Feature toggle for machine scan.
    Consumed by:
    - Main scan section (guards the machine-scan block)

.PARAMETER UsePerUserScan
    Feature toggle for per-user scan.
    Consumed by:
    - Main scan section (guards the per-user-scan block)

.PARAMETER UseRegistryScan
    Feature toggle for registry scan.
    Consumed by:
    - Main scan section (guards the registry-scan block)

.PARAMETER TriggerRemediationForMissingApp
    Controls exit code when nothing is found.
    Consumed by:
    - Post-scan “not found” branch
    - Final “no valid instances” branch
    (Determines whether script returns 1 to trigger remediation or 0.)

.PARAMETER MaxRetries
    Retry attempts for the main scan operation.
    Consumed by:
    - Invoke-OperationRetry (wrapping the entire scan phase)

.PARAMETER RetryDelay
    Delay (seconds) between scan retries.
    Consumed by:
    - Invoke-OperationRetry (between attempts)

.PARAMETER LogFile
    Optional path for log output. When `-EnableLogging` is true and `-LogFile` is not supplied
    the script derives a safe default at `Join-Path -Path $env:TEMP -ChildPath ("Detect-<SafeAppName>.log")`.
    Consumed by:
    - Write-LogEntry (file writing)
    - Get-SafeFileName (default path derivation)
    - Pre-scan directory creation

.PARAMETER MaxLogRetries
    Attempts to write a log entry if the file is temporarily locked.
    Consumed by:
    - Write-LogEntry (retry loop)

.PARAMETER LogRetryDelay
    Delay (seconds) between log write attempts.
    Consumed by:
    - Write-LogEntry (retry loop)

.PARAMETER VerboseMode
    Convenience switch: when present, sets VerbosePreference=Continue if -Verbose wasn’t provided.
    Consumed by:
    - Initial verbosity configuration for Write-Verbose calls throughout the script.
#>

[CmdletBinding(SupportsShouldProcess = $false)]
param (
    # AppDisplayName → Used by Get-SafeFileName (log path), Write-LogEntry prefixes, registry matching, JSON output
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AppDisplayName = "ASAP Utilities",

    # MachinePaths → Used by machine scan to enumerate candidate files; fed to Get-FileVersionInfoSafe and Write-LogEntry
    [Parameter()]
    [string[]]$MachinePaths = @(
        "${env:ProgramFiles(x86)}\ASAP Utilities\ASAP Utilities*.xll",
        "${env:ProgramW6432}\ASAP Utilities\ASAP Utilities*.xll"
    ),

    # PerUserRelativePaths → Resolved by Get-PerUserAppPaths; outputs file paths used by per-user scan + Get-FileVersionInfoSafe
    [Parameter()]
    [string[]]$PerUserRelativePaths = @(
        "AppData\Local\ASAP Utilities\ASAP Utilities*.xll"
    ),

    # ExpectedVersion → Compared in main evaluation via Compare-Versions; included in JSON output
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedVersion = "8.7",

    # RegistryDisplayName → Used by Get-RegistryAppEntries when UseRegistryScan is enabled; influences registry filtering
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RegistryDisplayName = "ASAP Utilities",

    # UseMachineScan → Controls inclusion of machine-scan block in main operation
    [switch]$UseMachineScan = $true,

    # UsePerUserScan → Controls inclusion of per-user-scan block in main operation
    [switch]$UsePerUserScan = $true,

    # UseRegistryScan → Controls inclusion of registry-scan block in main operation
    [switch]$UseRegistryScan = $true,

    # TriggerRemediationForMissingApp → Decides exit code (1 or 0) when no findings are present or after evaluation yields “NotInstalled”
    [bool]$TriggerRemediationForMissingApp = $false,

    # MaxRetries → Drives Invoke-OperationRetry around the main scan
    [int]$MaxRetries = 3,

    # RetryDelay → Delay used by Invoke-OperationRetry between scan attempts
    [int]$RetryDelay = 5,

    # LogFile → Path used by Write-Log; defaults via Get-SafeFileName(AppDisplayName)
    [string]$LogFile,

    # MaxLogRetries → Write-Log retry attempts
    [int]$MaxLogRetries = 5,

    # LogRetryDelay → Write-Log retry delay (seconds)
    [int]$LogRetryDelay = 2,

    # EnableLogging → when $true detection may write a local log; default is $false to remain read-only
    [bool]$EnableLogging = $false,

    # VerboseMode → Enables verbose flow without -Verbose; consumed by initial verbosity configuration
    [switch]$VerboseMode
)

# Honor either -Verbose (native) or -VerboseMode (compat)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# Require modern PowerShell and enable strict mode
#Requires -Version 5.1
Set-StrictMode -Version Latest

# ======================================================================
# Logging & Utilities
# ======================================================================

function Get-SafeFileName {
    <#
    PURPOSE
        Produces a Windows-safe filename from arbitrary text.

    USED BY
        - Default LogFile derivation (when -LogFile is omitted)
        - Ensures “Detect-<App>.log” path is valid

    DETAILS
        Replaces invalid characters, trims trailing dots/spaces, outputs “Application” if input is empty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    $clean = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# Derive default log path if not provided — only when logging is explicitly enabled
if ($PSBoundParameters.ContainsKey('LogFile') -and -not [string]::IsNullOrWhiteSpace($LogFile)) {
    # Use supplied LogFile
}
elseif ($EnableLogging) {
    $safeName = Get-SafeFileName -Name $AppDisplayName
    $LogFile = Join-Path -Path $env:TEMP -ChildPath ("Detect-$safeName.log")
}
else {
    $LogFile = $null
}

function Write-LogEntry {
    <#
    PURPOSE
        Writes verbose messages to console and persists to disk with retry handling.

    USED BY
        - All scan phases (machine, per-user, registry)
        - Evaluation outputs (malformed/outdated/compliant/missing)
        - Error/summary messages

    DETAILS
        Creates the log directory if needed; retries write operations up to MaxLogRetries with LogRetryDelay.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    Write-Verbose $Message

    if (-not $EnableLogging -or -not $LogFile) { return }

    $logDirectory = Split-Path -Path $LogFile -Parent
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        try { New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null } catch { Write-Verbose "Failed to create log directory ${logDirectory}: $_" }
    }

    for ($i = 1; $i -le $MaxLogRetries; $i++) {
        try {
            Add-Content -LiteralPath $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
            break
        }
        catch [System.IO.IOException] {
            if ($i -eq $MaxLogRetries) {
                Write-Verbose "Failed to write to log file after $MaxLogRetries attempts: $LogFile"
                throw
            }
            Start-Sleep -Seconds $LogRetryDelay
        }
        catch {
            Write-Verbose "Unexpected error writing to log: $_"
            break
        }
    }
}

function Invoke-OperationRetry {
    <#
    PURPOSE
        Wraps the MAIN SCAN (machine/per-user/registry) in a retry loop to mitigate transient enumeration/IO issues.

    USED BY
        - Main scan orchestration (one wrapped call)
        - Respects MaxRetries and RetryDelay

    DETAILS
        Logs each attempt; returns $true on success or $false after final failure.
    #>
    param (
        [Parameter(Mandatory = $true)][int]$MaxRetries,
        [Parameter(Mandatory = $true)][int]$RetryDelay,
        [Parameter(Mandatory = $true)][scriptblock]$Operation
    )
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-LogEntry "Attempt $i of $MaxRetries"
            & $Operation
            return $true
        }
        catch {
            Write-LogEntry "Attempt $i failed: $_"
            if ($i -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelay } else { return $false }
        }
    }
}

# ======================================================================
# Version Handling
# ======================================================================

function Format-Version {
    <#
    PURPOSE
        Normalizes version strings for consistent comparison (commas→dots, trims extras, extracts dotted numeric sequence).

    USED BY
        - Compare-Versions (pre-processing)
        - Main evaluation loop (validity check and normalization)

    DETAILS
        Ensures a 4-part dotted version by padding with zeros; returns “0” when no numeric pattern is found.
    #>
    [CmdletBinding()]
    param([string]$v)
    $v = ($v -replace ',', '.').Trim()
    if ($v -match '([0-9]+(?:\.[0-9]+)*)') { $v = $matches[1] } else { $v = '0' }
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}

function Compare-Versions {
    <#
    PURPOSE
        Compares installed vs expected by integer components (non-numeric components treated as 0).

    USED BY
        - Main evaluation loop (determines compliant/outdated)

    DETAILS
        Returns $true iff installed >= expected; otherwise $false. Handles variable component lengths safely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$InstalledVersion,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ExpectedVersion
    )

    $iv = Format-Version $InstalledVersion
    $ev = Format-Version $ExpectedVersion

    $a = $iv.Split('.') | ForEach-Object { $n = 0; [int]::TryParse($_, [ref]$n) | Out-Null; $n }
    $b = $ev.Split('.') | ForEach-Object { $n = 0; [int]::TryParse($_, [ref]$n) | Out-Null; $n }

    $max = [Math]::Max($a.Count, $b.Count)
    for ($i = 0; $i -lt $max; $i++) {
        $ai = if ($i -lt $a.Count) { $a[$i] } else { 0 }
        $bi = if ($i -lt $b.Count) { $b[$i] } else { 0 }
        if ($ai -gt $bi) { return $true }
        if ($ai -lt $bi) { return $false }
    }
    return $true
}

function Get-FileVersionInfoSafe {
    <#
    PURPOSE
        Reads ProductVersion/FileVersion from a file and normalizes commas/dots.

    USED BY
        - Machine scan (collects version from executables or enumerated files)
        - Per-user scan (collects version from user profile paths)

    DETAILS
        Falls back to FileVersion when ProductVersion is unavailable; trims and standardizes punctuation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    try {
        $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
        $version = $vi.ProductVersion
        if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
        return ($version -replace ',', '.').Trim()
    }
    catch { Write-Verbose "Failed to read version info for ${Path}: $_"; return '' }
}

# ======================================================================
# Scanners (Per-User & Registry)
# ======================================================================

function Get-PerUserAppPaths {
    <#
    PURPOSE
        Resolves one or more relative paths under C:\Users\<profile> for non-system profiles, returning candidate file paths.

    USED BY
        - Per-user scan block in main (iterates returned paths and calls Get-FileVersionInfoSafe)

    DETAILS
        Excludes default/system profiles; handles directories/wildcards by enumerating files when necessary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string[]]$RelativePaths,
        [string[]]$Exclusions = @('Public', 'Default', 'Default User', 'All Users', 'WDAGUtilityAccount')
    )
    if (-not $RelativePaths -or $RelativePaths.Count -eq 0) { return @() }
    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }

    $results = @()
    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $Exclusions -notcontains $_.Name } |
    ForEach-Object {
        $userHome = $_.FullName
        foreach ($rel in $RelativePaths) {
            $searchPath = Join-Path $userHome $rel
            try {
                if (Test-Path -LiteralPath $searchPath) {
                    $item = Get-Item -LiteralPath $searchPath -ErrorAction SilentlyContinue
                    if ($item -and $item.PSIsContainer) {
                        Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue |
                        ForEach-Object { $results += $_.FullName }
                    }
                    else {
                        $results += $searchPath
                    }
                }
                else {
                    Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue |
                    ForEach-Object { $results += $_.FullName }
                }
            }
            catch { Write-Verbose "Per-user path expansion failed for ${searchPath}: $_" }
        }
    }
    return $results
}

function Get-RegistryAppEntries {
    <#
    PURPOSE
        Scans Uninstall keys for entries whose DisplayName contains the given name and returns versions/locations.

    USED BY
        - Registry scan block in main (collects DisplayVersion and optional file references)

    DETAILS
        Reads HKLM/HKCU paths (including Wow6432Node); returns metadata used later in evaluation and logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$DisplayName
    )

    $roots = @(
        @{Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine' },
        @{Hive = 'HKLM'; Path = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine' },
        @{Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'User' }
    )

    $results = @()
    foreach ($r in $roots) {
        $base = "$($r.Hive):\$($r.Path)"
        try {
            Get-ChildItem -Path $base -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if (-not $props) { return }
                    $dn = $props.DisplayName
                    if (-not $dn) { return }
                    if ($dn -like "*$DisplayName*") {
                        $results += [pscustomobject]@{
                            RegistryPath    = $_.PSPath
                            DisplayName     = $dn
                            DisplayVersion  = $props.DisplayVersion
                            InstallLocation = $props.InstallLocation
                            DisplayIcon     = $props.DisplayIcon
                            Scope           = $r.Scope
                        }
                    }
                }
                catch { Write-Verbose "Failed reading uninstall key $($_.PSPath): $_" }
            }
        }
        catch { Write-Verbose "Failed enumerating registry root ${base}: $_" }
    }
    return $results
}

# ======================================================================
# Output Object (emitted as JSON)
# ======================================================================

$intuneOutput = @{
    AppName         = $AppDisplayName
    FilePath        = ""
    ExpectedVersion = $ExpectedVersion
    DetectedVersion = ""
    InstallScope    = ""
    Status          = "NotDetected"
}

# ======================================================================
# Main
# ======================================================================

try {
    # Ensure log directory exists (used by Write-LogEntry throughout)
    $logDir = Split-Path -Path $LogFile
    if ($logDir) { if (-not (Test-Path -LiteralPath $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } }

    # --- SCAN PHASE (wrapped with retries via Invoke-OperationRetry) ---
    $operationSucceeded = Invoke-OperationRetry -MaxRetries $MaxRetries -RetryDelay $RetryDelay -Operation {
        $found = $false
        $findings = @()

        # Machine scan (uses MachinePaths → Get-FileVersionInfoSafe → Write-LogEntry)
        if ($UseMachineScan -and $MachinePaths.Count > 0) {
            foreach ($path in $MachinePaths) {
                $candidates = @()
                try {
                    if (Test-Path -LiteralPath $path) {
                        $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                        if ($item -and $item.PSIsContainer) {
                            $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
                        }
                        else {
                            $candidates = @($path)
                        }
                    }
                    else {
                        $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
                    }
                }
                catch { Write-Verbose "Failed enumerating path ${path}: $_" }

                foreach ($candidate in $candidates) {
                    if (-not (Test-Path -LiteralPath $candidate)) { continue }
                    $found = $true
                    $rawVersion = Get-FileVersionInfoSafe -Path $candidate
                    Write-LogEntry "[$AppDisplayName] Machine version '$rawVersion' from '$candidate'"

                    $findings += [pscustomobject]@{
                        Source  = 'File'
                        Path    = $candidate
                        Version = $rawVersion
                        Scope   = 'Machine'
                    }
                }
            }
        }

        # Per-user scan (uses PerUserRelativePaths via Get-PerUserAppPaths → Get-FileVersionInfoSafe → Write-LogEntry)
        if ($UsePerUserScan -and $PerUserRelativePaths.Count > 0) {
            $perUserHits = Get-PerUserAppPaths -RelativePaths $PerUserRelativePaths
            foreach ($uPath in $perUserHits) {
                if (-not (Test-Path -LiteralPath $uPath)) { continue }
                $found = $true
                $rawVersion = Get-FileVersionInfoSafe -Path $uPath
                Write-LogEntry "[$AppDisplayName] User version '$rawVersion' from '$uPath'"

                $findings += [pscustomobject]@{
                    Source  = 'File'
                    Path    = $uPath
                    Version = $rawVersion
                    Scope   = 'User'
                }
            }
        }

        # Registry scan (uses RegistryDisplayName via Get-RegistryAppEntries → Write-LogEntry)
        if ($UseRegistryScan) {
            try {
                $regHits = Get-RegistryAppEntries -DisplayName $RegistryDisplayName
                foreach ($r in $regHits) {
                    $found = $true
                    $version = $r.DisplayVersion
                    Write-LogEntry "[$AppDisplayName] Registry '$($r.RegistryPath)' version '$version'"

                    $fileRef = $null
                    if ($r.DisplayIcon) { $fileRef = ($r.DisplayIcon -replace '\"') }
                    elseif ($r.InstallLocation) { $fileRef = $r.InstallLocation }

                    $findings += [pscustomobject]@{
                        Source        = 'Registry'
                        Path          = $r.RegistryPath
                        FileReference = $fileRef
                        Version       = $version
                        Scope         = if ($r.Scope -eq 'User') { 'UserRegistry' } else { 'MachineRegistry' }
                    }
                }
            }
            catch {
                Write-LogEntry "[$AppDisplayName] Registry scan failed: $_"
            }
        }

        if (-not $found) {
            Write-LogEntry "[$AppDisplayName] No file or registry entry found."
            throw "NotFound"
        }

        # Persist findings for evaluation phase
        Set-Variable -Name findings -Scope Script -Value $findings -Force
        return $true
    }

    # --- EVALUATION PHASE ---
    if (-not $operationSucceeded) {
        $intuneOutput.Status = "NotInstalled"
        Write-LogEntry "[$AppDisplayName] Not installed."
        $intuneOutput | ConvertTo-Json -Compress | Out-Host
        if ($TriggerRemediationForMissingApp) { exit 1 } else { exit 0 }
    }

    $firstMalformed = $null
    $firstOutdated = $null
    $firstCompliant = $null

    foreach ($f in $findings) {
        $raw = $f.Version
        $fmt = Format-Version $raw  # Format-Version used directly here

        if ([string]::IsNullOrWhiteSpace($raw) -or ($fmt -notmatch '^\d+(\.\d+)*$')) {
            if (-not $firstMalformed) { $firstMalformed = $f }
            continue
        }

        $isAtLeast = $false
        try { $isAtLeast = Compare-Versions -InstalledVersion $fmt -ExpectedVersion $ExpectedVersion } # Compare-Versions decides compliance
        catch { if (-not $firstMalformed) { $firstMalformed = $f }; continue }

        if (-not $isAtLeast) {
            if (-not $firstOutdated) { $firstOutdated = $f }
        }
        else {
            if (-not $firstCompliant) { $firstCompliant = $f }
        }
    }

    if ($firstMalformed) {
        $intuneOutput.FilePath = $firstMalformed.Path
        $intuneOutput.DetectedVersion = $firstMalformed.Version
        $intuneOutput.InstallScope = $firstMalformed.Scope
        $intuneOutput.Status = 'MalformedVersion'
        Write-LogEntry "[$AppDisplayName] Malformed version: $($firstMalformed.Path) => $($firstMalformed.Version)"
        $intuneOutput | ConvertTo-Json -Compress | Out-Host
        exit 1
    }

    if ($firstOutdated) {
        $intuneOutput.FilePath = $firstOutdated.Path
        $intuneOutput.DetectedVersion = $firstOutdated.Version
        $intuneOutput.InstallScope = $firstOutdated.Scope
        $intuneOutput.Status = if ($firstOutdated.Scope -like '*User*') { 'UserScopeOutdated' } else { 'Outdated' }
        Write-LogEntry "[$AppDisplayName] Outdated: $($firstOutdated.Path) => $($firstOutdated.Version)"
        $intuneOutput | ConvertTo-Json -Compress | Out-Host
        exit 1
    }

    if ($firstCompliant) {
        $intuneOutput.FilePath = $firstCompliant.Path
        $intuneOutput.DetectedVersion = $firstCompliant.Version
        $intuneOutput.InstallScope = $firstCompliant.Scope
        $intuneOutput.Status = 'Compliant'
        Write-LogEntry "[$AppDisplayName] Compliant: $($firstCompliant.Path) => $($firstCompliant.Version)"
        $intuneOutput | ConvertTo-Json -Compress | Out-Host
        exit 0
    }

    # No meaningful instances after evaluation
    $intuneOutput.Status = 'NotInstalled'
    Write-LogEntry "[$AppDisplayName] No valid instances detected after evaluation."
    $intuneOutput | ConvertTo-Json -Compress | Out-Host
    if ($TriggerRemediationForMissingApp) { exit 1 } else { exit 0 }

}
catch {
    $intuneOutput.Status = "Error"
    Write-LogEntry "[$AppDisplayName] Unexpected error: $_"
    $intuneOutput | ConvertTo-Json -Compress | Out-Host
    exit 1
}
