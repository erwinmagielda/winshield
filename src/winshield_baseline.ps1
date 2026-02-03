<#
.SYNOPSIS
    WinShield Baseline

.DESCRIPTION
    Collects host baseline data used by the WinShield scanner.
    Emits a JSON object consumed by winshield_scanner.py.
#>

function Get-WinShieldLatestMsrcMonthId {

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop

        # Pull the ValidateSet from the Get-MsrcCvrfDocument -ID parameter
        $cmd  = Get-Command Get-MsrcCvrfDocument -ErrorAction Stop
        $attr = $cmd.Parameters['ID'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -First 1

        if (-not $attr -or -not $attr.ValidValues) { return $null }

        # Parse each MonthId into a sortable datetime
        $parsed = foreach ($id in $attr.ValidValues) {
            if (-not $id) { continue }

            $parts = $id -split '-', 2
            if ($parts.Count -ne 2) { continue }

            # ParseExact is case-sensitive for month abbreviations
            $normMonth = $parts[1].Substring(0,1).ToUpper() + $parts[1].Substring(1).ToLower()

            try {
                $dt = [datetime]::ParseExact(
                    "$($parts[0])-$normMonth",
                    'yyyy-MMM',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )

                [pscustomobject]@{ Id = $id; Date = $dt }
            } catch {
                
            }
        }

        if (-not $parsed) { return $null }

        # Return the newest MonthId by date
        return ($parsed | Sort-Object Date | Select-Object -Last 1).Id
    }
    catch {
        return $null
    }
}

function Get-WinShieldProductNameHint {

    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthId
    )

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop

        # OS name is taken from CIM.
        $os = Get-CimInstance Win32_OperatingSystem

        # Version/build metadata comes from CurrentVersion registry.
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

        # Determine family strictly, because downstream matching relies on it.
        $family = $null
        if ($os.Caption -like "*Windows 11*") { $family = "Windows 11" }
        elseif ($os.Caption -like "*Windows 10*") { $family = "Windows 10" }
        else { return $null }

        # DisplayVersion is preferred (22H2, 23H2, 24H2, etc).
        # ReleaseId is a fallback for older builds.
        $displayVersion = $cv.DisplayVersion
        if (-not $displayVersion) { $displayVersion = $cv.ReleaseId }

        # Normalise architecture into the MSRC FullProductName token format.
        # MSRC uses "x64-based Systems", "ARM64-based Systems", "32-bit Systems".
        $archToken = switch ($env:PROCESSOR_ARCHITECTURE) {
            'AMD64' { 'x64' }
            'ARM64' { 'ARM64' }
            'x86'   { '32-bit' }
            default { 'x64' }
        }

        # Pull the CVRF doc and resolve affected software rows.
        $doc = Get-MsrcCvrfDocument -ID $MonthId -ErrorAction Stop
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
        if (-not $aff) { return $null }

        # Extract unique Windows FullProductName entries.
        $windowsNames = $aff |
            Select-Object -ExpandProperty FullProductName -Unique |
            Where-Object { $_ -like "Windows *" } |
            Sort-Object

        if (-not $windowsNames) { return $null }

        # ------------------------------------------------------------
        # MATCH LADDER (DETERMINISTIC)
        # ------------------------------------------------------------

        # (1) Exact: family + version + arch
        if ($displayVersion) {
            $target = if ($archToken -eq '32-bit') {
                "$family Version $displayVersion for 32-bit Systems"
            } else {
                "$family Version $displayVersion for $archToken-based Systems"
            }

            $hit = $windowsNames | Where-Object { $_ -eq $target } | Select-Object -First 1
            if ($hit) { return $hit }
        }

        # (2) Fallback: family + arch (no version)
        $target = if ($archToken -eq '32-bit') {
            "$family for 32-bit Systems"
        } else {
            "$family for $archToken-based Systems"
        }

        $hit = $windowsNames | Where-Object { $_ -eq $target } | Select-Object -First 1
        if ($hit) { return $hit }

        # (3) Fallback: any family entry matching arch (pattern)
        if ($archToken -eq '32-bit') {
            $hit = $windowsNames | Where-Object { $_ -like "$family*32-bit*" } | Select-Object -First 1
        } else {
            $hit = $windowsNames | Where-Object { $_ -like "$family*$archToken-based*" } | Select-Object -First 1
        }

        if ($hit) { return $hit }

        # (4) Final fallback: first family entry (keeps output deterministic)
        return ($windowsNames | Where-Object { $_ -like "$family*" } | Select-Object -First 1)
    }
    catch {
        return $null
    }
}

# ============================================================
# OS IDENTITY
# ============================================================

# Registry provides edition + build components.
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

# CIM provides the OS caption (human-readable OS name).
$os = Get-CimInstance Win32_OperatingSystem

# Build is emitted as "CurrentBuild.UBR" to match how operators reason about patch level.
$buildString = "$($cv.CurrentBuild).$($cv.UBR)"

# Architecture normalisation is kept simple for baseline output.
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64' }
    'ARM64' { 'ARM64' }
    'x86'   { 'x86' }
    default { $env:PROCESSOR_ARCHITECTURE }
}

# ============================================================
# ELEVATION STATUS
# ============================================================

# WinShield checks elevation once because DISM-backed queries require admin.
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ============================================================
# LCU ANCHOR (ADMIN-ONLY)
# ============================================================

# These remain null when not elevated or when DISM access fails.
$lcuMonthId     = $null
$lcuPackageName = $null
$lcuInstallTime = $null

if ($isAdmin) {
    try {
        # RollupFix packages are used as the LCU anchor.
        # The newest InstallTime is treated as the current LCU month.
        $pkg = Get-WindowsPackage -Online |
            Where-Object { $_.PackageName -like "*RollupFix*" } |
            Sort-Object InstallTime -Descending |
            Select-Object -First 1

        if ($pkg) {
            $lcuPackageName = $pkg.PackageName
            $lcuInstallTime = $pkg.InstallTime
            $lcuMonthId     = (Get-Date $pkg.InstallTime).ToString("yyyy-MMM")
        }
    } catch {
        # Leave LCU fields null.
        # The scanner can decide whether to hard-fail or run degraded.
    }
}

# ============================================================
# MSRC RESOLUTION
# ============================================================

# Latest MonthId comes from the MSRC module’s advertised set.
$msrcLatestMonthId = Get-WinShieldLatestMsrcMonthId

# ProductNameHint is resolved against the latest MonthId to keep names current.
$productNameHint = $null
if ($msrcLatestMonthId) {
    $productNameHint = Get-WinShieldProductNameHint -MonthId $msrcLatestMonthId
}

# ============================================================
# OUTPUT
# ============================================================

# Emit a single JSON object to stdout.
# The scanner consumes stdout as the JSON payload, so no extra prints are allowed.
[pscustomobject]@{
    OsName            = $os.Caption
    OsEdition         = $cv.EditionID
    DisplayVersion    = $cv.DisplayVersion
    Build             = $buildString
    Architecture      = $arch
    IsAdmin           = $isAdmin

    LcuMonthId        = $lcuMonthId
    LcuPackageName    = $lcuPackageName
    LcuInstallTime    = $lcuInstallTime

    MsrcLatestMonthId = $msrcLatestMonthId
    ProductNameHint   = $productNameHint
} | ConvertTo-Json -Depth 4
