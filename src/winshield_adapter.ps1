<#
.SYNOPSIS
    WinShield Adapter

.DESCRIPTION
    Pulls and aggregates MSRC CVRF data for a specific product across one or more MonthIds
    Emits a JSON object consumed by winshield_scanner.py.
#>

# Declare script parameters
param(
    # One or more MonthIds
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    # ProductNameHint must match MSRC FullProductName exactly
    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)

# ============================================================
# INPUT NORMALISATION
# ============================================================

# MonthIds normalisation ("2025-Dec","2026-Jan" or "2025-Dec,2026-Jan")
$MonthIds = @(
    $MonthIds |
        ForEach-Object { ($_ -split ",") } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
) | Sort-Object -Unique

# If required inputs are missing, emit a JSON error object
if (-not $MonthIds -or -not $ProductNameHint) {
    [pscustomobject]@{
        Error           = "Usage: winshield_adapter.ps1 -MonthIds <list> -ProductNameHint <name>"
        MonthIds        = $MonthIds
        ProductNameHint = $ProductNameHint
    } | ConvertTo-Json -Depth 5
    exit 1
}

# ============================================================
# MODULE DEPENDENCY
# ============================================================

# MsrcSecurityUpdates is required for CVRF retrieval and parsing helpers
try {
    Import-Module MsrcSecurityUpdates -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}

# ============================================================
# AGGREGATION MAP
# ============================================================

# KB aggregation map
$kbMap = @{}

# ============================================================
# PER-MONTH PROCESSING
# ============================================================

foreach ($month in $MonthIds) {

    try {
        # Pull CVRF document for the month
        $doc = Get-MsrcCvrfDocument -ID $month -ErrorAction Stop

        # Resolve affected software rows containing FullProductName, KBArticle, CVE, Supercedence, etc.
        $aff = Get-MsrcCvrfAffectedSoftware -Vulnerability $doc.Vulnerability -ProductTree $doc.ProductTree
    } catch {
        continue
    }

    # If the month has no affected software rows, nothing to do
    if (-not $aff) { continue }

    # ============================================================
    # EXACT PRODUCT MATCH
    # ============================================================

    # Baseline selects an exact FullProductName
    $rows = $aff | Where-Object { $_.FullProductName -eq $ProductNameHint }
    if (-not $rows) { continue }

    foreach ($row in $rows) {

        # ============================================================
        # CVE NORMALISATION
        # ============================================================

        # Normalise into a flat array so JSON output is stable
        $cveList = @()
        if ($row.CVE) {
            $cveList = @($row.CVE)
        }

        # ============================================================
        # SUPERSEDENCE NORMALISATION
        # ============================================================

        # Container for superseded KBs
        $supersedes = @()

        # Extract supersedence KB IDs
        if ($row.Supercedence) {
            foreach ($s in @($row.Supercedence)) {
                if ($null -eq $s) { continue }
                if ([string]$s -match '(\d{4,7})') {
                    $supersedes += "KB$($Matches[1])"
                }
            }
        }
        $supersedes = $supersedes | Sort-Object -Unique

        # ============================================================
        # KB AGGREGATION
        # ============================================================

        # KBArticle may be a single object or a list
        foreach ($kbObj in @($row.KBArticle)) {
            if (-not $kbObj -or -not $kbObj.ID) { continue }

            $kb = if ($kbObj.ID -like 'KB*') {
                $kbObj.ID
            } else {
                'KB' + $kbObj.ID
            }

            # Create the KB entry on first sighting
            if (-not $kbMap.ContainsKey($kb)) {
                $kbMap[$kb] = [pscustomobject]@{
                    KB         = $kb
                    Months     = @()
                    Cves       = @()
                    Supersedes = @()
                }
            }

            # Merge month if not already present.
            if ($kbMap[$kb].Months -notcontains $month) {
                $kbMap[$kb].Months += $month
            }

            # Merge CVEs uniquely
            foreach ($c in $cveList) {
                if ($c -and $kbMap[$kb].Cves -notcontains $c) {
                    $kbMap[$kb].Cves += $c
                }
            }

            # Merge supersedence uniquely
            foreach ($s in $supersedes) {
                if ($s -and $kbMap[$kb].Supersedes -notcontains $s) {
                    $kbMap[$kb].Supersedes += $s
                }
            }
        }
    }
}

# ============================================================
# OUTPUT
# ============================================================

# The scanner consumes stdout as the JSON payload, so no extra prints are allowed
[pscustomobject]@{
    ProductNameHint = $ProductNameHint
    MonthIds        = $MonthIds
    KbEntries       = @(
        $kbMap.GetEnumerator() |
            ForEach-Object { $_.Value } |
            Sort-Object KB
    )
} | ConvertTo-Json -Depth 10
