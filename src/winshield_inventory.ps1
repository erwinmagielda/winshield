<#
.SYNOPSIS
    WinShield Inventory

.DESCRIPTION
    Collects locally installed KB identifiers using Get-HotFix and Get-WindowsPackage.
    Emits a JSON object consumed by winshield_scanner.py.
#>

function Get-WinShieldInventory {

    # ============================================================
    # ELEVATION STATUS
    # ============================================================

    # Determine if the current session is running with admin privileges
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent() 
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # ============================================================
    # PRIMARY INVENTORY: GET-HOTFIX
    # ============================================================

    # Container for KB IDs from Get-HotFix
    $hotFixKbs = @()

    # Attempt to get installed HotFixes
    try {
        $hotFixKbs = Get-HotFix |
            Where-Object { $_.HotFixID -match '^KB\d+$' } |
            Select-Object -ExpandProperty HotFixID |
            Sort-Object -Unique
    } catch {
        # If Get-HotFix fails, keep empty
        $hotFixKbs = @()
    }

    # ============================================================
    # SECONDARY INVENTORY: GET-WINDOWSPACKAGE
    # ============================================================

    # Container for KB IDs from Get-WindowsPackage
    $packageKbs = @()

    if ($isAdmin) {
        try {
            $packageKbs = @(
                Get-WindowsPackage -Online |
                    ForEach-Object {

                        # Primary: extract KB from PackageName
                        if ($_.PackageName -match 'KB(\d{4,7})') {
                            "KB$($Matches[1])"
                        }

                        # Fallback: extract KB from Description
                        elseif ($_.Description -match 'KB(\d{4,7})') {
                            "KB$($Matches[1])"
                        }
                    } |
                    Sort-Object -Unique
            )
        } catch {
            # If Get-WindowsPackage fails, keep empty
            $packageKbs = @()
        }
    }

    # ============================================================
    # MERGE AND NORMALISE
    # ============================================================

    # Merge both sources into a single stable set
    $allInstalledKbs = @($hotFixKbs + $packageKbs) | Sort-Object -Unique

    # Emit a stable JSON shape
    [pscustomobject]@{
        IsAdmin         = $isAdmin
        HotFixKbs       = $hotFixKbs
        PackageKbs      = $packageKbs
        AllInstalledKbs = $allInstalledKbs
    }
}

# ============================================================
# SCRIPT ENTRY GUARD
# ============================================================

# When executed directly, emit JSON to stdout for the scanner
if ($MyInvocation.InvocationName -ne '.') { # 
    Get-WinShieldInventory | ConvertTo-Json -Depth 3
}
