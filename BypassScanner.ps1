# MC SS Super Scanner - Console Only
# Run as Administrator

$Findings = @()

function Add-Finding($Severity, $Type, $Path, $Evidence) {
    $script:Findings += [PSCustomObject]@{
        Time     = (Get-Date).ToString("HH:mm:ss")
        Severity = $Severity
        Type     = $Type
        Path     = $Path
        Evidence = $Evidence
    }
}

function Is-SafePath($FullPath) {
    $SafePaths = @(
        "C:\Windows",
        "C:\Program Files\Java",
        "C:\Program Files (x86)\Java",
        "C:\Program Files\Microsoft"
    )

    foreach ($safe in $SafePaths) {
        if ($FullPath.StartsWith($safe, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host " MC SS SUPER SCANNER - CONSOLE ONLY" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

$LauncherPaths = @(
    "$env:APPDATA\.minecraft",
    "$env:APPDATA\Feather Launcher",
    "$env:APPDATA\PrismLauncher",
    "$env:APPDATA\ModrinthApp",
    "$env:APPDATA\MultiMC",
    "$env:APPDATA\ATLauncher",
    "$env:APPDATA\Technic",
    "$env:APPDATA\.technic",
    "$env:USERPROFILE\.lunarclient",
    "$env:USERPROFILE\.badlion",
    "$env:LOCALAPPDATA\Packages",
    "$env:LOCALAPPDATA\Programs",
    "$env:LOCALAPPDATA\Feather Launcher",
    "$env:LOCALAPPDATA\ModrinthApp"
) | Where-Object { Test-Path $_ }

$SuspiciousPatterns = @(
    "fabric\.addMods",
    "\-Dfabric\.addMods",
    "C:\\Claude",
    "EdgeUpdate\\1\.3\.221\.3",
    "ferritecore",
    "bypass",
    "ghost",
    "cheat",
    "client",
    "loader",
    "hacked",
    "inject",
    "external"
)

$JvmConfigNames = @(
    "launcher_profiles.json",
    "options.txt",
    "settings.json",
    "config.json",
    "accounts.json",
    "instances.json",
    "instance.cfg",
    "mmc-pack.json",
    "launcher_log.txt",
    "latest.log"
)

Write-Host "[1/6] Checking Minecraft launcher configs and JVM arguments..." -ForegroundColor Yellow

foreach ($path in $LauncherPaths) {
    Get-ChildItem $path -Recurse -Force -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        $file = $_.FullName
        $name = $_.Name
        $hours = ((Get-Date) - $_.LastWriteTime).TotalHours

        $looksLikeJvmConfig =
            ($JvmConfigNames -contains $name) -or
            ($file -match "jvm|argument|launcher|profile|feather|prism|modrinth|lunar|multimc|technic|badlion")

        if ($looksLikeJvmConfig) {
            if ($hours -lt 12) {
                Add-Finding "HIGH" "Recent JVM/config change" $file "Modified $([math]::Round($hours,1))h ago; possible JVM args changed/removed"
            }
            elseif ($hours -lt 72) {
                Add-Finding "MEDIUM" "Recent launcher/config change" $file "Modified $([math]::Round($hours,1))h ago"
            }

            try {
                $content = Get-Content $file -Raw -ErrorAction Stop

                foreach ($pattern in $SuspiciousPatterns) {
                    if ($content -match $pattern) {
                        Add-Finding "HIGH" "Suspicious JVM/config content" $file "Matched pattern: $pattern"
                    }
                }
            } catch {}
        }
    }
}

Write-Host "[2/6] Checking known bypass/system hiding paths..." -ForegroundColor Yellow

$SuspiciousPaths = @(
    "C:\Claude",
    "C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.221.3"
)

foreach ($path in $SuspiciousPaths) {
    if (Test-Path $path) {
        Write-Host "[!] SUSPICIOUS PATH FOUND: $path" -ForegroundColor Red
        Add-Finding "HIGH" "Watched suspicious path exists" $path "Known/abused location exists"

        Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match "\.jar$|fabric|forge|mod|client|ghost|cheat|bypass|loader|ferritecore"
        } |
        ForEach-Object {
            Write-Host "   -> Suspicious file: $($_.FullName)" -ForegroundColor Red
            Add-Finding "HIGH" "Suspicious file inside watched path" $_.FullName "Minecraft/mod related file in unusual path"
        }
    }
}

Write-Host "[3/6] Checking PowerShell command history..." -ForegroundColor Yellow

$HistoryFiles = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
) | Where-Object { Test-Path $_ }

foreach ($hist in $HistoryFiles) {
    try {
        $content = Get-Content $hist -Raw -ErrorAction Stop

        if ($content -match "fsutil\s+usn\s+deletejournal") {
            Add-Finding "HIGH" "USN journal deletion command found" $hist "Anti-forensics command in PowerShell history"
        }

        foreach ($pattern in $SuspiciousPatterns) {
            if ($content -match $pattern) {
                Add-Finding "HIGH" "Suspicious command history" $hist "Matched pattern: $pattern"
            }
        }
    } catch {}
}

Write-Host "[4/6] Checking USN journal state..." -ForegroundColor Yellow

try {
    $usn = fsutil usn queryjournal C: 2>&1 | Out-String

    if ($usn -match "Error|not active|cannot find|is not active") {
        Add-Finding "MEDIUM" "USN journal suspicious state" "C:" "USN journal may be disabled/deleted"
    } else {
        Add-Finding "INFO" "USN journal present" "C:" "USN journal query succeeded"
    }
} catch {
    Add-Finding "INFO" "Could not query USN journal" "C:" $_.Exception.Message
}

Write-Host "[5/6] Checking Security Event Log for suspicious process execution..." -ForegroundColor Yellow

try {
    Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4688
        StartTime = (Get-Date).AddDays(-14)
    } -ErrorAction Stop |
    Where-Object {
        $_.Message -match "fsutil.exe|deletejournal|fabric\.addMods|C:\\Claude|EdgeUpdate\\1\.3\.221\.3|ferritecore"
    } |
    ForEach-Object {
        Add-Finding "HIGH" "Process execution evidence" "Security Event 4688" ($_.Message -replace "`r?`n", " ")
    }
} catch {
    Add-Finding "INFO" "Event log unavailable" "Security Event 4688" "Process creation logging may be disabled or inaccessible"
}

Write-Host "[6/6] Full C:\ scan for .jar files..." -ForegroundColor Yellow

Get-ChildItem "C:\" -Recurse -Force -Filter "*.jar" -ErrorAction SilentlyContinue |
Where-Object {
    -not (Is-SafePath $_.FullName)
} |
ForEach-Object {
    $file = $_.FullName
    $name = $_.Name
    $ageHours = ((Get-Date) - $_.LastWriteTime).TotalHours

    if ($name -match "client|ghost|cheat|bypass|fabric|forge|loader|ferrite|inject|external|hacked") {
        Add-Finding "HIGH" "Suspicious jar name" $file "Matched suspicious keyword"
    }
    elseif ($file -notmatch "\\mods\\") {
        Add-Finding "MEDIUM" "Jar outside mods folder" $file "JAR file found outside normal Minecraft mods folder"
    }

    if ($ageHours -lt 24) {
        Add-Finding "HIGH" "Recently modified jar" $file "Modified $([math]::Round($ageHours,1))h ago"
    }
    elseif ($ageHours -lt 72) {
        Add-Finding "MEDIUM" "Recently modified jar" $file "Modified $([math]::Round($ageHours,1))h ago"
    }
}

Write-Host ""
Write-Host "==================== RESULTS ====================" -ForegroundColor Cyan

if ($Findings.Count -eq 0) {
    Write-Host "No suspicious activity found." -ForegroundColor Green
} else {
    $Order = @{
        "HIGH"   = 1
        "MEDIUM" = 2
        "INFO"   = 3
    }

    $Sorted = $Findings | Sort-Object @{Expression = { $Order[$_.Severity] }}, Time

    foreach ($f in $Sorted) {
        switch ($f.Severity) {
            "HIGH"   { $color = "Red" }
            "MEDIUM" { $color = "Yellow" }
            default  { $color = "Gray" }
        }

        Write-Host ("[{0}] {1} | {2}" -f $f.Severity, $f.Type, $f.Path) -ForegroundColor $color
        Write-Host ("      -> {0}" -f $f.Evidence) -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "==================== SUMMARY ====================" -ForegroundColor Cyan

$high   = ($Findings | Where-Object Severity -eq "HIGH").Count
$medium = ($Findings | Where-Object Severity -eq "MEDIUM").Count
$info   = ($Findings | Where-Object Severity -eq "INFO").Count

Write-Host "HIGH:   $high"   -ForegroundColor Red
Write-Host "MEDIUM: $medium" -ForegroundColor Yellow
Write-Host "INFO:   $info"   -ForegroundColor Gray

Write-Host ""
Write-Host "Scan complete." -ForegroundColor Cyan