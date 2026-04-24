# TeslaProBypassDetection
# Run as Administrator

$ScannerName = "TeslaProBypassDetection"
$Findings = @()

function Relaunch-AsAdmin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Clear-Host
        Write-Host "========================================" -ForegroundColor Red
        Write-Host " $ScannerName" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "[!] Run as Administrator required." -ForegroundColor Yellow
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}

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
    $Safe = @("C:\Windows","C:\Program Files\Java","C:\Program Files (x86)\Java")
    foreach ($s in $Safe) {
        if ($FullPath.StartsWith($s)) { return $true }
    }
    return $false
}

function Header {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " $ScannerName" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Step($t){ Write-Host "`n[*] $t" -ForegroundColor Yellow }

Relaunch-AsAdmin
Header

# --- ACTIVE SESSION ---
Step "Checking active Minecraft process..."

$mc = Get-CimInstance Win32_Process -Filter "name = 'javaw.exe'" -ErrorAction SilentlyContinue

if ($mc) {
    Write-Host "[!] Minecraft is running!" -ForegroundColor Green
    foreach ($p in $mc) {
        Write-Host "`nArgs:" -ForegroundColor Yellow
        Write-Host $p.CommandLine -ForegroundColor DarkYellow

        if ($p.CommandLine -match "fabric\.addMods|C:\\Claude|\.jar") {
            Add-Finding "HIGH" "Live JVM args detected" "PID $($p.ProcessId)" $p.CommandLine
        }
    }
} else {
    Write-Host "[i] No active javaw.exe found." -ForegroundColor Gray
}

# --- LAUNCHER PROFILE ---
Step "Checking launcher_profiles.json..."

$lp = "$env:APPDATA\.minecraft\launcher_profiles.json"
if (Test-Path $lp) {
    try {
        $json = Get-Content $lp -Raw | ConvertFrom-Json
        foreach ($p in $json.profiles.PSObject.Properties) {
            $args = $p.Value.javaArgs
            if ($args) {
                Write-Host "[+] $($p.Value.name): $args" -ForegroundColor Yellow
                Add-Finding "MEDIUM" "Custom JVM args" $lp $args

                if ($args -match "fabric\.addMods|C:\\Claude") {
                    Add-Finding "HIGH" "Suspicious JVM args" $lp $args
                }
            }
        }
    } catch {}
}

# --- LAUNCHERS ---
Step "Scanning all popular launchers..."

$Paths = @(
"$env:APPDATA\.minecraft","$env:APPDATA\PrismLauncher","$env:APPDATA\ModrinthApp",
"$env:APPDATA\MultiMC","$env:APPDATA\CurseForge","$env:USERPROFILE\.lunarclient"
) | Where {Test-Path $_}

foreach ($p in $Paths) {
    Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        if ($_.Name -match "json|cfg|log") {
            try {
                $c = Get-Content $_.FullName -Raw
                if ($c -match "fabric\.addMods|C:\\Claude") {
                    Add-Finding "HIGH" "Launcher config hit" $_.FullName "Suspicious pattern"
                }
            } catch {}
        }
    }
}

# --- PATH CHECK ---
Step "Checking known bypass paths..."

$Sus = @("C:\Claude","C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.221.3")

foreach ($p in $Sus) {
    if (Test-Path $p) {
        Write-Host "[!] FOUND: $p" -ForegroundColor Red
        Add-Finding "HIGH" "Suspicious path exists" $p "Known bypass path"

        Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue |
        Where {$_.Name -match "\.jar"} |
        ForEach-Object {
            Add-Finding "HIGH" "Jar in suspicious path" $_.FullName "Hidden mod"
        }
    }
}

# --- HISTORY ---
Step "Checking command history..."

$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $hist) {
    $c = Get-Content $hist -Raw
    if ($c -match "fsutil usn deletejournal") {
        Add-Finding "HIGH" "USN wipe detected" $hist "Anti-forensics"
    }
}

# --- JAR SCAN ---
Step "Scanning entire C:\ for .jar..."

Get-ChildItem "C:\" -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue |
Where { -not (Is-SafePath $_.FullName) } |
ForEach-Object {
    if ($_.FullName -notmatch "\\mods\\") {
        Add-Finding "MEDIUM" "External jar" $_.FullName "Outside mods"
    }
}

# --- RESULTS ---
Write-Host "`n======== RESULTS ========" -ForegroundColor Cyan

if ($Findings.Count -eq 0) {
    Write-Host "Clean." -ForegroundColor Green
} else {
    foreach ($f in $Findings) {
        $c = if ($f.Severity -eq "HIGH") {"Red"} elseif ($f.Severity -eq "MEDIUM") {"Yellow"} else {"Gray"}
        Write-Host "[$($f.Severity)] $($f.Type)" -ForegroundColor $c
        Write-Host " -> $($f.Path)" -ForegroundColor White
    }
}

# --- SUMMARY ---
$high = ($Findings | ? Severity -eq "HIGH").Count
$med  = ($Findings | ? Severity -eq "MEDIUM").Count

Write-Host "`n======== SUMMARY ========" -ForegroundColor Cyan
Write-Host "HIGH: $high" -ForegroundColor Red
Write-Host "MEDIUM: $med" -ForegroundColor Yellow

if ($high -gt 0) {
    Write-Host "VERDICT: BYPASS LIKELY" -ForegroundColor Red
} elseif ($med -gt 0) {
    Write-Host "VERDICT: CHECK FURTHER" -ForegroundColor Yellow
} else {
    Write-Host "VERDICT: CLEAN" -ForegroundColor Green
}

Pause