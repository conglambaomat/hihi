param(
    [int]$Port = 3003,
    [string]$BindHost = "127.0.0.1",
    [switch]$Foreground
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
$stdoutLogPath = Join-Path $projectRoot "cabta-web.log"
$stderrLogPath = Join-Path $projectRoot "cabta-web.err.log"

if (-not (Test-Path $pythonPath)) {
    throw "Python venv not found at $pythonPath"
}

Set-Location $projectRoot
$env:CABTA_HOST = $BindHost
$env:CABTA_PORT = "$Port"

if ($Foreground) {
    & $pythonPath -m src.web.run_local
    exit $LASTEXITCODE
}

$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty OwningProcess

if ($existing) {
    Write-Host "Port $Port is already in use by PID $existing." -ForegroundColor Yellow
    Write-Host "Open http://$BindHost`:$Port if CABTA is already running, or stop that process first." -ForegroundColor Yellow
    exit 1
}

$process = Start-Process `
    -FilePath $pythonPath `
    -ArgumentList "-m", "src.web.run_local" `
    -WorkingDirectory $projectRoot `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutLogPath `
    -RedirectStandardError $stderrLogPath

Start-Sleep -Seconds 5

try {
    $response = Invoke-WebRequest -UseBasicParsing "http://$BindHost`:$Port/api/config/info" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "CABTA web is running at http://$BindHost`:$Port (PID $($process.Id))" -ForegroundColor Green
        Write-Host "Stdout log: $stdoutLogPath"
        Write-Host "Stderr log: $stderrLogPath"
        exit 0
    }
} catch {
    Write-Host "CABTA process started (PID $($process.Id)), but health check did not return 200 yet." -ForegroundColor Yellow
    Write-Host "Check stdout log: $stdoutLogPath"
    Write-Host "Check stderr log: $stderrLogPath"
    exit 1
}
