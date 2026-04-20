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

function Get-ListeningProcessId {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $listener) {
        return $null
    }

    return $listener.OwningProcess
}

function Clear-ListeningPort {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $listenerPid = Get-ListeningProcessId -Port $Port
    if (-not $listenerPid) {
        return
    }

    if ($listenerPid -eq $PID) {
        throw "Refusing to stop the current PowerShell process while clearing port $Port."
    }

    $listenerProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $listenerPid" -ErrorAction SilentlyContinue
    $listenerName = if ($listenerProcess -and $listenerProcess.Name) { $listenerProcess.Name } else { "PID $listenerPid" }

    Write-Host "Port $Port is in use by $listenerName ($listenerPid). Stopping it before launch..." -ForegroundColor Yellow

    try {
        Stop-Process -Id $listenerPid -Force -ErrorAction Stop
    } catch {
        $stillListening = Get-ListeningProcessId -Port $Port
        if ($stillListening) {
            throw
        }
    }

    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 250
        if (-not (Get-ListeningProcessId -Port $Port)) {
            return
        }
    }

    throw "Port $Port is still in use after stopping PID $listenerPid."
}

Set-Location $projectRoot
$env:CABTA_HOST = $BindHost
$env:CABTA_PORT = "$Port"

Clear-ListeningPort -Port $Port

if ($Foreground) {
    & $pythonPath -m src.web.run_local
    exit $LASTEXITCODE
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
