param(
    [int]$Port = 3003,
    [string]$BindHost = "127.0.0.1",
    [switch]$Foreground,
    [switch]$EnableTunnel,
    [switch]$NoTunnel
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspaceRoot = Split-Path -Parent $projectRoot
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
$stdoutLogPath = Join-Path $projectRoot "cabta-web.log"
$stderrLogPath = Join-Path $projectRoot "cabta-web.err.log"
$ngrokStdoutLogPath = Join-Path $projectRoot "ngrok.log"
$ngrokStderrLogPath = Join-Path $projectRoot "ngrok.err.log"
$chatPath = "/agent/chat"

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

function Get-NgrokPath {
    $pathCommand = Get-Command "ngrok" -ErrorAction SilentlyContinue
    if ($pathCommand -and $pathCommand.Source) {
        return $pathCommand.Source
    }

    $workspaceLocalNgrok = Join-Path $workspaceRoot ".tmp-tunnel\ngrok.exe"
    if (Test-Path $workspaceLocalNgrok) {
        return $workspaceLocalNgrok
    }

    return $null
}

function Get-NgrokPublicUrl {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    try {
        $tunnels = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -TimeoutSec 3
        $matchingTunnel = $tunnels.tunnels |
            Where-Object {
                $_.proto -eq "https" -and
                ($_.config.addr -eq "http://localhost:$Port" -or
                 $_.config.addr -eq "http://127.0.0.1:$Port" -or
                 $_.config.addr -eq "http://$BindHost`:$Port" -or
                 $_.config.addr -like "*:$Port")
            } |
            Select-Object -First 1

        if (-not $matchingTunnel) {
            $matchingTunnel = $tunnels.tunnels |
                Where-Object { $_.proto -eq "https" } |
                Select-Object -First 1
        }

        if ($matchingTunnel -and $matchingTunnel.public_url) {
            return $matchingTunnel.public_url
        }
    } catch {
        return $null
    }

    return $null
}

function Start-NgrokTunnel {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $existingPublicUrl = Get-NgrokPublicUrl -Port $Port
    if ($existingPublicUrl) {
        Write-Host "Using existing ngrok tunnel: $existingPublicUrl$chatPath" -ForegroundColor Green
        return $existingPublicUrl
    }

    $ngrokPath = Get-NgrokPath
    if (-not $ngrokPath) {
        Write-Host "ngrok was not found. Install ngrok on PATH or place ngrok.exe at .tmp-tunnel\ngrok.exe." -ForegroundColor Yellow
        Write-Host "AISA web remains available locally at http://$BindHost`:$Port$chatPath" -ForegroundColor Yellow
        return $null
    }

    Write-Host "Starting ngrok tunnel for http://$BindHost`:$Port ..." -ForegroundColor Cyan
    $ngrokProcess = Start-Process `
        -FilePath $ngrokPath `
        -ArgumentList "http", "$Port", "--log", "stdout" `
        -WorkingDirectory $workspaceRoot `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $ngrokStdoutLogPath `
        -RedirectStandardError $ngrokStderrLogPath

    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        $publicUrl = Get-NgrokPublicUrl -Port $Port
        if ($publicUrl) {
            Write-Host "ngrok tunnel is running at $publicUrl (PID $($ngrokProcess.Id))" -ForegroundColor Green
            return $publicUrl
        }
    }

    Write-Host "ngrok started (PID $($ngrokProcess.Id)), but its public URL was not available yet." -ForegroundColor Yellow
    Write-Host "Check ngrok stdout log: $ngrokStdoutLogPath"
    Write-Host "Check ngrok stderr log: $ngrokStderrLogPath"
    return $null
}

Set-Location $projectRoot
$env:CABTA_HOST = $BindHost
$env:CABTA_PORT = "$Port"

Clear-ListeningPort -Port $Port

if ($EnableTunnel -and -not $NoTunnel) {
    $publicUrl = Start-NgrokTunnel -Port $Port
    if ($publicUrl) {
        Write-Host "Public AISA chat URL: $publicUrl$chatPath" -ForegroundColor Green
    }
} else {
    Write-Host "Skipping ngrok tunnel. Pass -EnableTunnel to start ngrok." -ForegroundColor Yellow
}

if ($Foreground) {
    Write-Host "Starting AISA web in the foreground at http://$BindHost`:$Port$chatPath" -ForegroundColor Cyan
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
        Write-Host "AISA web is running at http://$BindHost`:$Port (PID $($process.Id))" -ForegroundColor Green
        Write-Host "Local AISA chat URL: http://$BindHost`:$Port$chatPath" -ForegroundColor Green
        if ($EnableTunnel -and -not $NoTunnel) {
            $publicUrl = Get-NgrokPublicUrl -Port $Port
            if ($publicUrl) {
                Write-Host "Public AISA chat URL: $publicUrl$chatPath" -ForegroundColor Green
            } else {
                Write-Host "Public AISA chat URL is not available yet. Check ngrok logs or http://127.0.0.1:4040." -ForegroundColor Yellow
            }
        }
        Write-Host "Stdout log: $stdoutLogPath"
        Write-Host "Stderr log: $stderrLogPath"
        exit 0
    }
} catch {
    Write-Host "CABTA process started (PID $($process.Id)), but health check did not return 200 yet." -ForegroundColor Yellow
    Write-Host "Local AISA chat URL may become available at http://$BindHost`:$Port$chatPath" -ForegroundColor Yellow
    if ($EnableTunnel -and -not $NoTunnel) {
        $publicUrl = Get-NgrokPublicUrl -Port $Port
        if ($publicUrl) {
            Write-Host "Public AISA chat URL: $publicUrl$chatPath" -ForegroundColor Green
        }
    }
    Write-Host "Check stdout log: $stdoutLogPath"
    Write-Host "Check stderr log: $stderrLogPath"
    exit 1
}
