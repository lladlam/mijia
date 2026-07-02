$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonCommand = @()

if ($env:MIJIA_WEB_PYTHON) {
    $PythonCommand = @($env:MIJIA_WEB_PYTHON)
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonCommand = @("py", "-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCommand = @("python")
} else {
    throw "Python was not found. Please install Python 3.9 or newer and run this script again."
}

function Invoke-Python {
    param(
        [string[]]$CommandArgs
    )

    if ($PythonCommand.Length -gt 1) {
        & $PythonCommand[0] $PythonCommand[1..($PythonCommand.Length - 1)] @CommandArgs
    } else {
        & $PythonCommand[0] @CommandArgs
    }
}

$Port = if ($env:MIJIA_WEB_PORT) { $env:MIJIA_WEB_PORT } else { "8123" }
$HostAddress = if ($env:MIJIA_WEB_HOST) { $env:MIJIA_WEB_HOST } else { "127.0.0.1" }
$StateDir = if ($env:MIJIA_STATE_DIR) { $env:MIJIA_STATE_DIR } else { Join-Path $ProjectRoot ".mijia-server" }
$ProductionMode = $env:MIJIA_WEB_PRODUCTION -in @("1", "true", "TRUE", "True")

Write-Host ""
Write-Host "Mijia API Server is starting"
Write-Host ("URL: http://{0}:{1}" -f $HostAddress, $Port)
if ($ProductionMode) {
    Write-Host "Mode: production"
    Write-Host "State: hidden"
} else {
    Write-Host "Mode: api-only"
    Write-Host ("State: {0}" -f $StateDir)
}
Write-Host "Close this window or press Ctrl+C to stop the service"
Write-Host ""

$CommandArgs = @("-m", "mijiaAPI", "web", "--state_dir", $StateDir, "--host", $HostAddress, "--port", $Port)

Invoke-Python -CommandArgs $CommandArgs
