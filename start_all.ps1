# Starts the whole system: local blockchain -> contract deploy -> HTTPS backend.
# Usage (from any folder):   powershell -ExecutionPolicy Bypass -File D:\embedded\start_all.ps1
# Add -Webcam to also start the laptop-webcam camera simulator.
param([switch]$Webcam)

$root = $PSScriptRoot
$backend = Join-Path $root "backend"
$chain = Join-Path $root "blockchain"

function Wait-Port($port, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# 1. Blockchain node (own window, stays open)
if (Get-NetTCPConnection -LocalPort 8545 -State Listen -ErrorAction SilentlyContinue) {
    Write-Host "[1/3] Blockchain node already running on 8545" -ForegroundColor Yellow
} else {
    Write-Host "[1/3] Starting blockchain node..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.UI.RawUI.WindowTitle='1 - Blockchain'; cd '$chain'; npx hardhat node"
    if (-not (Wait-Port 8545 60)) { Write-Host "Blockchain node did not start - check the '1 - Blockchain' window." -ForegroundColor Red; exit 1 }
}

# 2. Deploy contract (node is in-memory, so deploy every start)
Write-Host "[2/3] Deploying IncidentLedger contract..." -ForegroundColor Cyan
Push-Location $chain
npx hardhat run scripts/deploy.js --network localhost
$ok = $LASTEXITCODE -eq 0
Pop-Location
if (-not $ok) { Write-Host "Contract deploy failed." -ForegroundColor Red; exit 1 }

# 3. Backend server (own window, stays open)
if (Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue) {
    Write-Host "[3/3] Something is already running on port 5000 - restart it so it uses the new contract." -ForegroundColor Yellow
} else {
    Write-Host "[3/3] Starting backend server..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.UI.RawUI.WindowTitle='3 - Server'; cd '$backend'; .\.venv\Scripts\python app.py"
    if (-not (Wait-Port 5000 60)) { Write-Host "Server did not start - check the '3 - Server' window for the error." -ForegroundColor Red; exit 1 }
}

$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi" -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
if (-not $ip) { $ip = "127.0.0.1" }
Write-Host ""
Write-Host "System is running." -ForegroundColor Green
Write-Host "Dashboard: https://${ip}:5000   (accept the certificate warning, log in as admin)"

if ($Webcam) {
    Write-Host "Starting webcam simulator..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.UI.RawUI.WindowTitle='4 - Webcam camera'; cd '$backend'; .\.venv\Scripts\python simulate_camera.py --webcam 0"
}
