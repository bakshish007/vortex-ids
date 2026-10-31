# AegisCampus IDS — PowerShell Native Launcher (Zero-Docker)
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " AegisCampus IDS — Native Bare-Metal Launcher (Zero-Docker)" -ForegroundColor Green
Write-Host " Problem Statement: CTBF-CS-03" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

$WorkspaceRoot = $PSScriptRoot

Write-Host "`n[1/3] Starting Backend API & Socket Hub on port 3001..." -ForegroundColor White
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$WorkspaceRoot\backend'; npm start"
Start-Sleep -Seconds 2

Write-Host "[2/3] Starting Next.js SOC Dashboard on port 3000..." -ForegroundColor White
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$WorkspaceRoot\frontend'; npm run dev"
Start-Sleep -Seconds 3

Write-Host "[3/3] Opening SOC Console in browser..." -ForegroundColor White
Start-Process "http://localhost:3000"

Write-Host "`nSystem online without Docker!" -ForegroundColor Green
Write-Host "SOC Console:          http://localhost:3000" -ForegroundColor Cyan
Write-Host "Backend API:          http://localhost:3001" -ForegroundColor Cyan
Write-Host "GUI Attacker Console: cd red-team; python attacker_gui.py" -ForegroundColor Yellow
Write-Host "CLI Attack Suite:     cd red-team; python simulate-attacks.py --all" -ForegroundColor Yellow

