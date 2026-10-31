@echo off
title AegisCampus IDS — Native Launcher
echo ======================================================================
echo  AegisCampus IDS — Native Bare-Metal Launcher (Zero-Docker)
echo  Problem Statement: CTBF-CS-03
echo ======================================================================
echo.

cd /d "%~dp0"

echo [1/3] Starting Backend API & Socket Hub on port 3001...
start "Aegis Backend (Port 3001)" cmd /k "cd backend && npm start"
timeout /t 2 /nobreak >nul

echo [2/3] Starting Next.js SOC Dashboard on port 3000...
start "Aegis SOC Console (Port 3000)" cmd /k "cd frontend && npm run dev"
timeout /t 3 /nobreak >nul

echo [3/3] Opening SOC Console in default browser...
start http://localhost:3000

echo.
echo ======================================================================
echo  All services launched natively without Docker!
echo  SOC Console:   http://localhost:3000
echo  Backend API:   http://localhost:3001
echo.
echo  To run attack simulation:
echo    GUI Attacker Console: cd red-team && python attacker_gui.py
echo    CLI Headless Suite:   cd red-team && python simulate-attacks.py --all
echo ======================================================================
pause

