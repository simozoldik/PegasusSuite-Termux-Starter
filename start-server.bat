@echo off
REM ============================================================
REM  Pegasus Suite - start the backend
REM  Listens on 0.0.0.0:8710 (reachable from the phone on the same Wi-Fi).
REM ============================================================
setlocal
cd /d "%~dp0backend"

echo [1/2] Checking Node dependencies...
if not exist "node_modules" (
  echo     running npm install...
  call npm install
  if errorlevel 1 ( echo npm install FAILED & pause & exit /b 1 )
)

echo [2/2] Starting backend on http://0.0.0.0:8710 ...
echo.
echo   Browser (PC)      : http://localhost:8710/
echo   Phone (same LAN)  : http://192.168.1.137:8710/
echo   API health        : http://localhost:8710/api/health
echo.
node src\server.js
pause
