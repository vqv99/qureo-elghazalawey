@echo off
cd /d "d:\My_projects\E-business\new"

:: Find node
set "NODE=node"
if exist "C:\Program Files\nodejs\node.exe" set "NODE=C:\Program Files\nodejs\node.exe"
if exist "C:\Program Files (x86)\nodejs\node.exe" set "NODE=C:\Program Files (x86)\nodejs\node.exe"

:: Find npm
set "NPM=npm"
if exist "C:\Program Files\nodejs\npm.cmd" set "NPM=C:\Program Files\nodejs\npm.cmd"
if exist "C:\Program Files (x86)\nodejs\npm.cmd" set "NPM=C:\Program Files (x86)\nodejs\npm.cmd"

echo.
echo  =========================================
echo   QUREO Solver - Starting...
echo  =========================================
echo.

:: Install express if missing
if not exist "node_modules\express\index.js" (
    echo [..] Installing express...
    "%NPM%" install express
    echo [OK] express ready.
)

:: Kill anything on port 3000
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr /R ":3000 "') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Open browser after 2 seconds
start "" /b cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:3000"

echo [OK] Opening http://localhost:3000
echo.
echo  Press Ctrl+C to stop the server.
echo.

:: Start server (blocking - keeps window open)
"%NODE%" server.js

echo.
echo Server stopped.
pause
