@echo off
cd /d "%~dp0"
set NODE=
if exist "C:\Program Files\nodejs\node.exe" set NODE=C:\Program Files\nodejs\node.exe
if "%NODE%"=="" for /f "delims=" %%i in ('where node 2^>nul') do set NODE=%%i

echo Checking server.js syntax...
"%NODE%" --check server.js && echo [OK] server.js syntax is fine || echo [ERROR] server.js has syntax errors

echo Checking scripts...
"%NODE%" --check scripts\solver_core.js   && echo [OK] solver_core.js   || echo [ERROR] solver_core.js
"%NODE%" --check scripts\gov_js_first.js  && echo [OK] gov_js_first.js  || echo [ERROR] gov_js_first.js
"%NODE%" --check scripts\gov_js_second.js && echo [OK] gov_js_second.js || echo [ERROR] gov_js_second.js
"%NODE%" --check scripts\gov_py.js        && echo [OK] gov_py.js        || echo [ERROR] gov_py.js
"%NODE%" --check scripts\gov_fin.js       && echo [OK] gov_fin.js       || echo [ERROR] gov_fin.js

echo.
echo Done. Press any key to close.
pause
