@echo off
setlocal

REM Start the frontend (Next.js) in a new window
start "Frontend Dev Server" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"

REM Start the backend using the existing elevated script
pushd "%~dp0backend"
call start.bat
popd

endlocal
exit /b 0