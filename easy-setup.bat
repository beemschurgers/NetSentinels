@echo off
echo Installing NetSentinel Dependencies in separate windows...
echo.

REM Launch Backend installation in a new window
start "NetSentinel - Backend Dependencies" cmd /k "cd /d backend && echo Installing Backend Dependencies (Python/Anaconda)... && conda create --name netsentinel --file requirements.txt && echo. && echo Backend dependencies installed successfully! && echo. && echo You can close this window when finished. && pause"

REM Launch Frontend installation in a new window
start "NetSentinel - Frontend Dependencies" cmd /k "cd /d frontend && echo Installing Frontend Dependencies (Node.js)... && npm install && echo. && echo Frontend dependencies installed successfully! && echo. && echo You can close this window when finished. && pause"

echo.
echo Installation processes have been started in separate windows.
echo You can monitor progress there. This window can now be closed.
echo.