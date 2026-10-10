@echo off
setlocal
cd /d "%~dp0"
title INTCOMP Tests
where py >nul 2>&1 && (py -3 tools\run_tests.py & goto :end)
where python >nul 2>&1 && (python tools\run_tests.py & goto :end)
echo ERROR: Python not found.
pause
exit /b 1
:end
pause
endlocal
