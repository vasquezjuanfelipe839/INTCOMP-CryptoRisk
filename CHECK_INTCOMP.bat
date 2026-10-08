@echo off
setlocal
cd /d "%~dp0"
title INTCOMP Check
where py >nul 2>&1 && (py -3 tools\check_intcomp.py & goto :end)
where python >nul 2>&1 && (python tools\check_intcomp.py & goto :end)
echo ERROR: Python not found.
pause
exit /b 1
:end
pause
endlocal
