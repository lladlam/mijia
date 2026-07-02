@echo off
setlocal enabledelayedexpansion
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

rem -- Single instance lock --
set "LOCK=%TEMP%\mijia-api-server-startup.lock"
if exist "%LOCK%" (
    echo Another startup is already running.
    timeout /t 5 /nobreak >nul
    exit /b 0
)
echo .>"%LOCK%"

rem -- Find Python --
set "PYTHON="
set "PYARGS="
for /f "delims=" %%p in ('where py 2^>nul') do (set "PYTHON=%%p" & set "PYARGS=-3" & goto :found)
for /f "delims=" %%p in ('where python 2^>nul') do (set "PYTHON=%%p" & set "PYARGS=" & goto :found)
for /f "delims=" %%p in ('where python3 2^>nul') do (set "PYTHON=%%p" & set "PYARGS=" & goto :found)

echo Python not found. Trying to install...
where winget >nul 2>nul
if %ERRORLEVEL% equ 0 (
    winget install --exact --id "Python.Python.3.11" --source winget --accept-package-agreements --accept-source-agreements --disable-interactivity --silent >nul 2>nul
    timeout /t 3 /nobreak >nul
    for /f "delims=" %%p in ('where py 2^>nul') do (set "PYTHON=%%p" & set "PYARGS=-3" & goto :found)
)

powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile '%TEMP%\python-installer.exe'" >nul 2>nul
if exist "%TEMP%\python-installer.exe" (
    "%TEMP%\python-installer.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_launcher=1 Include_test=0 Shortcuts=0
    del "%TEMP%\python-installer.exe" 2>nul
    timeout /t 3 /nobreak >nul
    for /f "delims=" %%p in ('where py 2^>nul') do (set "PYTHON=%%p" & set "PYARGS=-3" & goto :found)
)

echo Failed to install Python. Please install Python 3.9+ manually.
pause
del "%LOCK%" 2>nul
exit /b 1

:found
rem -- Run Python startup script --
set "STARTUP_PY=%ROOT%\_startup.py"
if not exist "%STARTUP_PY%" (
    echo Missing startup script: %STARTUP_PY%
    pause
    del "%LOCK%" 2>nul
    exit /b 1
)

"%PYTHON%" %PYARGS% "%STARTUP_PY%" "%ROOT%"
set "EC=%ERRORLEVEL%"

del "%LOCK%" 2>nul
exit /b %EC%
