@echo off
setlocal

REM Determine project directory (this .bat's folder)
set "PROJECT_DIR=%~dp0"
set "VENV_DIR=%PROJECT_DIR%.venv"

echo.
echo === Resume Analyzer Launcher ===
echo Project: %PROJECT_DIR%

REM Create virtual environment if missing
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Creating virtual environment...
    py -3 -m venv "%VENV_DIR%" 2>NUL || python -m venv "%VENV_DIR%"
)

echo Installing dependencies (if needed)...
call "%VENV_DIR%\Scripts\pip.exe" install -r "%PROJECT_DIR%requirements.txt"

echo Starting application...
call "%VENV_DIR%\Scripts\python.exe" "%PROJECT_DIR%app.py"

endlocal