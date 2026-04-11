@echo off
REM NKS WDC Catalog API — local dev launcher (Windows)
REM Creates a venv in .venv, installs deps, and runs uvicorn on :8765.

setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [catalog-api] Creating virtualenv...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo [catalog-api] Failed to create venv. Is Python 3.11+ installed?
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"

echo [catalog-api] Installing / updating dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo [catalog-api] Starting uvicorn on http://127.0.0.1:8765
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload
endlocal
