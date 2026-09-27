@echo off
REM Starts both the backend (FastAPI/uvicorn) and frontend (Vite) dev servers,
REM each in its own console window. Assumes one-time setup is already done:
REM   backend\.venv exists with dependencies installed (pip install -r requirements.txt)
REM   frontend\node_modules exists (npm install)
REM See README.md if either of those hasn't been done yet.

cd /d "%~dp0"

start "Mail Analysis - backend (:8000)" cmd /k "cd backend && .venv\Scripts\activate && uvicorn app.main:app --reload"
start "Mail Analysis - frontend (:5173)" cmd /k "cd frontend && npm run dev"

echo Started backend (http://localhost:8000) and frontend (http://localhost:5173) in separate windows.
echo Closing these windows does NOT reliably stop the servers on Windows (their child
echo processes can keep running with the ports still bound) -- run stop.bat to shut both
echo down cleanly.
