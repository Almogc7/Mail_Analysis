@echo off
REM Stops the Mail Analysis dev servers by killing whatever is listening on their ports.
REM Needed because closing the console windows start.bat opens does NOT reliably terminate
REM the uvicorn --reload / npm run dev child processes on Windows -- verified directly:
REM force-closing those windows left both servers running with their ports still bound.
REM This targets the actual listening sockets instead, which is reliable regardless of how
REM many child/grandchild processes uvicorn's reloader or npm spawned underneath.

setlocal enabledelayedexpansion
set STOPPED=0

for %%P in (8000 5173) do (
    for /f "tokens=5" %%A in ('netstat -ano ^| findstr ":%%P " ^| findstr "LISTENING"') do (
        echo Stopping process %%A on port %%P...
        taskkill /F /T /PID %%A >nul 2>&1
        set STOPPED=1
    )
)

if !STOPPED! == 1 (
    echo Done.
) else (
    echo Nothing was listening on :8000 or :5173.
)
