# ============================================================
# run_all.ps1  — PowerShell launcher for LLM Security Monitor
# Usage: .\run_all.ps1
# ============================================================

$VENV = "C:\ids_venv\Scripts"
$PROJECT = $PSScriptRoot

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  LLM Security Monitor" -ForegroundColor White
Write-Host "  CNN-LSTM Behavioral Security Analysis" -ForegroundColor Gray
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Start FastAPI in a new window
Write-Host "  [1/2] Starting FastAPI backend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PROJECT'; C:\ids_venv\Scripts\uvicorn.exe api.main:app --reload --port 8000"

Start-Sleep -Seconds 4

# Start Streamlit in a new window
Write-Host "  [2/2] Starting Streamlit dashboard..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PROJECT'; C:\ids_venv\Scripts\streamlit.exe run dashboard/app.py --server.port 8501"

Write-Host ""
Write-Host "  ✓ Services started!" -ForegroundColor Green
Write-Host "  Dashboard : http://localhost:8501" -ForegroundColor White
Write-Host "  API       : http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs  : http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
