$ErrorActionPreference = "Stop"
if (!(Test-Path ".\venv")) { Write-Host "No venv found. Run reset_backend.ps1 first."; exit 1 }

.\venv\Scripts\Activate.ps1
$env:PYTHONPATH = (Get-Location).Path
python -m uvicorn backend.main:app --reload
