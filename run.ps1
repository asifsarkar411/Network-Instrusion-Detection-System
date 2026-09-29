$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host "Starting SOC-NIDS Threat Command..." -ForegroundColor Cyan
python -X utf8 -m streamlit run app.py
