@echo off
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
chcp 65001 >nul
echo Starting SOC-NIDS Threat Command...
python -X utf8 -m streamlit run app.py
pause
