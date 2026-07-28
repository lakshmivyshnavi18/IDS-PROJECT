@echo off
echo ============================================================
echo   LLM Security Monitor - Activating Environment
echo ============================================================

REM Activate the virtual environment
call C:\ids_venv\Scripts\activate.bat

echo   Virtual environment: C:\ids_venv
echo   Python: %VIRTUAL_ENV%\Scripts\python.exe
echo.
echo   Available commands:
echo     python data\generation\dataset_generator.py  - Generate dataset
echo     python models\cnn_lstm\trainer.py cnn_lstm   - Train model
echo     python start.py                              - Launch all services
echo     uvicorn api.main:app --reload --port 8000    - API only
echo     streamlit run dashboard\app.py               - Dashboard only
echo     python testing\run_tests.py --mode all       - Run tests
echo     python experiments\ablation_study.py --all   - Ablation study
echo.
echo   Dashboard: http://localhost:8501
echo   API:       http://localhost:8000
echo   API Docs:  http://localhost:8000/docs
echo ============================================================
