@echo off
echo Installing Python dependencies for VAPT Analysis...
pip install streamlit pandas requests reportlab python-docx openai anthropic google-genai
echo.
echo Setup complete! You can now run the app using run.bat
pause