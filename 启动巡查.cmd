@echo off
cd /d "%~dp0"

where /q python
if errorlevel 1 goto nopython

python -c "import requests, websocket, PIL"
if errorlevel 1 (
  echo.
  echo 首次运行，正在安装依赖，请稍候...
  python -m pip install -r requirements.txt
  if errorlevel 1 goto pipfail
)

where /q pythonw
if errorlevel 1 (
  start "" python gui.pyw
) else (
  start "" pythonw gui.pyw
)
exit /b 0

:nopython
echo.
echo 未检测到 Python 3。
echo 请安装 Python 3.9 或更高版本，安装时勾选 "Add python.exe to PATH"：
echo   https://www.python.org/downloads/
echo.
start "" https://www.python.org/downloads/
pause
exit /b 1

:pipfail
echo.
echo 依赖安装失败，请检查网络后重试，或手动运行：
echo   python -m pip install -r requirements.txt
echo.
pause
exit /b 1
