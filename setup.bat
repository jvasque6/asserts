FOR /F "Tokens=*" %%x IN ('dir /b /S "build\dist\*.zip"') do (%PYTHON%\\python.exe pip install -U %%x)
