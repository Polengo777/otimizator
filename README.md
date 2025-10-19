@echo off
setlocal enabledelayedexpansion
title Instalador do Painel de Otimizacao do Windows

echo ===========================================================
echo         PAINEL DE OTIMIZACAO DO WINDOWS - INSTALADOR
echo ===========================================================
echo.

:: 1) Verificar se Python ja esta instalado
where python >nul 2>nul
if %errorlevel%==0 (
    echo [OK] Python ja instalado.
) else (
    echo [INFO] Python nao encontrado. Instalando Python 3.12...
    powershell -Command ^
     "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe -OutFile $env:TEMP\python_installer.exe"
    echo.
    echo [INFO] Iniciando instalacao silenciosa do Python...
    start /wait "" "%TEMP%\python_installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    if %errorlevel% NEQ 0 (
        echo [ERRO] Falha ao instalar Python. Verifique a conexao e tente novamente.
        pause
        exit /b
    )
)

:: 2) Garantir que o Python esteja no PATH
set "PATH=%PATH%;C:\Python312;C:\Python312\Scripts;C:\Program Files\Python312;C:\Program Files\Python312\Scripts"

echo.
echo [INFO] Instalando bibliotecas necessarias (PyQt5, psutil, requests)...
python -m pip install --upgrade pip
python -m pip install pyqt5 psutil requests >nul 2>nul

if %errorlevel% NEQ 0 (
    echo [ERRO] Nao foi possivel instalar as dependencias.
    pause
    exit /b
)

:: 3) Criar pasta de destino
set "DEST=%USERPROFILE%\Desktop\Otimizador_Windows"
if not exist "%DEST%" mkdir "%DEST%"

:: 4) Baixar o painel Python (substitua o link abaixo pelo seu)
echo.
echo [INFO] Baixando o painel de otimizacao...
powershell -Command ^
 "Invoke-WebRequest -Uri 'https://gist.githubusercontent.com/Polengo777/0211ae883d4aba24e1e1905586020826/raw/2a3b9959e15806661ca1475c2398ca63616383c5/OTIMIZA%25C3%2587AO' -OutFile '%DEST%\Painel_Otimizacao_Windows.py'"

if not exist "%DEST%\Painel_Otimizacao_Windows.py" (
    echo [ERRO] Falha ao baixar o script. Verifique o link.
    pause
    exit /b
)

:: 5) Criar atalho de execucao rapida
echo Criando atalho...
echo @echo off > "%DEST%\IniciarPainel.bat"
echo python "%DEST%\Painel_Otimizacao_Windows.py" >> "%DEST%\IniciarPainel.bat"

:: 6) Executar o painel
echo.
echo [OK] Instalacao concluida! Iniciando o painel...
cd /d "%DEST%"
start "" "%DEST%\IniciarPainel.bat"

echo.
echo ===========================================================
echo Otimizador instalado com sucesso!
echo Arquivos: %DEST%
echo ===========================================================
pause
exit /b
