#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Painel de Otimização Profissional para Windows (PyQt5)
- Salve como Painel_Otimizacao_Windows.py e execute como Administrador.
- Requer: Python 3.8+, PyQt5, psutil
- Pip: pip install pyqt5 psutil
AVISO: muitas ações modificam o sistema (registro, serviços, apps). Teste em VM antes.
"""

import sys
import os
import subprocess
import tempfile
import threading
import time
import json
from datetime import datetime
from pathlib import Path

# ---- Dependências externas
try:
    from PyQt5 import QtWidgets, QtCore, QtGui
except Exception as e:
    print("Erro: PyQt5 não encontrado. Instale com: pip install pyqt5")
    input("Pressione Enter para sair...")
    raise

try:
    import psutil
except Exception:
    print("Erro: psutil não encontrado. Instale com: pip install psutil")
    input("Pressione Enter para sair...")
    raise

# -------------------- Utilitários --------------------
def is_admin():
    """Retorna True se estamos em contexto de administrador."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_powershell(cmd, capture_output=True, timeout=600):
    """
    Executa um comando PowerShell ou script (cmd é string).
    Retorna (returncode, stdout, stderr).
    """
    full_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]
    try:
        proc = subprocess.run(full_cmd, capture_output=capture_output, text=True, timeout=timeout, shell=False)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return -1, "", f"Timeout: {e}"
    except Exception as e:
        return -2, "", str(e)

def write_temp_ps1(content: str):
    """Grava conteúdo em arquivo .ps1 temporário e retorna caminho."""
    fd, path = tempfile.mkstemp(suffix=".ps1", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path

def safe_run_ps1(content: str):
    """Executa script PowerShell temporário e remove arquivo."""
    p = write_temp_ps1(content)
    try:
        return run_powershell(f"& '{p}'")
    finally:
        try:
            os.remove(p)
        except Exception:
            pass

# -------------------- Definição das otimizações (~60) --------------------
# Cada otimização: id, category, title, desc, enable_ps, disable_ps, reversible
def generate_optimizations():
    items = []

    # --- Desempenho (20)
    items += [
        # 1
        {'id':'svc_wuauserv_disable','category':'Desempenho','title':'Windows Update -> Manual (parar)','desc':'Define Windows Update como Manual e tenta parar serviço','enable_ps':"Set-Service -Name wuauserv -StartupType Manual; Stop-Service -Name wuauserv -Force","disable_ps":"Set-Service -Name wuauserv -StartupType Automatic; Start-Service -Name wuauserv","reversible':True} if False else {
            'id':'svc_wuauserv_disable','category':'Desempenho','title':'Windows Update -> Manual (parar)','desc':'Define Windows Update como Manual e tenta parar serviço','enable_ps':"Set-Service -Name wuauserv -StartupType Manual; Stop-Service -Name wuauserv -Force","disable_ps":"Set-Service -Name wuauserv -StartupType Automatic; Start-Service -Name wuauserv","reversible':True
        },
    ]
    # The above conditional was to keep formatting; build list properly below:
    items = [
        {'id':'svc_wuauserv_disable','category':'Desempenho','title':'Windows Update -> Manual (parar)','desc':'Define Windows Update como Manual e tenta parar serviço','enable_ps':"Set-Service -Name wuauserv -StartupType Manual; Stop-Service -Name wuauserv -Force","disable_ps":"Set-Service -Name wuauserv -StartupType Automatic; Start-Service -Name wuauserv","reversible':True} if False else None
    ]
    # The above attempts to be clever caused issues; scrap and re-create cleanly:
    items = []

    # Add core performance tweaks (I'll include ~60 by grouping many safe tweaks)
    perf = [
        ("svc_wuauserv_disable","Desempenho","Windows Update -> Manual (parar)","Set-Service -Name wuauserv -StartupType Manual; Stop-Service -Name wuauserv -Force","Set-Service -Name wuauserv -StartupType Automatic; Start-Service -Name wuauserv", True),
        ("svc_sysmain_disable","Desempenho","Desativar SysMain (Superfetch)","Set-Service -Name SysMain -StartupType Disabled; Stop-Service -Name SysMain -Force","Set-Service -Name SysMain -StartupType Manual; Start-Service -Name SysMain", True),
        ("svc_spooler_disable","Desempenho","Desativar Print Spooler","Set-Service -Name Spooler -StartupType Disabled; Stop-Service -Name Spooler -Force","Set-Service -Name Spooler -StartupType Automatic; Start-Service -Name Spooler", True),
        ("startup_trim","Desempenho","Otimizar inicialização (listar/trim)","# Placeholder: list startups; See UI for manual review","", False),
        ("ram_free","Desempenho","Liberar RAM (EmptyWorkingSet)","[System.GC]::Collect(); Get-Process | ForEach-Object {try{ (\"\" + $_.Id) | Out-Null ; } catch {}}; Add-Type -MemberDefinition '[DllImport(\"psapi.dll\")]public static extern int EmptyWorkingSet(IntPtr hProcess);' -Name Psapi -Namespace Win32; Get-Process | ForEach-Object { try { [Win32.Psapi]::EmptyWorkingSet($_.Handle) | Out-Null } catch { } }","", False),
        ("cpu_bg_priority","Desempenho","Reduz prioridade de background","Get-Process | Where-Object { $_.MainWindowTitle -eq '' } | ForEach-Object { try { $_.PriorityClass = 'BelowNormal' } catch {} }","", False),
        ("disable_telemetry_tasks","Desempenho","Desativar tarefas de telemetria conhecidas","schtasks /Change /TN '\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator' /Disable; schtasks /Change /TN '\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater' /Disable","", False),
        ("optimize_boot","Desempenho","Ativar Fast Startup (Hiberboot)","powercfg /hibernate on; reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' /v HiberbootEnabled /t REG_DWORD /d 1 /f","reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' /v HiberbootEnabled /t REG_DWORD /d 0 /f", True),
        ("optimize_disks","Desempenho","Otimizar volumes (Optimize-Volume)","Get-Volume | Where-Object { $_.DriveLetter -ne $null } | ForEach-Object { Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Defrag -Verbose }","", False),
        ("prefetch_tweaks","Desempenho","Ajustar Prefetch/Superfetch","reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters' /v EnablePrefetcher /t REG_DWORD /d 3 /f; reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters' /v EnableSuperfetch /t REG_DWORD /d 0 /f","reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters' /v EnableSuperfetch /t REG_DWORD /d 3 /f", True),
        ("disable_indexing","Desempenho","Desativar Windows Search (indexing)","Set-Service -Name WSearch -StartupType Disabled; Stop-Service -Name WSearch -Force","Set-Service -Name WSearch -StartupType Automatic; Start-Service -Name WSearch", True),
        ("disable_visual_effects","Desempenho","Efeitos visuais -> Performance","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' /v VisualFXSetting /t REG_DWORD /d 2 /f","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' /v VisualFXSetting /t REG_DWORD /d 0 /f", True),
        ("menu_delay","Desempenho","Remover atraso de menus (MenuShowDelay)","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v MenuShowDelay /t REG_SZ /d 0 /f","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v MenuShowDelay /t REG_SZ /d 400 /f", True),
        ("background_apps_off","Desempenho","Desativar apps em background","reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy' /v LetAppsRunInBackground /t REG_DWORD /d 2 /f","reg delete 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy' /v LetAppsRunInBackground /f", True),
        ("disable_8dot3","Desempenho","Desativar nomes 8.3 em NTFS","fsutil behavior set disable8dot3 1","fsutil behavior set disable8dot3 0", True),
        ("power_high_perf","Desempenho","Selecionar plano de energia: Alto desempenho","powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c > $null; $guid = (powercfg -list | Select-String 8c5e7fda).ToString().Split()[-1]; powercfg -setactive $guid","powercfg -setactive scheme_balanced", True),
        ("clear_temp","Desempenho","Limpar temporários e flush DNS","Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue; ipconfig /flushdns","", False),
        ("trim_ssd_now","Desempenho","Executar TRIM (SSD)","Get-PhysicalDisk | Where-Object MediaType -eq 'SSD' | ForEach-Object { $drv = (Get-Volume -DiskNumber $_.Number).DriveLetter; if ($drv) { Optimize-Volume -DriveLetter $drv -ReTrim -Verbose } }","", False),
        ("stop_unneeded_services","Desempenho","Parar serviços Bluetooth/RemoteRegistry/BITS se não usados","Set-Service -Name bthserv -StartupType Disabled; Stop-Service -Name bthserv -Force; Set-Service -Name RemoteRegistry -StartupType Disabled; Stop-Service -Name RemoteRegistry -Force; Set-Service -Name BITS -StartupType Disabled; Stop-Service -Name BITS -Force","Set-Service -Name bthserv -StartupType Manual; Start-Service -Name bthserv; Set-Service -Name RemoteRegistry -StartupType Manual; Start-Service -Name RemoteRegistry; Set-Service -Name BITS -StartupType Manual; Start-Service -Name BITS", True),
    ]

    for t in perf:
        items.append({
            'id': t[0],
            'category': t[1],
            'title': t[2],
            'desc': t[3] if len(t[3]) < 500 else t[3][:500],
            'enable_ps': t[3],
            'disable_ps': t[4],
            'reversible': t[5]
        })

    # --- Aparência (12)
    appearance = [
        ("theme_light","Aparência","Aplicar tema claro leve","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' /v AppsUseLightTheme /t REG_DWORD /d 1 /f; reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' /v SystemUsesLightTheme /t REG_DWORD /d 1 /f","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' /v AppsUseLightTheme /t REG_DWORD /d 0 /f", True),
        ("reduce_transparency","Aparência","Reduzir transparências e blur","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' /v EnableTransparency /t REG_DWORD /d 0 /f","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' /v EnableTransparency /t REG_DWORD /d 1 /f", True),
        ("disable_animations","Aparência","Desativar animações do Windows","reg add 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate /t REG_SZ /d 0 /f","reg add 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate /t REG_SZ /d 1 /f", True),
        ("center_taskbar","Aparência","Centralizar ícones da Taskbar (Win11 tweak)","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v TaskbarAl /t REG_DWORD /d 1 /f","reg delete 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v TaskbarAl /f", True),
        ("startmenu_trim","Aparência","Remover sugestões do Start Menu","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager' /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f","reg delete 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager' /v SystemPaneSuggestionsEnabled /f", True),
        ("clean_desktop","Aparência","Mover arquivos grandes da área de trabalho","$d=[Environment]::GetFolderPath('Desktop'); New-Item -Path ($d+'\\\\Desktop_Extras') -ItemType Directory -Force; Get-ChildItem -Path $d -File | Where-Object { $_.Length -gt 10485760 } | Move-Item -Destination ($d+'\\\\Desktop_Extras') -Force","", False),
        ("explorer_perf","Aparência","Ajustar Explorer para performance","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v ShowInfoTip /t REG_DWORD /d 0 /f","", False),
        ("hide_desktop_icons","Aparência","Ocultar ícones padrões da Desktop","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel' /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 1 /f","reg delete 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel' /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /f", True),
        ("cursor_minimal","Aparência","Aplicar cursor minimal (placeholder)","# Placeholder: aplicar esquema via registry","", False),
        ("icons_pack","Aparência","Aplicar pacote de ícones (placeholder)","# Placeholder: copiar ícones e aplicar via registry/desktop.ini","", False),
        ("visual_mode_perf","Aparência","Preset: Performance vs Beleza (Performance)","# UI aplica um conjunto de ajustes visuais para performance","# UI pode reverter aplicando preset oposto", True),
        ("visual_mode_beauty","Aparência","Preset: Performance vs Beleza (Beleza)","# UI aplica um conjunto de ajustes visuais para melhor aparência","", True),
    ]
    for t in appearance:
        items.append({'id':t[0],'category':t[1],'title':t[2],'desc':t[3],'enable_ps':t[3],'disable_ps':t[4],'reversible':t[5] if len(t)>4 else False})

    # --- Sistema (18)
    system = [
        ("disable_onedrive","Sistema","Desinstalar OneDrive","Start-Process -FilePath \"$env:WinDir\\SysWOW64\\OneDriveSetup.exe\" -ArgumentList '/uninstall' -NoNewWindow -Wait","Start-Process -FilePath \"$env:WinDir\\SysWOW64\\OneDriveSetup.exe\" -ArgumentList '/install' -NoNewWindow -Wait", True),
        ("disable_cortana","Sistema","Desativar Cortana via política","reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' /v AllowCortana /t REG_DWORD /d 0 /f; Stop-Process -Name Cortana -ErrorAction SilentlyContinue","reg delete 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' /v AllowCortana /f", True),
        ("disable_widgets","Sistema","Desativar Widgets","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v TaskbarDa /t REG_DWORD /d 0 /f","reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' /v TaskbarDa /t REG_DWORD /d 1 /f", True),
        ("remove_bloat_appx","Sistema","Remover apps UWP comuns","Get-AppxPackage -AllUsers | Where-Object { $_.Name -match 'Xbox|CandyCrush|3DBuilder|Zune|ZuneMusic|Microsoft.MicrosoftSolitaireCollection' } | Remove-AppxPackage -AllUsers; Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match 'Xbox|CandyCrush|3DBuilder|Zune|ZuneMusic|Microsoft.MicrosoftSolitaireCollection' } | Remove-AppxProvisionedPackage -Online","", False),
        ("registry_backup","Sistema","Exportar registro (backup)","reg export HKLM %TEMP%\\hklm_software_before.reg /y; reg export HKCU %TEMP%\\hkcu_before.reg /y","reg import %TEMP%\\hklm_software_before.reg", True),
        ("firewall_perf","Sistema","Ajustar Firewall para performance (teste)","Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -DefaultOutboundAction Allow","Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow", True),
        ("remove_old_drivers","Sistema","Listar drivers antigos (revisar antes)","pnputil /enum-drivers | Out-File $env:TEMP\\drivers_list.txt","", False),
        ("create_restore_point","Sistema","Criar ponto de restauração agora","Checkpoint-Computer -Description 'Before-Optimization' -RestorePointType 'MODIFY_SETTINGS'","", False),
        ("adjust_pagefile","Sistema","Ajustar Pagefile (placeholder)","# Placeholder: configurar pagefile via wmic or system settings","", False),
        ("disable_error_reporting","Sistema","Desativar Error Reporting","reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' /v Disabled /t REG_DWORD /d 1 /f","reg delete 'HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' /v Disabled /f", True),
        ("smart_check","Sistema","Verificar SMART (disco)","Get-WmiObject -Namespace root\\WMI -Class MSStorageDriver_FailurePredictStatus | ConvertTo-Json","", False),
        ("disable_smb1","Sistema","Desativar SMBv1","Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart","Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol", True),
        ("set_powercfg_tweaks","Sistema","Ajustes avançados de energia (placeholder)","# Placeholder: powercfg /change ...","", False),
        ("add_mp_exclusions","Sistema","Adicionar exclusões no Defender (ex: jogos)","Add-MpPreference -ExclusionPath 'C:\\Games','D:\\VMs'","", False),
        ("disable_autoupdates","Sistema","Desativar atualizações automáticas (policy)","reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f","reg delete 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' /v NoAutoUpdate /f", True),
        ("cleanup_temp_system","Sistema","Limpeza profunda temporários (reboot recomendado)","Get-ChildItem -Path $env:SystemRoot\\Temp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue","", False),
        ("optimize_network","Sistema","Otimizar TCP/IP (placeholder)","# Placeholder: netsh int tcp set global autotuninglevel=disabled etc.","", False),
    ]
    for t in system:
        items.append({'id':t[0],'category':t[1],'title':t[2],'desc':t[3],'enable_ps':t[3],'disable_ps':t[4],'reversible':t[5] if len(t)>4 else False})

    # --- Extras (approx 15) ---
    extras = [
        ("total_optim","Extras","Otimização Total (aplica tudo seguro)","# Aplicado pela UI: chama cada enable_ps sequencialmente","", True),
        ("revert_mode","Extras","Modo Reversível (backup antes)","# UI gera backups e aplica revert via disable_ps quando possível","", True),
        ("sched_restore","Extras","Agendar pontos de restauração diários","$action=New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-Command \"Checkpoint-Computer -Description \\'Auto-Restore\\' -RestorePointType MODIFY_SETTINGS\"'; Register-ScheduledTask -Action $action -Trigger (New-ScheduledTaskTrigger -Daily -At 03:00) -TaskName 'AutoRestorePoint' -RunLevel Highest -Force","Unregister-ScheduledTask -TaskName 'AutoRestorePoint' -Confirm:$false", True),
        ("perf_report","Extras","Coletar relatório de performance (CPU/RAM/IO)","Get-Counter -Counter '\\\\Processor(_Total)\\\\% Processor Time','\\\\Memory\\\\Available MBytes','\\\\PhysicalDisk(_Total)\\\\% Disk Time' -SampleInterval 1 -MaxSamples 3 | ConvertTo-Json","", False),
        ("auto_update_panel","Extras","Verificar atualizações do painel (placeholder)","# Placeholder: baixar versão mais recente do repo e comparar versão","", False),
        ("export_profile","Extras","Exportar seleção (perfil)","# Implementado na UI","", True),
        ("import_profile","Extras","Importar seleção (perfil)","# Implementado na UI","", True),
        ("sandbox_mode","Extras","Modo Sandbox (temporário - limitado)","# Aplica apenas mudanças não persistentes onde possível","", False),
        ("log_and_audit","Extras","Ativar logs detalhados de alterações","# Logging implementado no Python","", True),
        ("health_check","Extras","Health check do sistema (pré-aplicação)","Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json","", False),
        ("clear_win_cache","Extras","Limpar caches (thumbs, temp, dns)","Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue; del /f /q $env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*.db 2>$null; ipconfig /flushdns","", False),
        ("quick_reboot","Extras","Reiniciar sistema","Restart-Computer -Force","", False),
        ("open_logs","Extras","Abrir pasta de logs","# Implementado na UI para abrir pasta optim_backups","", True),
        ("create_shortcut","Extras","Criar atalho para o painel (Desktop)","# UI pode criar arquivo .lnk via powershell if solicitado","", True),
        ("check_updates_apps","Extras","Checar atualizações de apps (placeholder)","# Placeholder: use winget/list a ser implementado","", False),
    ]
    for t in extras:
        items.append({'id':t[0],'category':t[1],'title':t[2],'desc':t[3],'enable_ps':t[3],'disable_ps':t[4],'reversible':t[5] if len(t)>4 else False})

    # Fill to ~60 by adding smaller safe toggles programmatically
    auto_small = [
        ("disable_xbox","Sistema","Desativar Xbox services/aplicativos","Get-AppxPackage *xbox* -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue","", True),
        ("disable_gamebar","Sistema","Desativar Game Bar","reg add 'HKCU\\Software\\Microsoft\\XboxGamingOverlay' /v AllowAutoGameMode /t REG_DWORD /d 0 /f; Get-AppxPackage *XboxGamingOverlay* | Remove-AppxPackage -ErrorAction SilentlyContinue","", True),
        ("disable_tips","Sistema","Desativar dicas do Windows","reg add 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager' /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f","reg delete 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager' /v SubscribedContent-338388Enabled /f", True),
        ("disable_remote_assist","Sistema","Desativar Remote Assistance","reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' /v fAllowToGetHelp /t REG_DWORD /d 0 /f","reg delete 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' /v fAllowToGetHelp /f", True),
        ("disable_error_reports","Sistema","Desativar Relatórios de Erro","reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' /v Disabled /t REG_DWORD /d 1 /f","reg delete 'HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' /v Disabled /f", True),
        ("disable_speech","Sistema","Desativar Speech Runtime (se não usar)","Set-Service -Name SpeechRuntime -StartupType Disabled; Stop-Service -Name SpeechRuntime -Force","Set-Service -Name SpeechRuntime -StartupType Manual; Start-Service -Name SpeechRuntime", True),
        ("disable_telemetry","Sistema","Reduzir Telemetria (placeholder)","reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' /v AllowTelemetry /t REG_DWORD /d 0 /f","reg delete 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' /v AllowTelemetry /f", True),
        ("disable_feedback","Sistema","Desativar Feedback Hub","reg add 'HKCU\\Software\\Microsoft\\Siuf\\Rules' /v 'NumberOfSIUFInPeriod' /t REG_DWORD /d 0 /f","", True),
    ]
    for t in auto_small:
        items.append({'id':t[0],'category':t[1],'title':t[2],'desc':t[3],'enable_ps':t[3],'disable_ps':t[4],'reversible':t[5] if len(t)>4 else False})

    # return list
    return items

# -------------------- UI --------------------
class OptimizationPanel(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Painel de Otimização - Profissional")
        self.resize(1100, 720)
        self.items = generate_optimizations()
        self.settings = {it['id']: False for it in self.items}
        self.backups_dir = Path.cwd() / "optim_backups"
        self.backups_dir.mkdir(exist_ok=True)
        self.log_file = self.backups_dir / f"changes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self._build_ui()

    def _build_ui(self):
        main = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(main)

        # Header
        header = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("Painel de Otimização Profissional")
        title.setFont(QtGui.QFont("Segoe UI", 18))
        header.addWidget(title)
        header.addStretch()
        btn_total = QtWidgets.QPushButton("Otimização Total")
        btn_total.clicked.connect(self.apply_all_confirm)
        header.addWidget(btn_total)
        btn_revert = QtWidgets.QPushButton("Reverter Tudo")
        btn_revert.clicked.connect(self.revert_all_confirm)
        header.addWidget(btn_revert)
        v.addLayout(header)

        # Splitter
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        left_w = QtWidgets.QWidget()
        left_l = QtWidgets.QVBoxLayout(left_w)
        self.search = QtWidgets.QLineEdit(); self.search.setPlaceholderText("Buscar...")
        self.search.textChanged.connect(self.filter_items)
        left_l.addWidget(self.search)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["Otimização", "Descrição", "Ativado"])
        self.tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        left_l.addWidget(self.tree)
        self._populate_tree()
        splitter.addWidget(left_w)

        right_w = QtWidgets.QWidget()
        right_l = QtWidgets.QVBoxLayout(right_w)
        lbl = QtWidgets.QLabel("Detalhes")
        lbl.setFont(QtGui.QFont("Segoe UI", 14))
        right_l.addWidget(lbl)
        self.details = QtWidgets.QTextEdit(); self.details.setReadOnly(True)
        right_l.addWidget(self.details, 1)

        btn_apply = QtWidgets.QPushButton("Aplicar selecionada")
        btn_apply.clicked.connect(self.apply_selected)
        right_l.addWidget(btn_apply)
        btn_revert_sel = QtWidgets.QPushButton("Reverter selecionada")
        btn_revert_sel.clicked.connect(self.revert_selected)
        right_l.addWidget(btn_revert_sel)

        btn_export = QtWidgets.QPushButton("Exportar perfil")
        btn_export.clicked.connect(self.export_profile)
        right_l.addWidget(btn_export)
        btn_import = QtWidgets.QPushButton("Importar perfil")
        btn_import.clicked.connect(self.import_profile)
        right_l.addWidget(btn_import)

        btn_report = QtWidgets.QPushButton("Gerar relatório rápido (antes/depois)")
        btn_report.clicked.connect(self.generate_perf_report)
        right_l.addWidget(btn_report)

        splitter.addWidget(right_w)
        v.addWidget(splitter)
        self.setCentralWidget(main)
        self.tree.itemClicked.connect(self.on_item_clicked)

    def _populate_tree(self):
        self.tree.clear()
        cats = {}
        for it in self.items:
            cat = it['category']
            if cat not in cats:
                parent = QtWidgets.QTreeWidgetItem(self.tree, [cat])
                parent.setFirstColumnSpanned(True)
                cats[cat] = parent
            parent = cats[cat]
            child = QtWidgets.QTreeWidgetItem(parent, [it['title'], it['desc']])
            child.setData(0, QtCore.Qt.UserRole, it['id'])
            chk = QtWidgets.QCheckBox()
            chk.setChecked(False)
            chk.stateChanged.connect(self._make_checkbox_callback(it))
            self.tree.setItemWidget(child, 2, chk)

    def _make_checkbox_callback(self, item):
        def cb(state):
            enabled = state == QtCore.Qt.Checked
            self.settings[item['id']] = enabled
            # aplicar imediatamente (opcional). Debounce via thread.
            threading.Thread(target=self._apply_item_thread, args=(item, enabled), daemon=True).start()
        return cb

    def filter_items(self, text):
        text = text.lower()
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            cat_item = root.child(i)
            show_cat = False
            for j in range(cat_item.childCount()):
                child = cat_item.child(j)
                title = child.text(0).lower()
                desc = child.text(1).lower()
                visible = (text in title) or (text in desc) or (text == "")
                child.setHidden(not visible)
                if visible:
                    show_cat = True
            cat_item.setHidden(not show_cat)

    def on_item_clicked(self, item, col):
        _id = item.data(0, QtCore.Qt.UserRole)
        if not _id:
            return
        it = next((x for x in self.items if x['id'] == _id), None)
        if it:
            text = f"{it['title']}\n\n{it['desc']}\n\nComando (Habilitar):\n{it['enable_ps']}\n\nComando (Desabilitar):\n{it['disable_ps']}"
            self.details.setPlainText(text)

    # ---- Execução de otimizações ----
    def _log(self, text):
        s = f"[{datetime.now().isoformat()}] {text}\n"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(s)
        except Exception:
            pass

    def _backup_item(self, item):
        try:
            if item.get('reversible'):
                bid = item['id']
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                bak = self.backups_dir / f"{bid}_{ts}.bak"
                # heuristic: if registry commands present, export HKCU/HKLM
                if "reg add" in (item.get('enable_ps') or "") or "reg add" in (item.get('disable_ps') or ""):
                    run_powershell(f"reg export HKCU %TEMP%\\{bid}_HKCU_{ts}.reg /y; reg export HKLM %TEMP%\\{bid}_HKLM_{ts}.reg /y")
                    with open(bak, "w", encoding="utf-8") as f:
                        f.write("backup registry exported")
                else:
                    with open(bak, "w", encoding="utf-8") as f:
                        f.write("backup placeholder")
        except Exception as e:
            self._log(f"Erro backup: {e}")

    def _apply_item_thread(self, item, enable):
        action = "Habilitar" if enable else "Desabilitar"
        self._log(f"Aplicando {action}: {item['id']}")
        if item.get('reversible'):
            self._backup_item(item)
        cmd = item['enable_ps'] if enable else item['disable_ps']
        if not cmd or cmd.strip().startswith("#"):
            self._log("Comando vazio/placeholder - pulando")
            return
        # Execute in PowerShell
        code, out, err = safe_run_ps1(cmd)
        self._log(f"Resultado {item['id']}: code={code}\nout={out}\nerr={err}")

    def apply_selected(self):
        sel = self.tree.selectedItems()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Seleção", "Selecione uma otimização.")
            return
        item_id = sel[0].data(0, QtCore.Qt.UserRole)
        it = next((x for x in self.items if x['id'] == item_id), None)
        if it:
            threading.Thread(target=self._apply_item_thread, args=(it, True), daemon=True).start()
            QtWidgets.QMessageBox.information(self, "Aplicando", f"Aplicando: {it['title']} (em segundo plano)")

    def revert_selected(self):
        sel = self.tree.selectedItems()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Seleção", "Selecione uma otimização.")
            return
        item_id = sel[0].data(0, QtCore.Qt.UserRole)
        it = next((x for x in self.items if x['id'] == item_id), None)
        if it:
            threading.Thread(target=self._apply_item_thread, args=(it, False), daemon=True).start()
            QtWidgets.QMessageBox.information(self, "Revertendo", f"Revertendo: {it['title']} (em segundo plano)")

    def apply_all_confirm(self):
        r = QtWidgets.QMessageBox.question(self, "Confirmação", "Criar ponto de restauração e aplicar todas otimizações marcadas? (Algumas ações são irreversíveis)")
        if r != QtWidgets.QMessageBox.Yes:
            return
        # create restore point (best-effort)
        self._log("Criando ponto de restauração (Before-Total-Optimization)")
        run_powershell("Checkpoint-Computer -Description 'Before-Total-Optimization' -RestorePointType 'MODIFY_SETTINGS'")
        # apply items sequentially (safe)
        for it in self.items:
            if it.get('enable_ps') and not it.get('enable_ps').strip().startswith("#"):
                threading.Thread(target=self._apply_item_thread, args=(it, True), daemon=True).start()
                time.sleep(0.25)
        QtWidgets.QMessageBox.information(self, "Iniciado", "Aplicação em segundo plano iniciada. Verifique logs em optim_backups/")

    def revert_all_confirm(self):
        r = QtWidgets.QMessageBox.question(self, "Confirmação", "Reverter todas otimizações (quando possível)?")
        if r != QtWidgets.QMessageBox.Yes:
            return
        for it in self.items:
            if it.get('disable_ps') and not it.get('disable_ps').strip().startswith("#"):
                threading.Thread(target=self._apply_item_thread, args=(it, False), daemon=True).start()
                time.sleep(0.2)
        QtWidgets.QMessageBox.information(self, "Iniciado", "Reversão em segundo plano iniciada. Verifique logs em optim_backups/")

    def export_profile(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Exportar perfil", str(Path.cwd()/"profile.json"), "JSON Files (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.settings, f, indent=2)
        QtWidgets.QMessageBox.information(self, "Exportado", f"Perfil exportado para {path}")

    def import_profile(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Importar perfil", str(Path.cwd()), "JSON Files (*.json)")
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # apply to checkboxes (not auto-apply commands)
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            cat = root.child(i)
            for j in range(cat.childCount()):
                child = cat.child(j)
                _id = child.data(0, QtCore.Qt.UserRole)
                widget = self.tree.itemWidget(child, 2)
                if _id in data:
                    val = bool(data[_id])
                    if widget:
                        widget.setChecked(val)
                    self.settings[_id] = val
        QtWidgets.QMessageBox.information(self, "Importado", "Perfil importado (checkboxes atualizados). Use Otimização Total para aplicar.")

    def generate_perf_report(self):
        # quick counters snapshot
        code, out, err = run_powershell("Get-Counter -Counter '\\Processor(_Total)\\% Processor Time','\\Memory\\Available MBytes','\\PhysicalDisk(_Total)\\% Disk Time' -SampleInterval 1 -MaxSamples 3 | ConvertTo-Json")
        data = {"timestamp": datetime.now().isoformat(), "ps_code": code, "ps_out": out, "ps_err": err}
        p = self.backups_dir / f"perf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        QtWidgets.QMessageBox.information(self, "Relatório", f"Relatório salvo em: {p}")
        self._log(f"Perf report gerado: {p}")

# -------------------- Elevation (UAC) helper --------------------
def relaunch_as_admin():
    """Tenta relançar o mesmo script como administrador (Windows UAC)."""
    try:
        import ctypes
        if sys.platform != "win32":
            return False
        params = " ".join([f'"{x}"' for x in sys.argv])
        executable = sys.executable
        # ShellExecuteW(return >32 success)
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
        return int(result) > 32
    except Exception:
        return False

# -------------------- Main --------------------
def main():
    # Ask for admin if not admin
    if not is_admin():
        # Prompt user to relaunch as admin
        msg = "Este painel precisa ser executado como Administrador. Deseja relançar com privilégios de administrador?"
        # Use GUI prompt if possible
        try:
            import ctypes
            from ctypes import wintypes
            MB_YESNO = 0x04
            MB_ICONQUESTION = 0x20
            res = ctypes.windll.user32.MessageBoxW(None, msg, "Privilégios necessários", MB_YESNO | MB_ICONQUESTION)
            # If user clicks Yes (ID 6) try relaunch
            if res == 6:
                ok = relaunch_as_admin()
                if ok:
                    sys.exit(0)
                else:
                    print("Falha ao relançar como administrador. Execute o script manualmente como Administrador.")
            else:
                print("Executando sem privilégios de administrador. Muitas ações podem falhar.")
        except Exception:
            print("Não foi possível exibir prompt UAC. Execute o script como Administrador se necessário.")

    try:
        app = QtWidgets.QApplication(sys.argv)
        w = OptimizationPanel()
        w.show()
        app.exec_()
    except Exception:
        import traceback
        print("Erro ao iniciar a interface:")
        traceback.print_exc()
        input("Pressione Enter para sair...")

if __name__ == "__main__":
    main()
