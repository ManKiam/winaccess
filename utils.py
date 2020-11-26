import os
import platform
import logging
import subprocess

try:
    import _winreg as winreg  # Python 2
except ImportError:  # Python 3
    import winreg

from .winstructures import *


log = logging.getLogger('winaccess')


class disable_fsr:
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            ctypes.windll.kernel32.Wow64RevertWow64FsRedirection(self.old_value)


# def create(payload, params="", window=False, get_exit_code=False):
#     try:
#         s = subprocess.Popen(
#             (payload + " " + params), stdout=subprocess.PIPE,
#             universal_newlines=True, stdin=subprocess.DEVNULL,
#             stderr=subprocess.DEVNULL, shell=not window
#         )
#         if get_exit_code:
#             s.communicate()
#             return s.returncode
#         return True
#     except:
#         pass

def create(payload, params="", window=False, get_exit_code=False):
    shinfo = ShellExecuteInfoW()
    shinfo.cbSize = sizeof(shinfo)
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS
    shinfo.lpFile = payload
    shinfo.nShow = SW_SHOW if window else SW_HIDE
    shinfo.lpParameters = params

    if ShellExecuteEx(byref(shinfo)):
        if get_exit_code:
            ctypes.windll.kernel32.WaitForSingleObject(shinfo.hProcess, -1)
            i = ctypes.c_int(0)
            pi = ctypes.pointer(i)
            if ctypes.windll.kernel32.GetExitCodeProcess(shinfo.hProcess, pi) != 0:
                return i.value
        return True


def access(fp: str):
    try:
        assert os.path.exists(fp)
        open(fp, 'ab')
        os.rename(fp, fp)
        return 1
    except:
        pass


def get_target(val):
    target = val.split(',')
    if target[1:] and target[1].count('"') > 1:
        target = target[1]
        tar = target.index('"')
        return target[tar+1:target.index('"', tar+1)]
    return ''


def runas(payload, params=""):
    shinfo = ShellExecuteInfoW()
    shinfo.cbSize = sizeof(shinfo)
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS
    shinfo.lpVerb = "runas"
    shinfo.lpFile = payload
    shinfo.nShow = SW_SHOW
    shinfo.lpParameters = params
    try:
        return bool(ShellExecuteEx(byref(shinfo)))
    except Exception as error:
        psdd


def modify_key(hkey, path, name, value, create=False, key64=False):
    hkey = {"hkcu": winreg.HKEY_CURRENT_USER, "hklm": winreg.HKEY_LOCAL_MACHINE}.get(hkey, hkey)
    try:
        if not create:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
        else:
            key = winreg.CreateKey(hkey, os.path.join(path))
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        pass


def read_key(hkey, path, name=""):
    hkey = {"hkcu": winreg.HKEY_CURRENT_USER, "hklm": winreg.HKEY_LOCAL_MACHINE}.get(hkey, hkey)
    value = ""
    try:
        key = winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS)
        value = winreg.QueryValueEx(key, name)[0]
        winreg.CloseKey(key)
    except:
        pass
    return value


def remove_key(hkey, path, name="", delete_key=False, key64=False):
    hkey = {"hkcu": winreg.HKEY_CURRENT_USER, "hklm": winreg.HKEY_LOCAL_MACHINE}.get(hkey, hkey)
    try:
        if delete_key:
            winreg.DeleteKey(hkey, path)
        else:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
        return True
    except Exception as e:
        return False


def system_directory():
    return os.path.join(os.environ.get("windir"), "system32")


def system_drive():
    return os.environ.get("systemdrive")


def windows_directory():
    return os.environ.get("windir")


def architecture():
    return platform.machine()


def username():
    return os.environ.get("username")


def admin():
    return ctypes.windll.shell32.IsUserAnAdmin()


def build_number():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", 0, winreg.KEY_READ)
        cbn = winreg.QueryValueEx(key, "CurrentBuildNumber")
        winreg.CloseKey(key)
        return cbn[0]
    except Exception as error:
        pass


def uac_level():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, winreg.KEY_READ)
        cpba = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        cpbu = winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")
        posd = winreg.QueryValueEx(key, "PromptOnSecureDesktop")
        winreg.CloseKey(key)
        cpba_cpbu_posd = (cpba[0], cpbu[0], posd[0])
        return {(0, 3, 0): 1, (5, 3, 0): 2, (5, 3, 1): 3, (2, 3, 1): 4}.get(cpba_cpbu_posd)
    except Exception as error:
        pass
