"""Read-only Windows identity inventory used as the rollback baseline."""

import json
import subprocess
import sys
import winreg


MACHINE_GUID_KEY = r"SOFTWARE\Microsoft\Cryptography"


def machine_guid() -> str:
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        return winreg.QueryValueEx(key, "MachineGuid")[0]


def adapters() -> list[dict]:
    script = "Get-NetAdapter | Select-Object Name, InterfaceGuid, MacAddress, Status | ConvertTo-Json -Compress"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            check=True, capture_output=True, text=True)
    value = json.loads(result.stdout or "[]")
    return value if isinstance(value, list) else [value]


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != "inspect":
        print("usage: BASELINE.py inspect", file=sys.stderr)
        return 2
    print(json.dumps({"MachineGuid": machine_guid(), "adapters": adapters()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
