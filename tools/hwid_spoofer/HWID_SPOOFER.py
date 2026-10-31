"""Windows user-mode HWID spoofer for MachineGuid and one NIC's MAC.

Run from an elevated terminal. Keep the explicit backup file for restoration.
Restart Windows after spoofing or restoration so processes refresh cached IDs.
This does not alter SMBIOS, firmware UUIDs, or physical disk serial numbers.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import unittest
import uuid
import winreg

MACHINE_GUID_KEY = r"SOFTWARE\Microsoft\Cryptography"
ADAPTER_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
REG_READ = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
REG_WRITE = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY


def ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def normalize_guid(value: str) -> str:
    return str(uuid.UUID(value.strip("{}")))


def normalize_mac(value: str) -> str:
    digits = re.sub(r"[:-]", "", value).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", digits):
        raise ValueError("MAC must contain exactly 12 hexadecimal digits")
    if int(digits[:2], 16) & 3 != 2:
        raise ValueError("MAC must be locally administered and unicast")
    return digits


def random_mac() -> str:
    return "02" + secrets.token_hex(5).upper()


def mac_digits(value: str | None) -> str:
    return re.sub(r"[:-]", "", value or "").upper()


class WindowsBackend:
    def require_admin(self) -> None:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("run from an elevated Windows terminal")

    def machine_guid(self) -> str:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, 0, REG_READ) as key:
            return winreg.QueryValueEx(key, "MachineGuid")[0]

    def set_machine_guid(self, value: str) -> None:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, 0, REG_WRITE) as key:
            winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, value)

    def adapters(self) -> list[dict]:
        data = powershell(
            "$ErrorActionPreference='Stop'; "
            "Get-NetAdapter | Select-Object Name,InterfaceGuid,MacAddress,Status | ConvertTo-Json -Compress"
        )
        if not data:
            return []
        value = json.loads(data)
        return value if isinstance(value, list) else [value]

    def adapter(self, name: str) -> dict:
        data = powershell(
            "$ErrorActionPreference='Stop'; "
            f"Get-NetAdapter -Name {ps_literal(name)} | "
            "Select-Object Name,InterfaceGuid,MacAddress,Status | ConvertTo-Json -Compress"
        )
        value = json.loads(data)
        if not isinstance(value, dict) or not value.get("InterfaceGuid"):
            raise RuntimeError("adapter lookup returned no interface GUID")
        return value

    def class_key(self, interface_guid: str) -> str:
        wanted = normalize_guid(interface_guid)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ADAPTER_CLASS_KEY, 0, REG_READ) as parent:
            index = 0
            while True:
                try:
                    child = winreg.EnumKey(parent, index)
                except OSError:
                    break
                index += 1
                if not re.fullmatch(r"\d{4}", child):
                    continue
                path = ADAPTER_CLASS_KEY + "\\" + child
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, REG_READ) as key:
                        candidate = winreg.QueryValueEx(key, "NetCfgInstanceId")[0]
                    if normalize_guid(candidate) == wanted:
                        return path
                except (OSError, ValueError):
                    continue
        raise LookupError("no network class key matches the adapter GUID")

    def network_address(self, path: str) -> dict | None:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, REG_READ) as key:
            try:
                value, kind = winreg.QueryValueEx(key, "NetworkAddress")
            except FileNotFoundError:
                return None
        return {"value": value, "kind": kind}

    def set_network_address(self, path: str, address: dict | None) -> None:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, REG_WRITE) as key:
            if address is None:
                try:
                    winreg.DeleteValue(key, "NetworkAddress")
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, "NetworkAddress", 0, address["kind"], address["value"])

    def restart_adapter(self, name: str) -> None:
        powershell(
            "$ErrorActionPreference='Stop'; "
            f"Restart-NetAdapter -Name {ps_literal(name)} -Confirm:$false -ErrorAction Stop"
        )


def write_backup(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def spoof(backend, adapter_name: str, backup_path: Path, new_guid: str, new_mac: str) -> dict:
    backend.require_admin()
    new_guid = normalize_guid(new_guid)
    new_mac = normalize_mac(new_mac)
    adapter = backend.adapter(adapter_name)
    interface_guid = normalize_guid(adapter["InterfaceGuid"])
    class_key = backend.class_key(interface_guid)
    original_machine_guid = backend.machine_guid()
    original_network_address = backend.network_address(class_key)
    record = {
        "version": 1,
        "adapter_name": adapter["Name"],
        "interface_guid": interface_guid,
        "class_key": class_key,
        "original_machine_guid": original_machine_guid,
        "original_network_address": original_network_address,
        "original_reported_mac": adapter.get("MacAddress"),
        "spoofed_machine_guid": new_guid,
        "spoofed_network_address": new_mac,
    }
    write_backup(backup_path, record)
    try:
        backend.set_machine_guid(new_guid)
        backend.set_network_address(class_key, {"value": new_mac, "kind": winreg.REG_SZ})
        backend.restart_adapter(adapter["Name"])
        if normalize_guid(backend.machine_guid()) != new_guid:
            raise RuntimeError("MachineGuid did not persist")
        if mac_digits(backend.adapter(adapter["Name"]).get("MacAddress")) != new_mac:
            raise RuntimeError("NIC driver did not apply the requested MAC")
    except Exception as exc:
        try:
            backend.set_network_address(class_key, original_network_address)
            backend.set_machine_guid(original_machine_guid)
            backend.restart_adapter(adapter["Name"])
        except Exception as rollback_exc:
            raise RuntimeError(f"spoof failed: {exc}; automatic rollback failed: {rollback_exc}; use backup") from exc
        raise RuntimeError(f"spoof failed and original identifiers were restored: {exc}") from exc
    return record


def restore(backend, backup_path: Path) -> dict:
    backend.require_admin()
    with backup_path.open(encoding="utf-8") as stream:
        record = json.load(stream)
    if record.get("version") != 1:
        raise ValueError("unsupported backup version")
    adapter = backend.adapter(record["adapter_name"])
    current_guid = normalize_guid(adapter["InterfaceGuid"])
    if current_guid != record["interface_guid"] or backend.class_key(current_guid) != record["class_key"]:
        raise ValueError("backup adapter identity does not match current registry")
    backend.set_network_address(record["class_key"], record["original_network_address"])
    backend.set_machine_guid(record["original_machine_guid"])
    backend.restart_adapter(record["adapter_name"])
    if backend.machine_guid() != record["original_machine_guid"]:
        raise RuntimeError("MachineGuid restoration did not persist")
    if mac_digits(backend.adapter(record["adapter_name"]).get("MacAddress")) != mac_digits(record.get("original_reported_mac")):
        raise RuntimeError("NIC driver did not restore the original MAC")
    return record


class FakeBackend:
    """No host changes; exercises the same transaction for self-test."""

    def __init__(self):
        self.guid = "11111111-1111-4111-8111-111111111111"
        self.mac = None
        self.fail_restart_once = False

    def require_admin(self):
        pass

    def adapter(self, name):
        mac = self.mac["value"] if self.mac else "00-00-00-00-00-01"
        return {"Name": name, "InterfaceGuid": "{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}",
                "MacAddress": mac}

    def class_key(self, interface_guid):
        return ADAPTER_CLASS_KEY + r"\0001"

    def machine_guid(self):
        return self.guid

    def set_machine_guid(self, value):
        self.guid = value

    def network_address(self, path):
        return self.mac

    def set_network_address(self, path, address):
        self.mac = address

    def restart_adapter(self, name):
        if self.fail_restart_once:
            self.fail_restart_once = False
            raise RuntimeError("simulated restart failure")


class SelfTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_mac("02:11:22:33:44:55"), "021122334455")
        with self.assertRaises(ValueError):
            normalize_mac("01:11:22:33:44:55")
        self.assertEqual(normalize_guid("{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}"),
                         "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

    def test_spoof_and_restore(self):
        backend = FakeBackend()
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "original.json"
            record = spoof(backend, "Ethernet", backup,
                           "22222222-2222-4222-8222-222222222222", "02:11:22:33:44:55")
            self.assertTrue(backup.is_file())
            self.assertEqual(backend.guid, record["spoofed_machine_guid"])
            self.assertEqual(backend.mac["value"], "021122334455")
            restore(backend, backup)
            self.assertEqual(backend.guid, "11111111-1111-4111-8111-111111111111")
            self.assertIsNone(backend.mac)

    def test_failure_rolls_back(self):
        backend = FakeBackend()
        backend.fail_restart_once = True
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "original.json"
            with self.assertRaisesRegex(RuntimeError, "original identifiers were restored"):
                spoof(backend, "Ethernet", backup,
                      "22222222-2222-4222-8222-222222222222", "021122334455")
            self.assertEqual(backend.guid, "11111111-1111-4111-8111-111111111111")
            self.assertIsNone(backend.mac)

    def test_existing_backup_is_preserved(self):
        backend = FakeBackend()
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "original.json"
            backup.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                spoof(backend, "Ethernet", backup,
                      "22222222-2222-4222-8222-222222222222", "021122334455")
            self.assertEqual(backup.read_text(encoding="utf-8"), "keep")
            self.assertEqual(backend.guid, "11111111-1111-4111-8111-111111111111")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("inspect", help="show current MachineGuid and network adapters")
    change = sub.add_parser("spoof", help="change MachineGuid and a NIC MAC; save originals")
    change.add_argument("--adapter", required=True, help="exact adapter name from inspect")
    change.add_argument("--backup", required=True, type=Path, help="new JSON backup path")
    change.add_argument("--machine-guid", default=None, help="optional replacement UUID")
    change.add_argument("--mac", default=None, help="optional local-unicast MAC")
    undo = sub.add_parser("restore", help="restore originals from the backup")
    undo.add_argument("--backup", required=True, type=Path)
    sub.add_parser("selftest", help="run no-host-change transaction tests")
    args = parser.parse_args(argv)
    if args.command == "selftest":
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    backend = WindowsBackend()
    try:
        if args.command == "inspect":
            print(json.dumps({"MachineGuid": backend.machine_guid(), "adapters": backend.adapters()}, indent=2))
        elif args.command == "spoof":
            record = spoof(backend, args.adapter, args.backup,
                           args.machine_guid or str(uuid.uuid4()), args.mac or random_mac())
            print(json.dumps({"status": "spoofed", "MachineGuid": record["spoofed_machine_guid"],
                              "NetworkAddress": record["spoofed_network_address"],
                              "backup": str(args.backup), "reboot_required": True}, indent=2))
        elif args.command == "restore":
            record = restore(backend, args.backup)
            print(json.dumps({"status": "restored", "MachineGuid": record["original_machine_guid"],
                              "NetworkAddress": record["original_network_address"],
                              "reboot_required": True}, indent=2))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

