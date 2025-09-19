import ssl
import time
import uuid
import os
import json
import argparse
import requests
from cryptography.fernet import Fernet
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import threading

ssl_context = ssl._create_unverified_context()
cache_lock = threading.Lock()  # prevent simultaneous cache rebuilds

# ---------- CACHE FUNCTIONS ----------
def load_cache(cache_file: str, key_file: str) -> dict:
    if not os.path.exists(cache_file) or not os.path.exists(key_file):
        return {}
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    with open(cache_file, "rb") as f:
        encrypted = f.read()
    try:
        return json.loads(fernet.decrypt(encrypted))
    except Exception:
        return {}

def save_cache(cache: dict, cache_file: str, key_file: str):
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(cache).encode())
    with open(cache_file, "wb") as f:
        f.write(encrypted)

def build_full_cache(vcenters, cache=None, rate_limit=0.5):
    if cache is None:
        cache = {}

    if not cache_lock.acquire(blocking=False):
        print("[INFO] Cache rebuild already running, using existing cache...")
        return cache

    try:
        for vc in vcenters:
            try:
                si = SmartConnect(host=vc["host"], user=vc["user"], pwd=vc["password"], sslContext=ssl_context)
                content = si.RetrieveContent()
                container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                for vm in container_view.view:
                    try:
                        name = vm.summary.config.name
                        name_lower = name.lower()
                        ip_list = []
                        host_list = []
                        if vm.guest.toolsRunningStatus == 'guestToolsRunning' and vm.guest.net:
                            for net in vm.guest.net:
                                if net.ipAddress:
                                    ip_list.extend(net.ipAddress)
                        if vm.guest.hostName:
                            host_list.append(vm.guest.hostName)

                        vm_data = {"name": name, "mo_ref": vm._moId, "vcenter": vc["host"], "ips": ip_list}
                        keys_to_cache = [name_lower] + [ip.lower() for ip in ip_list] + [h.lower() for h in host_list]
                        for k in keys_to_cache:
                            cache_key = f"{vc['host']}::{k}"
                            cache[cache_key] = vm_data
                        time.sleep(rate_limit)
                    except Exception:
                        continue
                container_view.Destroy()
                Disconnect(si)
            except Exception as e:
                print(f"[WARN] Failed to cache {vc['host']}: {e}")
    finally:
        cache_lock.release()

    return cache

# ---------- VM CONNECTION & GUEST COMMAND ----------
def connect_to_vcenter(host: str, user: str, password: str):
    si = SmartConnect(host=host, user=user, pwd=password, sslContext=ssl_context)
    print(f"[INFO] Connected to vCenter {host}")
    return si

def find_vm_by_cache_or_live(vcenters, target, cache=None, skip_cache=False):
    """
    Return (vm_object, vcenter_info, si)
    """
    target_lower = target.lower()
    for vc in vcenters:
        # check cache first
        if cache and not skip_cache:
            for key, vm_data in cache.items():
                if vm_data["vcenter"] == vc["host"] and target_lower in [vm_data["name"].lower()] + [ip.lower() for ip in vm_data.get("ips", [])]:
                    si = connect_to_vcenter(vc["host"], vc["user"], vc["password"])
                    content = si.RetrieveContent()
                    container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                    for vm in container_view.view:
                        if vm._moId == vm_data["mo_ref"]:
                            container_view.Destroy()
                            return vm, vc, si
                    container_view.Destroy()
                    Disconnect(si)

        # fallback: live search
        try:
            si = connect_to_vcenter(vc["host"], vc["user"], vc["password"])
            content = si.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
            for vm in container_view.view:
                if vm.summary.config.name.lower() == target_lower:
                    container_view.Destroy()
                    return vm, vc, si
            container_view.Destroy()
            Disconnect(si)
        except Exception:
            continue

    return None, None, None

def run_command_in_vm(si, vm: vim.VirtualMachine, guest_user: str, guest_pass: str, command: str, args: str = ""):
    if vm.guest.toolsRunningStatus != 'guestToolsRunning':
        raise RuntimeError(f"VM {vm.summary.config.name} does not have VMware Tools running")

    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    gom = si.content.guestOperationsManager
    pm = gom.processManager
    fm = gom.fileManager

    # Temp file for stdout/stderr
    if "\\" in command:
        temp_file = f"C:\\Windows\\Temp\\guest_out_{uuid.uuid4().hex}.txt"
        redirect_args = f"{args} > {temp_file} 2>&1"
    else:
        temp_file = f"/tmp/guest_out_{uuid.uuid4().hex}.txt"
        redirect_args = f"{args} > {temp_file} 2>&1"

    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=command, arguments=redirect_args)
    pid = pm.StartProgramInGuest(vm=vm, auth=creds, spec=spec)
    print(f"[INFO] Started process in VM {vm.summary.config.name}, PID={pid}")
    return pid, temp_file, gom

def wait_for_process(vm: vim.VirtualMachine, pid: int, gom, guest_user: str, guest_pass: str, timeout=60):
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    pm = gom.processManager
    start_time = time.time()
    while time.time() - start_time < timeout:
        processes = pm.ListProcessesInGuest(vm, creds, [pid])
        if not processes or processes[0].endTime:
            return True
        time.sleep(1)
    return False

def read_file_from_guest(vm: vim.VirtualMachine, gom, guest_user: str, guest_pass: str, file_path: str):
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    fm = gom.fileManager
    try:
        file_info = fm.InitiateFileTransferFromGuest(vm, creds, file_path)
        response = requests.get(file_info.url, verify=False)
        if response.status_code == 200:
            return response.text
        return f"[ERROR] Could not read file {file_path}: HTTP {response.status_code}"
    except Exception as e:
        return f"[ERROR] Exception reading file {file_path}: {e}"

def delete_file_from_guest(vm: vim.VirtualMachine, gom, guest_user: str, guest_pass: str, file_path: str):
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    fm = gom.fileManager
    try:
        fm.DeleteFileInGuest(vm, creds, file_path)
        print(f"[INFO] Deleted temp file {file_path}")
    except Exception as e:
        print(f"[WARN] Could not delete temp file {file_path}: {e}")

def execute_guest_command(vcenters, target, guest_user, guest_pass, command, args="", cache=None, skip_cache=False, timeout=60):
    vm, vc, si = find_vm_by_cache_or_live(vcenters, target, cache, skip_cache)
    if not vm:
        return False, f"VM {target} not found"
    pid, temp_file, gom = run_command_in_vm(si, vm, guest_user, guest_pass, command, args)
    success = wait_for_process(vm, pid, gom, guest_user, guest_pass, timeout)
    output = read_file_from_guest(vm, gom, guest_user, guest_pass, temp_file)
    delete_file_from_guest(vm, gom, guest_user, guest_pass, temp_file)
    Disconnect(si)
    return success, output

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description="Execute commands in VMs using VMware Tools with cache support",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--cred-file", default="vm_cred.enc", help="Encrypted vCenter credentials file")
    parser.add_argument("--key-file", default="vm_key.key", help="Key for encrypted credentials and cache")
    parser.add_argument("--cache-file", default="vm_cache.enc", help="Encrypted VM cache file")
    parser.add_argument("--refresh-cache", action="store_true", help="Rebuild global VM cache")
    parser.add_argument("--skip-cache", action="store_true", help="Do not use existing cache")
    parser.add_argument("--vm", required=True, help="VM name or IP")
    parser.add_argument("--guest-user", required=True, help="Guest OS username")
    parser.add_argument("--guest-pass", required=True, help="Guest OS password")
    parser.add_argument("--command", required=True, help="Command or program to run inside guest VM")
    parser.add_argument("--args", default="", help="Command arguments")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")
    args = parser.parse_args()

    from vm_snapshot import load_encrypted_credentials
    vcenters = load_encrypted_credentials(args.cred_file, args.key_file)
    cache = load_cache(args.cache_file, args.key_file)

    if args.refresh_cache:
        cache = build_full_cache(vcenters, cache)
        save_cache(cache, args.cache_file, args.key_file)
        print("[INFO] Cache rebuilt successfully.")

    success, output = execute_guest_command(
        vcenters=vcenters,
        target=args.vm,
        guest_user=args.guest_user,
        guest_pass=args.guest_pass,
        command=args.command,
        args=args.args,
        cache=cache,
        skip_cache=args.skip_cache,
        timeout=args.timeout
    )

    if success:
        print(f"[SUCCESS] Command executed successfully in VM {args.vm}")
    else:
        print(f"[FAIL] Command failed or VM not found: {args.vm}")

    if output:
        print(f"[OUTPUT]\n{output}")

if __name__ == "__main__":
    main()
