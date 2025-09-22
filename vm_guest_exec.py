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

# ---------- CREDENTIALS ----------
def load_encrypted_credentials(cred_file: str, key_file: str) -> list[dict]:
    if not os.path.exists(cred_file):
        raise FileNotFoundError(f"Credentials file '{cred_file}' not found.")
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Key file '{key_file}' not found.")

    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)

    vcenters = []
    with open(cred_file, "rb") as f:
        for enc_line in f:
            enc_line = enc_line.strip()
            if not enc_line:
                continue
            line = fernet.decrypt(enc_line).decode()
            parts = line.split(",")
            if len(parts) != 3:
                raise ValueError(f"Invalid decrypted line: {line}")
            host, user, password = parts
            vcenters.append({"host": host.strip(), "user": user.strip(), "password": password.strip()})
    return vcenters

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

def build_full_cache(vcenters, cache=None, rate_limit=0.5, verbose=False):
    if cache is None:
        cache = {}

    if not cache_lock.acquire(blocking=False):
        if verbose:
            print("[INFO] Cache rebuild already running, using existing cache...")
        return cache

    try:
        for vc in vcenters:
            try:
                if verbose:
                    print(f"[INFO] Connecting to vCenter {vc['host']} to build cache...")
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
                        if verbose:
                            print(f"[CACHE] Cached VM {name} on {vc['host']}")
                        time.sleep(rate_limit)
                    except Exception:
                        continue
                container_view.Destroy()
                Disconnect(si)
                if verbose:
                    print(f"[INFO] Finished caching vCenter {vc['host']}")
            except Exception as e:
                print(f"[WARN] Failed to cache {vc['host']}: {e}")
    finally:
        cache_lock.release()

    return cache

# ---------- VM CONNECTION & GUEST COMMAND ----------
def connect_to_vcenter(host: str, user: str, password: str, verbose=False):
    if verbose:
        print(f"[INFO] Connecting to vCenter {host}...")
    si = SmartConnect(host=host, user=user, pwd=password, sslContext=ssl_context)
    if verbose:
        print(f"[INFO] Connected to {host}")
    return si

def find_vm_by_cache_or_live(vcenters, target, cache=None, skip_cache=False, verbose=False):
    """
    Fast VM lookup: check cache first, then fallback to live search.
    Returns (vm_object, vcenter_info, si) or (None, None, None)
    """
    target_lower = target.lower()

    # --- 1. Try cache first ---
    if cache and not skip_cache:
        for cache_key, vm_data in cache.items():
            if target_lower in [vm_data["name"].lower()] + [ip.lower() for ip in vm_data.get("ips", [])]:
                if verbose:
                    print(f"[INFO] Found VM '{target}' in cache for vCenter {vm_data['vcenter']}")
                # Connect to the correct vCenter
                vc = next((vc for vc in vcenters if vc["host"] == vm_data["vcenter"]), None)
                if vc is None:
                    continue
                try:
                    si = connect_to_vcenter(vc["host"], vc["user"], vc["password"], verbose)
                    content = si.RetrieveContent()
                    container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                    for vm in container_view.view:
                        if vm._moId == vm_data["mo_ref"]:
                            container_view.Destroy()
                            return vm, vc, si
                    container_view.Destroy()
                    Disconnect(si)
                except Exception as e:
                    if verbose:
                        print(f"[WARN] Error connecting to vCenter {vc['host']}: {e}")
                    continue

    # --- 2. Fallback to live search ---
    for vc in vcenters:
        if skip_cache:  # Only attempt live search
            try:
                if verbose:
                    print(f"[INFO] Performing live search in vCenter {vc['host']} for VM '{target}'...")
                si = connect_to_vcenter(vc["host"], vc["user"], vc["password"], verbose)
                content = si.RetrieveContent()
                container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                for vm in container_view.view:
                    if vm.summary.config.name.lower() == target_lower:
                        container_view.Destroy()
                        if verbose:
                            print(f"[INFO] Found VM '{target}' live on {vc['host']}")
                        return vm, vc, si
                container_view.Destroy()
                Disconnect(si)
            except Exception as e:
                if verbose:
                    print(f"[WARN] Error searching vCenter {vc['host']}: {e}")
                continue

    if verbose:
        print(f"[INFO] VM '{target}' not found in any vCenter")
    return None, None, None

def run_command_in_vm(si, vm: vim.VirtualMachine, guest_user: str, guest_pass: str, command: str, args: str = "", verbose=False):
    if vm.guest.toolsRunningStatus != 'guestToolsRunning':
        raise RuntimeError(f"VM {vm.summary.config.name} does not have VMware Tools running")

    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    gom = si.content.guestOperationsManager
    pm = gom.processManager

    guest_os = vm.summary.config.guestFullName.lower()
    is_windows = "windows" in guest_os

    temp_file = f"/tmp/guest_out_{uuid.uuid4().hex}.txt" if not is_windows else f"C:\\Windows\\Temp\\guest_out_{uuid.uuid4().hex}.txt"

    if is_windows:
        program_path = "C:\\Windows\\System32\\cmd.exe"
        final_args = f"/c {command} {args} > {temp_file} 2>&1"
    else:
        program_path = "/bin/bash"
        final_args = f"-c \"{command} {args} > {temp_file} 2>&1\""

    spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program_path, arguments=final_args)
    pid = pm.StartProgramInGuest(vm=vm, auth=creds, spec=spec)
    if verbose:
        print(f"[INFO] Started process in VM {vm.summary.config.name}, PID={pid}")
    return pid, temp_file, gom, is_windows

def wait_for_process(vm: vim.VirtualMachine, pid: int, gom, guest_user: str, guest_pass: str, timeout=60, verbose=False):
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    pm = gom.processManager
    start_time = time.time()
    while time.time() - start_time < timeout:
        processes = pm.ListProcessesInGuest(vm, creds, [pid])
        if not processes or processes[0].endTime:
            if verbose:
                print(f"[INFO] Process PID={pid} finished in VM {vm.summary.config.name}")
            return True
        time.sleep(1)
    if verbose:
        print(f"[WARN] Process PID={pid} timed out in VM {vm.summary.config.name}")
    return False

def read_file_from_guest(vm: vim.VirtualMachine, gom, guest_user: str, guest_pass: str, file_path: str, is_windows: bool, verbose=False):
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    fm = gom.fileManager
    try:
        file_info = fm.InitiateFileTransferFromGuest(vm, creds, file_path)
        response = requests.get(file_info.url, verify=False)
        if response.status_code == 200:
            if verbose:
                print(f"[INFO] Read output file {file_path} from VM {vm.summary.config.name}")
            return response.text
        return f"[ERROR] Could not read file {file_path}: HTTP {response.status_code}"
    except Exception as e:
        return f"[ERROR] Exception reading file {file_path}: {e}"

def delete_file_from_guest(vm: vim.VirtualMachine, gom, guest_user: str, guest_pass: str, file_path: str, verbose=False):
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_user, password=guest_pass)
    fm = gom.fileManager
    try:
        fm.DeleteFileInGuest(vm, creds, file_path)
        if verbose:
            print(f"[INFO] Deleted temp file {file_path} in VM {vm.summary.config.name}")
    except Exception as e:
        if verbose:
            print(f"[WARN] Could not delete temp file {file_path}: {e}")

def execute_guest_command(vcenters, target, guest_user, guest_pass, command, args="", cache=None, skip_cache=False, timeout=60, verbose=False):
    vm, vc, si = find_vm_by_cache_or_live(vcenters, target, cache, skip_cache, verbose)
    if not vm:
        return False, f"VM {target} not found"
    pid, temp_file, gom, is_windows = run_command_in_vm(si, vm, guest_user, guest_pass, command, args, verbose)
    success = wait_for_process(vm, pid, gom, guest_user, guest_pass, timeout, verbose)
    output = read_file_from_guest(vm, gom, guest_user, guest_pass, temp_file, is_windows, verbose)
    delete_file_from_guest(vm, gom, guest_user, guest_pass, temp_file, verbose)
    Disconnect(si)
    return success, output

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description="Execute shell commands in VMs using VMware Tools with cache support",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--cred-file", default="vm_cred.enc", help="Encrypted vCenter credentials file")
    parser.add_argument("--key-file", default="vm_key.key", help="Key for encrypted credentials and cache")
    parser.add_argument("--cache-file", default="vm_cache.enc", help="Encrypted VM cache file")
    parser.add_argument("--refresh-cache", action="store_true", help="Rebuild global VM cache")
    parser.add_argument("--skip-cache", action="store_true", help="Do not use existing cache, force live search")
    parser.add_argument("--vm", required=True, help="VM name or IP")
    parser.add_argument("--guest-user", required=True, help="Guest OS username")
    parser.add_argument("--guest-pass", required=True, help="Guest OS password")
    parser.add_argument("--command", required=True, help="Shell command to run inside guest VM")
    parser.add_argument("--args", default="", help="Optional command arguments")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    vcenters = load_encrypted_credentials(args.cred_file, args.key_file)
    cache = load_cache(args.cache_file, args.key_file)

    if args.refresh_cache:
        cache = build_full_cache(vcenters, cache, verbose=args.verbose)
        save_cache(cache, args.cache_file, args.key_file)
        if args.verbose:
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
        timeout=args.timeout,
        verbose=args.verbose
    )

    if success:
        print(f"[SUCCESS] Command executed successfully in VM {args.vm}")
    else:
        print(f"[FAIL] Command failed or VM not found: {args.vm}")

    if output:
        print(f"[OUTPUT]\n{output}")

if __name__ == "__main__":
    main()
