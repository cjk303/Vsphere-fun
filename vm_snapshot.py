import ssl
import time
import argparse
import os
import json
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable
from cryptography.fernet import Fernet
import threading

ssl_context = ssl._create_unverified_context()
cache_lock = threading.Lock()  # Lock to prevent multiple simultaneous cache rebuilds

# ---------- CREDENTIALS ----------
def load_encrypted_credentials(cred_file: str, key_file: str) -> List[Dict]:
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

# ---------- CACHE ----------
def load_cache(cache_file: str, key_file: str) -> Dict:
    if not os.path.exists(cache_file) or not os.path.exists(key_file):
        return {}
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    with open(cache_file, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)
    except Exception:
        return {}

def save_cache(cache: Dict, cache_file: str, key_file: str):
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(cache).encode())
    with open(cache_file, "wb") as f:
        f.write(encrypted)

def build_full_cache(vcenters: List[Dict], cache=None,
                     progress_callback: Optional[Callable[[str], None]] = None,
                     verbose=False, max_workers=1, rate_limit=0.5) -> Dict:
    """Build a global cache for all VMs in all vCenters with optional progress and single-threaded rate-limit."""
    if cache is None:
        cache = {}

    if not cache_lock.acquire(blocking=False):
        if verbose and progress_callback:
            progress_callback("Cache rebuild already running, using existing cache...")
        return cache  # Another thread is already building cache

    try:
        total_vms = 0
        # First count total VMs for progress percentage
        for vc in vcenters:
            try:
                si = SmartConnect(host=vc["host"], user=vc["user"], pwd=vc["password"], sslContext=ssl_context)
                content = si.RetrieveContent()
                container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                total_vms += len(container_view.view)
                container_view.Destroy()
                Disconnect(si)
            except Exception:
                continue

        cached_count = 0
        for vc in vcenters:
            try:
                si = SmartConnect(host=vc["host"], user=vc["user"], pwd=vc["password"], sslContext=ssl_context)
                content = si.RetrieveContent()
                container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                vms = container_view.view
                if verbose and progress_callback:
                    progress_callback(f"Caching {len(vms)} VMs from {vc['host']}...")

                for vm in vms:
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
                        cached_count += 1
                        if progress_callback and verbose and total_vms > 0:
                            percent = int(cached_count / total_vms * 100)
                            progress_callback(f"Cached {cached_count}/{total_vms} VMs ({percent}%)")
                        time.sleep(rate_limit)  # Rate-limit to prevent overloading vCenter
                    except Exception:
                        continue

                container_view.Destroy()
                Disconnect(si)
            except Exception as e:
                if verbose and progress_callback:
                    progress_callback(f"Failed to cache {vc['host']}: {e}")

    finally:
        cache_lock.release()

    return cache

# ---------- VM CONNECTION, SEARCH, AND SNAPSHOT ----------
def connect_to_vcenter(host: str, user: str, password: str, verbose=False, progress_callback=None):
    if verbose and progress_callback:
        progress_callback(f"Connecting to vCenter {host}...")
    try:
        si = SmartConnect(host=host, user=user, pwd=password, sslContext=ssl_context)
        if verbose and progress_callback:
            progress_callback(f"Connected to {host}")
        return si
    except Exception as e:
        raise ConnectionError(f"Failed to connect to {host}: {e}")

def find_vm_by_ip_or_name_parallel(content, search: str, cache=None, vcenter_host=None,
                                   progress_callback: Optional[Callable[[str], None]] = None,
                                   verbose=False, max_workers=1) -> Optional[vim.VirtualMachine]:
    # Single-threaded default; parallel optional with max_workers
    search_lower = search.lower()
    container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    vms = container_view.view

    found_vm = None

    def check_vm(vm):
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

            if cache is not None:
                vm_data = {"name": name, "mo_ref": vm._moId, "vcenter": vcenter_host, "ips": ip_list}
                keys_to_cache = [name_lower] + [ip.lower() for ip in ip_list] + [h.lower() for h in host_list]
                for k in keys_to_cache:
                    cache_key = f"{vcenter_host}::{k}"
                    cache[cache_key] = vm_data

            search_matches = [name_lower] + [ip.lower() for ip in ip_list] + [h.lower() for h in host_list]
            if search_lower in search_matches:
                return vm
        except Exception:
            return None
        return None

    if max_workers == 1:
        # Single-threaded
        for vm in vms:
            result = check_vm(vm)
            if result:
                found_vm = result
                break
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vm = {executor.submit(check_vm, vm): vm for vm in vms}
            for future in as_completed(future_to_vm):
                vm_result = future.result()
                if vm_result:
                    found_vm = vm_result
                    break

    container_view.Destroy()
    return found_vm

def create_snapshot(vm: vim.VirtualMachine, name: str, description: str, memory=False, quiesce=True,
                    progress_callback: Optional[Callable[[str], None]] = None, verbose=False) -> bool:
    if verbose and progress_callback:
        progress_callback(f"Starting snapshot for VM {vm.summary.config.name}")
    task = vm.CreateSnapshot_Task(name=name, description=description, memory=memory, quiesce=quiesce)
    last_progress = -1
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
        current_progress = task.info.progress
        if current_progress is not None and current_progress != last_progress:
            last_progress = current_progress
            if progress_callback and verbose:
                progress_callback(f"Snapshot progress for VM {vm.summary.config.name}: {current_progress}%")
        time.sleep(1)
    if task.info.state == vim.TaskInfo.State.success:
        if progress_callback and verbose:
            progress_callback(f"Snapshot '{name}' created successfully for VM {vm.summary.config.name}")
        return True
    else:
        if progress_callback and verbose:
            progress_callback(f"Snapshot failed for VM {vm.summary.config.name}: {task.info.error}")
        return False

def search_and_snapshot(vc: Dict, target: str, snapshot_name: str, snapshot_description: str,
                        include_memory=False, progress_callback: Optional[Callable[[str], None]] = None,
                        verbose=False, cache=None, skip_cache=False) -> Dict:
    result = {"vcenter": vc["host"], "found": False, "snapshot_created": False, "vm_name": None, "error": None}
    try:
        si = connect_to_vcenter(vc["host"], vc["user"], vc["password"], verbose=verbose, progress_callback=progress_callback)
        content = si.RetrieveContent()
        cache_key = f"{vc['host']}::{target.lower()}"
        vm = None
        if cache and not skip_cache and cache_key in cache:
            vm_mo_ref = cache[cache_key]["mo_ref"]
            for v in content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True).view:
                if v._moId == vm_mo_ref:
                    vm = v
                    if verbose and progress_callback:
                        progress_callback(f"VM {target} found in cache for {vc['host']}")
                    break

        if not vm and (cache is None or skip_cache):
            vm = find_vm_by_ip_or_name_parallel(content, target, cache=cache if not skip_cache else None,
                                                vcenter_host=vc["host"], progress_callback=progress_callback, verbose=verbose, max_workers=1)

        if vm:
            result["found"] = True
            result["vm_name"] = vm.summary.config.name
            if verbose and progress_callback:
                progress_callback(f"Found VM '{vm.summary.config.name}' on {vc['host']}")
            success = create_snapshot(vm, snapshot_name, snapshot_description, memory=include_memory,
                                      progress_callback=progress_callback, verbose=verbose)
            result["snapshot_created"] = success
        else:
            if verbose and progress_callback:
                progress_callback(f"No VM matching '{target}' found on {vc['host']}")
        Disconnect(si)
    except Exception as e:
        result["error"] = str(e)
        if verbose and progress_callback:
            progress_callback(f"Error on {vc['host']}: {e}")
    return result

def create_vm_snapshot(vcenters: List[Dict], target: str, snapshot_name: str, snapshot_description: str,
                       include_memory=False, progress_callback: Optional[Callable[[str], None]] = None,
                       verbose=False, max_workers=1, cache=None, skip_cache=False) -> List[Dict]:
    results = []
    for vc in vcenters if max_workers == 1 else []:
        # Single-threaded
        res = search_and_snapshot(vc, target, snapshot_name, snapshot_description, include_memory,
                                  progress_callback, verbose, cache, skip_cache)
        results.append(res)

    if max_workers > 1:
        # Multi-threaded
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vc = {executor.submit(search_and_snapshot, vc, target, snapshot_name, snapshot_description,
                                            include_memory, progress_callback, verbose, cache, skip_cache): vc for vc in vcenters}
            for future in as_completed(future_to_vc):
                res = future.result()
                results.append(res)
                if res["snapshot_created"]:
                    break
    return results

# ---------- MAIN ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VMware VM Snapshot Creator")
    parser.add_argument("--cred-file", default="vm_cred.enc")
    parser.add_argument("--key-file", default="vm_key.key")
    parser.add_argument("--cache-file", default="vm_cache.enc")
    parser.add_argument("--vm", required=True)
    parser.add_argument("--snapshot-name", required=True)
    parser.add_argument("--snapshot-desc", default="Created by script")
    parser.add_argument("--include-memory", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--skip-cache", action="store_true")
    parser.add_argument("--refresh-cache", action="store_true")
    parser.add_argument("--multithreaded", action="store_true", help="Enable multi-threaded snapshot search and cache")
    args = parser.parse_args()

    def print_progress(msg):
        print(msg)

    try:
        vcenters = load_encrypted_credentials(args.cred_file, args.key_file)
        cache = load_cache(args.cache_file, args.key_file)
    except Exception as e:
        print(f"Error loading credentials or cache: {e}")
        exit(1)

    max_workers = 5 if args.multithreaded else 1  # Single-threaded by default

    if args.refresh_cache:
        if args.verbose:
            print_progress("Refreshing global cache for all vCenters...")
        cache = build_full_cache(vcenters, cache=cache, progress_callback=print_progress, verbose=args.verbose, max_workers=max_workers)
        save_cache(cache, args.cache_file, args.key_file)
        if args.verbose:
            print_progress("Global cache rebuilt successfully.")

    results = create_vm_snapshot(
        vcenters,
        target=args.vm,
        snapshot_name=args.snapshot_name,
        snapshot_description=args.snapshot_desc,
        include_memory=args.include_memory,
        progress_callback=print_progress,
        verbose=args.verbose,
        max_workers=max_workers,
        cache=cache,
        skip_cache=args.skip_cache
    )

    if not args.skip_cache:
        save_cache(cache, args.cache_file, args.key_file)

    print("\n--- Snapshot Results ---")
    for r in results:
        print(r)
