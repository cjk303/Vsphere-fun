#!/usr/bin/env python3
"""
Auto-add VM to encrypted cache with optional credential source

This script connects to a specified vCenter, finds a VM by name, and adds it to
the encrypted VM cache automatically with mo_ref, guest hostnames, and IPs.

By default, it reads credentials from an encrypted file (vm_cred.enc + vm_key.key).
You can override by providing --user and --password manually.
"""

import ssl
import os
import json
import argparse
from cryptography.fernet import Fernet
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# ------------------ Credential Loader ------------------
def load_encrypted_credentials(cred_file: str, key_file: str):
    """
    Load vCenter credentials from encrypted file
    Returns a list of dicts: [{"host": "...", "user": "...", "password": "..."}]
    """
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
            vcenters.append({
                "host": host.strip(),
                "user": user.strip(),
                "password": password.strip()
            })
    return vcenters

# ------------------ Cache Handling ------------------
def load_cache(cache_file: str, key_file: str):
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

# ------------------ VM Lookup ------------------
def find_vm_by_name(si, vm_name):
    content = si.RetrieveContent()
    container_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    vm_found = None
    for vm in container_view.view:
        if vm.summary.config.name.lower() == vm_name.lower():
            vm_found = vm
            break
    container_view.Destroy()
    return vm_found

# ------------------ Add VM to Cache ------------------
def add_vm_to_cache(cache_file, key_file, vm, vcenter):
    if not vm:
        print("[ERROR] VM not found, cannot add to cache.")
        return

    vm_name = vm.summary.config.name
    mo_ref = vm._moId
    ips = []
    hostnames = []

    # Only if VMware Tools is running
    if vm.guest.toolsRunningStatus == "guestToolsRunning" and vm.guest.net:
        for net in vm.guest.net:
            if net.ipAddress:
                ips.extend(net.ipAddress)
    if vm.guest.hostName:
        hostnames.append(vm.guest.hostName)

    cache = load_cache(cache_file, key_file)

    # Lowercase keys: name + IPs + hostnames
    keys = [vm_name.lower()] + [ip.lower() for ip in ips] + [h.lower() for h in hostnames]

    vm_data = {
        "name": vm_name,
        "mo_ref": mo_ref,
        "vcenter": vcenter,
        "ips": ips
    }

    for k in keys:
        cache_key = f"{vcenter}::{k}"
        cache[cache_key] = vm_data

    save_cache(cache, cache_file, key_file)
    print(f"[SUCCESS] VM '{vm_name}' added to cache for vCenter '{vcenter}' with keys: {keys}")

# ------------------ Main ------------------
def main():
    parser = argparse.ArgumentParser(description="Automatically add a VM to encrypted cache with optional credential source")
    parser.add_argument("--cache-file", default="vm_cache.enc", help="Encrypted cache file")
    parser.add_argument("--key-file", default="vm_key.key", help="Encryption key file")
    parser.add_argument("--cred-file", default="vm_cred.enc", help="Encrypted vCenter credentials file")
    parser.add_argument("--vm-name", required=True, help="VM display name")
    parser.add_argument("--vcenter", required=True, help="vCenter hostname or IP")
    parser.add_argument("--user", help="vCenter username (overrides encrypted credentials)")
    parser.add_argument("--password", help="vCenter password (overrides encrypted credentials)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # ------------------ Get credentials ------------------
    if args.user and args.password:
        username = args.user
        password = args.password
    else:
        vcenters = load_encrypted_credentials(args.cred_file, args.key_file)
        matched = [vc for vc in vcenters if vc["host"].lower() == args.vcenter.lower()]
        if not matched:
            print(f"[ERROR] vCenter '{args.vcenter}' not found in encrypted credentials.")
            return
        username = matched[0]["user"]
        password = matched[0]["password"]

    ssl_context = ssl._create_unverified_context()
    if args.verbose:
        print(f"[INFO] Connecting to vCenter {args.vcenter}...")
    si = SmartConnect(host=args.vcenter, user=username, pwd=password, sslContext=ssl_context)
    if args.verbose:
        print(f"[INFO] Connected to {args.vcenter}")

    vm = find_vm_by_name(si, args.vm_name)
    if not vm:
        print(f"[ERROR] VM '{args.vm_name}' not found in {args.vcenter}")
    else:
        add_vm_to_cache(args.cache_file, args.key_file, vm, args.vcenter)

    Disconnect(si)
    if args.verbose:
        print(f"[INFO] Disconnected from {args.vcenter}")

if __name__ == "__main__":
    main()
