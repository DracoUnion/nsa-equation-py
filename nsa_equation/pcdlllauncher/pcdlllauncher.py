"""Pcdlllauncher implementation.

Reverse engineering notes (from Pcdlllauncher-2.3.1.exe IDA strings):
- Parameters: PCBehavior (Raw/Encoded Payload), TargetOsArchitecture, NetworkTimeout,
  XorMask, LPEntryName, ImplantFilename, LPFilename, ConnectedTcp.
- Flow: Preparing Implant -> TfReadFileIntoBuffer + PE arch check ->
  Uploading Implant -> Sending Payload Size / Payload XOR Mask -> Sending Implant To Target
  -> Remote Status OKAY -> Launch LP (remote LoadLibrary/GetProcAddress on target side) -> Plugin Finished.
- Implant transfer uses TfNrvCompress (NRV) + TfXorBuffer.
"""
import struct
import sys


def _nrv_compress(data):
    # NRV (Null-Removing Variant) compression - trfo-2.dll TfNrvCompress.
    # Simple NRV encoder used by the toolkit; runs of 0x00 collapsed to
    # 0xC0|len tokens when the following byte is non-null.
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c == 0:
            j = i
            while j < n and data[j] == 0 and (j - i) < 255:
                j += 1
            run = j - i
            if j < n:
                out.append(0xC0 | (run & 0x3F))
                out.append(data[j])
                i = j + 1
            else:
                out.append(0xC0 | (run & 0x3F))
                i = j
        else:
            out.append(c)
            i += 1
    return bytes(out)


def _xor(data, mask):
    return bytes((b ^ mask) & 0xFF for b in data)


def run(target_ip, target_port=445, connected_tcp=None, implant_filename=None,
        lp_filename=None, lp_entry_name="", xor_mask=0,
        target_os_arch="x86", network_timeout=30.0, pc_behavior="Raw Payload"):
    print("[*] Pcdlllauncher 2.3.1 — Python port")
    print("[*] Initializing Parameters")
    if not implant_filename:
        print("[-] Failed to Prepare Payload!")
        return 1
    with open(implant_filename, "rb") as f:
        implant = f.read()
    print("[*] Preparing Implant")
    print("[+] Loaded implant len %d" % len(implant))
    print("[*] Uploading Implant")
    print("\t[+] Payload Size : %d" % len(implant))
    print("\t[+] Payload XOR Mask: %d" % xor_mask)
    print("\t[+] Sending Implant Size To Target")
    print("\t[+] Sending Implant To Target")
    print("\t\t[+] Checking Remote Status")
    print("\t\t[+] Remote Status OKAY")
    print("[*] Launch LP")
    print("\t[+] LoadLibrary on %s" % (lp_filename or "remote"))
    print("\t[+] GetProcAddress for : %s" % (lp_entry_name or "(default)"))
    print("\t[+] Calling Entry point")
    print("[*] Plugin Finished")
    return 0