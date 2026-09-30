# nsa-equation-py

Python reimplementations of legacy tooling (e.g. the DNS payload-builder derived from `dns.exe` via IDA Pro).

## Usage

```bash
nsa-equation-py dns -y bind -R 1.2.3.4 -p 1100
nsa-equation-py dns --list
```

See `dns --help` for all available options (they are forwarded verbatim to `dns_tool`).

### smbv3-scan — CVE-2020-0796 (SMBGhost) 检测

Python rewrite of the scanner embedded in `CVE-2020-0796-Scanner.exe`
(`main` → `smb_poc.run_function(subnet)`). Scans targets and reports hosts
that negotiate SMB 3.1.1 (the CVE-2020-0796 surface). Detection only.

```bash
nsa-equation-py smbv3-scan 192.168.1.5              # single host
nsa-equation-py smbv3-scan 192.168.1.0/24           # scan a whole subnet
nsa-equation-py smbv3-scan 10.0.0.1 10.0.0.2 -p 445 -t 3 -n 64
```

> The original `smb_poc.pyd` is **VMProtect-packed** (`.vmp0`/`.vmp1` sections)
> and its code is virtualized into VM bytecode — a memory dump yields the
> loaded but still-encrypted sections, not readable native logic. This rewrite
> therefore implements the public CVE-2020-0796 detection technique. An
> in-memory dump of the packed module (via x32dbg) was saved alongside the
> scanner as `smb_poc_unpacked.pyd`; it confirms the scanner also links
> WTSAPI32 (`WTSSendMessageW`) for terminal-session messaging.