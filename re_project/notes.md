任务开始。目标目录 D:\Program Files\方程式工具包图形界面版v0.68\Eclipsedwing-ms08-2000-xp-03-08 含 7 个 EXE：
1. danecfg.exe
2. Doublepulsar-1.3.1.exe
3. Eclipsedwing-1.5.2.exe
4. Eclipsedwingtouch-1.0.4.exe
5. Pcdlllauncher-2.3.1.exe
6. Rpcproxy-1.0.1.exe
7. Rpctouch-2.1.0.exe

宿主项目 D:\src\nsa-equation-py：python 包 nsa_equation，__main__.py 用 argparse 子命令注册各模块，模块模式为 reg_subparser(subparsers) + handle(args)。已有子命令：dns/smbv3_scan/smbv3_exp/getarch/netapi32_exp/reternal_blue/rpc_exp。
任务：逆向 7 个 EXE（IDA 静态分析）→ 分别生成 python cli 模块 + 注册子命令。

Eclipsedwing-1.5.2.exe 初步：32 位 PE，导入 adfw-2/tibe-1/trfo-2/trch-0/tucl-1 静态库符号；字符串显示这是 MS08-067 利用工具：初始化参数(TargetIp/TargetPort/CallbackIp/CallbackPort/CallinPort/ListenPort/PayloadDll/FbStorage/CallinTimeout/NetworkTimeout/XorMask 等 egg 与 shellcode 偏移参数字符串)、构建 primer/exploit 包、准备 egg(AuthCode/XOR mask)、回调、RPC proxy。下一步：定位入口与各模块函数，反编译梳理控制流。
Eclipsedwing-1.5.2.exe 分析（IDA）：
- 32 位 PE，入口 0x40530f → 0x405794(__security_cookie 初始化) → ___tmainCRTStartup。
- 导入静态库 adfw-2(工具框架)、tibe-1(TbDoSmbStartup/TbMakeSocket/TbDoRpcRequestEx/TbDoSmbSendData 等 SMB/RPC 客户端)、trfo-2(TfNrvCompress 压缩/TfReadFileIntoBuffer/TfRandomizeBuffer)、trch-1(参数系统)、tucl-1(TcLog 日志)。
- 参数表 (sub_401D10 / InitializeParameters)：NetworkTimeout、CallinTimeout、TargetIp、TargetPort、PayloadDll、FbStorage、LPEntryPoint、LPFilename、ClientName、ServerName、RsaenhBaseAddress、PrefixLength、…大量 shellcode 偏移/值参数(x86 堆喷射 ret 值)…NoNX、CallESP、JmpEDI、xor_key_reg、initial_eax_val、sub_eax_val。
- 字典项：Target 模式(Payload Paramchoice: Callback/Listener/RPCReuse)、Protocol(SMB/NBT)、Payload。
- 流程字符串：[*] Initializing parameters → [*] Building primer / primer request → [*] Priming target → [*] Preparing the egg (EGG XOR Key, AuthCode) → [*] Building exploit / NX capable / Exploit package → [*] Exploiting target → [*] Checking AuthCode → [*] Receiving callback → [*] Cleaning up。
- 网络回调模式：Callback socket creation、ListenPort/CallinPort、RPCReuse 拼接 ServerName+browser。基本可确认是 MS08-067 (NetpwPathCanonicalize, BROWSER/SRVSVC) 利用器框架。

Doublepulsar-1.3.1.exe 字符串（已读）：
- 参数：Function、Architecture、Target(IP?)、Protocol、NetworkTimeout、TargetPort、TargetIp、DllPayload、DllOrdinal、ProcessName、ProcessCommandLine、ShellcodeFile、OutputFile、OutputInstall（以及 RunDLL/RunShellcode/Uninstall 模式）。
- 功能：SMB 后门（DoublePulsar）安装/卸载/运行；Ping 返回目标架构与 XOR Key；DLL 注入(32/64 位校验)、shellcode 写入 OutputFile；使用 SMB 协议(TbDoSmbStartup/TbMakeSmbHeader/TbDoSmbPacket/TbPutTransact)；XDevLib_xorMask/XDevLib_generateRandomSequence；SSL(RDP?) 相关字符串(应为 SSL 库打包，非核心)。
逆向分析完成概要：
1) Eclipsedwing-1.5.2.exe – MS08-067 SMB NetpwPathCanonicalize 利用器，参数：TargetIp/TargetPort、CallbackIp/CallbackPort/CallbackLocalPort、CallinPort/ListenPort、PayloadDll/FbStorage、Protocol(SMB/NBT)、NetworkTimeout/CallinTimeout、Target 模式(Callback/Listener/RPCReuse)、XorMask/EGG、shellcode 偏移表、NoNX。流程：InitializeParameters → InitializeNetwork → BuildPrimer → RunPrimer → PrepareEgg(AuthCode/XOR) → BuildExploit(NX/NONX) → RunExploit → AuthCode check → callback。
2) Eclipsedwingtouch-1.0.4.exe – MS08-067 检测器（Touch），参数：TargetIp/TargetPort、Protocol、NetworkTimeout、ServerName/ClientName、MS08-67/OsPatch、PathName1/2 NetPathCompare 构建 → 判断是否 VULNERABLE/NOT vulnerable。
3) Doublepulsar-1.3.1.exe – DoublePulsar SMB 后门安装器/卸载器，参数：Function(install/uninstall/get/exec)、TargetIp/TargetPort、Protocol、Architecture(32/64)、DllPayload、DllOrdinal、ProcessName/ProcessCommandLine、ShellcodeFile/OutputFile/OutputInstall、NetworkTimeout。操作：ping 后门返回 Arch/XOR Key、安装/卸载、注入 DLL、运行 shellcode。
4) Pcdlllauncher-2.3.1.exe – 后利用 DLL 启动器，复用已建立的 TCP 连接（ConnectedTcp），上传 implant（XOR+NRV 压缩）、发送 Size/Payload、远程 LoadLibrary/GetProcAddress/调入口，参数：PCBehavior、TargetOsArchitecture、NetworkTimeout、XorMask、LPEntryName、ImplantFilename、LPFilename。
5) Rpcproxy-1.0.1.exe – RPC 代理/利用，绑定 BROWSER pipe，上传 implant、发送 PayloadSize/PayloadChunk/PayloadLaunch、通过 SMB+RPC 将 payload 发送给目标，参数：Protocol/VersionMajor/VersionMinor/ServerName/ClientName/LPFilename/LPEntryPoint/ImplantFilename/TargetIp/TargetPort/PollingInterval/NetworkTimeout。
6) Rpctouch-2.1.0.exe – RPC Touch 探测器，探测目标架构/ServicePack/语言、计算 non-paged pool 地址、判断 MS08-067 可利用性，参数：TargetIp/TargetPort、Protocol、NetworkTimeout、NetBIOSName、TouchArchitecture/TouchLanguage、Target(TargetString/TargetDWORD)。
7) danecfg.exe – DANE 配置生成工具，命令行 5 个位置参数：TEMPLATE_DLL PLUGIN_DLL PLUGIN_CORE_DLL CONFIG_XML OUTPUT_DLL。功能：加载插件 DLL 的 marshalParams/freeMarshaledParams/Config_* API、解析 XML、压缩(LZO)、将插件资源写入模板 DLL，生成定制 implant DLL。

接下来创建 Python 子命令模块。
Python CLI 子命令实现完成：
- D:\src\nsa-equation-py\nsa_equation\eclipsedwing\__init__.py + eclipsedwing.py
  → MS08-067 Eclipsedwing 框架，端口号/协议/Callback/Listener/RPCReuse 模式，Egg XOR/ AuthCode、primer/exploit 构建。
- D:\src\nsa-equation-py\nsa_equation\eclipsedwingtouch\__init__.py + eclipsedwingtouch.py
  → MS08-067 Touch 检测器，PathName1/2 NetPathCompare 构建，VULNERABLE/NOT vulnerable 判定。
- D:\src\nsa-equation-py\nsa_equation\doublepulsar\__init__.py + doublepulsar.py
  → DoublePulsar SMB 后门 Ping/Install/Uninstall/RunDLL/RunShellcode，打印 arch/XOR key。
- D:\src\nsa-equation-py\nsa_equation\pcdlllauncher\__init__.py + pcdlllauncher.py
  → 后利用 DLL 启动器，上传 Implant (NRV+XOR)、远程 LoadLibrary/GetProcAddress/EntryPoint。
- D:\src\nsa-equation-py\nsa_equation\rpcproxy\__init__.py + rpcproxy.py
  → RPC Proxy/Implant 投递，SMB BROWSER 绑定、PayloadSize/Chunk/Launch、LP 线程启动。
- D:\src\nsa-equation-py\nsa_equation\rpctouch\__init__.py + rpctouch.py
  → RPC Touch 探测器，OS/ServicePack/语言/架构指纹、非分页池地址计算。
- D:\src\nsa-equation-py\nsa_equation\danecfg\__init__.py + danecfg.py
  → DANE 配置打包器 TEMPLATE_DLL PLUGIN_DLL PLUGIN_CORE_DLL CONFIG_XML OUTPUT_DLL，
     PE 架构校验、plugin marshalParams API 校验、XML 解析、LZO/NRV压缩、资源合并。
- __main__.py 已注册 7 个新子命令：eclipsedwing/eclipsedwingtouch/doublepulsar/pcdlllauncher/rpcproxy/rpctouch/danecfg
- 测试通过：python -m nsa_equation --help 显示全部子命令，各个子命令 --help 返回正常。
