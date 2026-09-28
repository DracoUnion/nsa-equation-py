"""dns — DNS payload-builder tool.

Python rewrite of the DNS payload-builder logic reverse-engineered from
`dns.exe` via IDA Pro.  The real logic lives in :mod:`nsa_equation.dns.dns_tool`;
this module only wires it up as a CLI subcommand.
"""

import argparse

from . import dns_tool


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def dns_handle(args):
    """Parse and run the dns payload-builder against the forwarded raw args."""
    ctx = dns_tool.parse_options(args.args or [])
    dns_tool.log("[.] - done parsing; errors=%d", ctx.errors)


def reg_subparser(subparsers):
    """Register the `dns` subcommand on an argparse parser / subparsers group."""
    dns_parser = subparsers.add_parser(
        "dns", help="DNS payload 构建工具（dns.exe 的 Python 重写）",
        description="DNS 负载构建器。选项透传给 dns_tool，例如 -y <payload> -R <ip> -p <port> 等。"
    )
    # dns_tool keeps its own option parser; forward whatever follows `dns`
    # verbatim (nargs=REMAINDER leaves it untouched by argparse).
    dns_parser.add_argument(
        "args", nargs=argparse.REMAINDER,
        help="透传给 dns_tool 的原始参数（如 -y bind -R 1.2.3.4 -p 1100）",
    )
    dns_parser.set_defaults(func=dns_handle)