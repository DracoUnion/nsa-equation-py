# nsa-equation-py

Python reimplementations of legacy tooling (e.g. the DNS payload-builder derived from `dns.exe` via IDA Pro).

## Usage

```bash
nsa-equation-py dns -y bind -R 1.2.3.4 -p 1100
nsa-equation-py dns --list
```

See `dns --help` for all available options (they are forwarded verbatim to `dns_tool`).