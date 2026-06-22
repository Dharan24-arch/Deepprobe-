# DeepProbe

DeepProbe is a Python GUI network mapping tool for authorized cybersecurity assessments. It is designed to feel easier than command-line scanners while adding detailed evidence, local AI-style triage, ethical-hacking themed visuals, and exportable reporting.

## Features

- CIDR, hostname, comma-separated, and multiline targets
- Quick, deep, web, Windows/AD, database, range-based, custom, or full TCP port scans
- Ping discovery with optional TCP probing for hosts that block ICMP
- Banner grabbing for common services
- HTTP title and server-header fingerprinting
- TLS cipher and certificate common-name collection where available
- UDP-lite checks for DNS, NTP, and SNMP when enabled
- Optional traceroute path collection
- Basic OS/service role guesses using ports and TTL hints
- Local DeepProbe AI Intel summaries with findings, per-port attack impact explanations, and recommendations
- Risk scoring for exposed management, file sharing, database, remote access, and infrastructure services
- Professional security-console dark GUI with styled live topology map, host vulnerability analysis panel, and operations console
- JSON, CSV, and HTML export with weaknesses, possible attack paths, impact, and defenses
- Built with Python standard library modules only

## Run

```powershell
python .\network_mapper.py
```

On Windows, ICMP discovery uses the built-in `ping` command, MAC lookup uses `arp -a`, and trace route uses `tracert`. Some networks block ping, so the default setting also probes selected TCP ports.

## Scan Profiles

- `quick`
- `deep`
- `web`
- `windows`
- `databases`
- `20-1024`
- `80,443,445,3389,5985`
- `all`

Custom port lists and ranges can be combined:

```text
22,80,443,8000-8100,3389
```

## Advanced Options

- **TCP discovery when ping is blocked**: continues TCP probing even if ICMP ping fails.
- **Deep banner + HTTP/TLS fingerprinting**: gathers banners, web titles, web server headers, and TLS hints.
- **UDP-lite DNS/NTP/SNMP**: sends safe UDP probes only to selected DNS, NTP, and SNMP ports.
- **Trace route**: records up to 8 route hops for reachable hosts.

## Ethical Use

Only scan systems you own or have explicit permission to assess. Start with `quick` or `deep` on a small CIDR such as `/24`, then narrow or expand port coverage as needed.

## Limitations

DeepProbe does not try to replace Nmap's raw packet engine, NSE scripts, or privileged SYN scanning. It focuses on an advanced GUI, TCP-connect scanning, lightweight UDP checks, service evidence, risk triage, per-port security explanations, and reporting in pure Python.
