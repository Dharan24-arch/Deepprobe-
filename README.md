<<<<<<< HEAD
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

Or double-click/run:

```powershell
.\launch_deepprobe.bat
```

On Linux/macOS:

```bash
python3 ./network_mapper.py
```

Or run:

```bash
sh ./launch_deepprobe.sh
```

DeepProbe uses Python standard library modules only and is designed to run on Windows, Linux, and macOS with a local desktop session. ICMP discovery uses the operating system `ping` command, MAC lookup uses `arp -a`, and trace route uses `tracert` on Windows or `traceroute` on Linux/macOS. Some networks block ping, so the default setting also probes selected TCP ports.

## Deploy On All Operating Systems

DeepProbe is a desktop GUI application. Deploy it by copying this folder to the target machine and running the launcher for that operating system.

### Windows

1. Install Python 3 from python.org or Microsoft Store.
2. Confirm Tkinter is available:

```powershell
python -m tkinter
```

3. Start DeepProbe:

```powershell
.\launch_deepprobe.bat
```

### Linux

1. Install Python 3 and Tkinter. Examples:

```bash
sudo apt install python3 python3-tk traceroute
sudo dnf install python3 python3-tkinter traceroute
```

2. Start DeepProbe:

```bash
sh ./launch_deepprobe.sh
```

If you want a directly executable launcher:

```bash
chmod +x ./launch_deepprobe.sh
./launch_deepprobe.sh
```

### macOS

1. Install Python 3 from python.org or Homebrew.
2. Confirm Tkinter is available:

```bash
python3 -m tkinter
```

3. Start DeepProbe:

```bash
sh ./launch_deepprobe.sh
```

For Finder double-click launching, make the command file executable:

```bash
chmod +x ./launch_deepprobe.command
```

### Optional Single-File Packaging

For managed deployments, package separately on each target operating system. Build Windows packages on Windows, Linux packages on Linux, and macOS packages on macOS:

```bash
python -m pip install pyinstaller
pyinstaller --onefile --windowed --name DeepProbe network_mapper.py
```

The generated executable will be in `dist/`. Packaging is optional; the source launchers above are the most portable option.

## Accuracy Modes

- `fast`: single TCP-connect check for quicker sweeps.
- `balanced`: default mode; verifies open TCP ports with an extra connection and records confidence.
- `precise`: slower mode; uses longer connect timing and additional verification to reduce missed services on slow or filtered networks.

Each open-port finding includes scan evidence, confidence percentage, probe attempts, connect timing, service purpose, likely weakness, possible attack path, impact, and defense guidance in the GUI and exported reports.

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
=======
# Deepprobe-
>>>>>>> dd333834cbb7db65be5a48356ea0d8241c6d2504
