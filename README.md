# ReconCLI

Advanced reconnaissance automation tool for bug bounty hunters and penetration testers.

## Features

* Subdomain Enumeration (subfinder, assetfinder)
* DNS Resolution (dnsx)
* Alive Host Detection (httpx)
* Technology Fingerprinting
* URL Collection (katana, gau, waybackurls)
* Endpoint Classification
* JavaScript Endpoint Extraction
* Screenshot Automation (gowitness)
* JSON Summary Reports

## Installation

### Clone Repository

```bash
git clone git@github.com:birechamar/ReconCLI.git
cd ReconCLI
```

### Required Tools

Install the following tools before use:

* subfinder
* assetfinder
* dnsx
* httpx
* katana
* gau
* waybackurls
* gowitness

## Usage

```bash
python3 reconcli.py
```

Enter target domain when prompted:

```bash
example.com
```

## Output Structure

```bash
results_target/
├── subs/
├── urls/
├── classified/
├── tech/
├── screenshots/
└── summary.json
```

## Disclaimer

This tool is intended for authorized security testing and educational purposes only.

## License

MIT License
