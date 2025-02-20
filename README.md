# VLAN Scanner by Swack3r

## Description
VLAN Scanner is a CLI tool for Kali Linux that passively detects VLANs on a selected network interface by sniffing 802.1Q tagged packets. It is useful for penetration testers and network administrators to identify accessible VLANs.

## Features
- Detects VLANs passively (no active probes required)
- Supports both wired (eth0) and wireless (wlan0) interfaces
- Ignores loopback (`lo`) automatically
- Provides real-time updates of detected VLANs
- Checks if the script is run as root and provides a warning if not
- Uses `termcolor` for colored output in the terminal

## Requirements
- Kali Linux or any Linux distribution with Scapy support
- Python 3
- Required Python libraries:
  - `scapy`
  - `termcolor`

## Installation
To install the necessary dependencies, run the following command:
```bash
sudo apt update && sudo apt install -y python3 python3-pip
pip3 install scapy termcolor
```

## Usage
Clone this repository and navigate to the directory:
```bash
git clone https://github.com/yourusername/vlan-scanner.git
cd vlan-scanner
```
Run the script with:
```bash
sudo python3 vlan_scanner.py
```
To specify a network interface:
```bash
sudo python3 vlan_scanner.py -i eth0
```

## Notes
- This tool requires **root** privileges to capture network traffic.
- VLAN discovery relies on capturing **802.1Q tagged packets**, so results may vary based on the network environment.

## License
MIT License

## Disclaimer
This tool is for educational and security auditing purposes only. Unauthorized use on networks without permission is prohibited.

