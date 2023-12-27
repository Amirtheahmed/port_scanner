# Python Port Scanner

This Python Port Scanner is a simple tool that scans for open ports on a network. It can scan a specified range of IP addresses or random IPs for a given set of ports. This script is useful for network administrators and cybersecurity enthusiasts who need to monitor network security or identify potential vulnerabilities.

## Features

- Scans specified IP range or random IP addresses for open ports.
- Customizable port range for scanning.
- Simple and easy-to-use command-line interface.

## Prerequisites

Before you begin, ensure you have the following requirements:

- Python 3.x installed on your system.

## Installation

No additional installation is required. The script uses standard Python libraries.

## Usage

To use the Python Port Scanner, you can specify the IP range and ports via command-line arguments:

`python -m src.port_scanner -r <IPRANGE> -p <PORTNUMBERS>`


### Arguments

- `-r` or `--range`: Specify the IP range to scan. Format: `start_ip-end_ip` (e.g., `192.168.1.1-192.168.1.255`). If this argument is omitted, the script will scan random IP addresses.
- `-p` or `--ports`: Comma-separated port numbers to scan (e.g., `80,443`).

### Example

`python -m src.port_scanner.py -r 192.168.1.1-192.168.1.255 -p 80,443`


This command will scan the IP range `192.168.1.1` to `192.168.1.255` for open ports 80 and 443.

## Output

The script outputs the results to the console, indicating whether each port on each IP address is open or closed.

## Warning

Port scanning can be interpreted as a hostile or intrusive act by network administrators. Always have explicit permission before scanning networks that you do not own or operate.

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgments

- Original script concept in Perl by [sizeof(cat)](https://github.com/sizeofcat).
  - Python adaptation by [Amirtheahmed](https://github.com/Amirtheahmed).

---

For any additional information or inquiries, feel free to open an issue on this repository.
