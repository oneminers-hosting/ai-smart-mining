# Smart Mining Utility

**An open-source Python tool** for monitoring and optimizing ASIC miners on a local network. This utility scans for miners, monitors mining pool performance, and intelligently switches miners to the most profitable pools based on luck and other metrics. It supports multiple cryptocurrencies, including **Bitcoin (BTC)**, **Litecoin (LTC)**, **Ethereum (ETH)**, and **Dogecoin (DOGE)**.

---

## Features

- **Network Scanning**: Automatically discovers ASIC miners on the local network using `nmap`.
- **Pool Monitoring**: Tracks pool luck, hashrate, and worker count for multiple pools.
- **Smart Pool Switching**: Switches miners to the best pool based on luck and priority.
- **Multi-Coin Support**: Configurable for various cryptocurrencies.
- **Configuration Utility**: Command-line interface to add miners, pools, and list configurations.
- **Real-ITime Monitoring**: Monitors miner status, hashrate, and temperature with overheating alerts.
- **YAML Configuration**: Easy-to-edit configuration file for miners and pools.
- **Logging**: Detailed logs for debugging and monitoring.

---

## Prerequisites

- **Python 3.8+**
- `nmap` installed on your system
- Network access to ASIC miners and pool APIs

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/smart-mining-utility.git
   cd smart-mining-utility
   ```

2. **Install Python dependencies**:
   ```bash
   pip install requests pyyaml python-nmap
   ```

3. **Install `nmap`**:
   - **Ubuntu/Debian**:
     ```bash
     sudo apt-get install nmap
     ```
   - **macOS**:
     ```bash
     brew install nmap
     ```
   - **Windows**: Download and install from [nmap.org](https://nmap.org/download.html)

---

## Configuration

Edit `mining_config.yaml` to configure your network, miners, and pools. Below is an example configuration:

```yaml
network_range: "192.168.1.0/24"
monitor_interval: 300
pools:
  - name: "Pool1"
    url: "stratum+tcp://pool1.example.com:3333"
    luck_api: "https://api.pool1.example.com/stats/luck"
    priority: 1
    coin: "BTC"
  - name: "Pool2"
    url: "stratum+tcp://pool2.example.com:3333"
    luck_api: "https://api.pool2.example.com/stats/luck"
    priority: 2
    coin: "LTC"
miners:
  - ip: "192.168.1.100"
    username: "admin"
    password: "admin"
    model: "Antminer S19"
  - ip: "192.168.1.101"
    username: "admin"
    password: "admin"
    model: "Whatsminer M30S"
```

### Configuration Fields

- `network_range`: CIDR notation for your local network (e.g., `192.168.1.0/24`).
- `monitor_interval`: Seconds between optimization cycles (e.g., `300` for 5 minutes).
- `pools`: List of mining pools with their stratum URLs, luck APIs, priorities, and coin types.
- `miners`: List of ASIC miners with their IP addresses, credentials, and models.

---

## Usage

Run the utility using the following commands:

### Start the Mining Utility

```bash
python smart_mining_utility.py --config mining_config.yaml
```

### Configuration Commands

- **Scan for miners**:
  ```bash
  python smart_mining_utility.py --config mining_config.yaml --scan
  ```

- **Add a miner**:
  ```bash
  python smart_mining_utility.py --config mining_config.yaml --add-miner 192.168.1.102 admin admin Antminer_S19
  ```

- **Add a pool**:
  ```bash
  python smart_mining_utility.py --config mining_config.yaml --add-pool http://pool3.example.com
  ```

- **List configuration**:
  ```bash
  python smart_mining_utility.py --config mining_config.yaml --list
  ```

---

## Important Notes

- **Miner APIs**: The utility assumes miners support HTTP-based configuration (e.g., CGMiner API). Modify the `configure_miner_pool` function in `smart_mining_utility.py` for specific miner models or protocols (e.g., SSH).
- **Pool APIs**: Pool APIs should return JSON with `luck`, `hashrate`, and `workers` fields. Adjust the `get_pool_stats` function for specific API formats.
- **Security**: Ensure miner credentials are secure and the network is protected from unauthorized access.
- **Logging**: Logs are saved to `smart_mining.log` for debugging and monitoring.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add your feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/your-feature
   ```
5. Open a Pull Request on GitHub.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Built with Python and open-source libraries: `requests`, `pyyaml`, `python-nmap`.
- Designed for ASIC miners such as **Antminer** and **Whatsminer**.
- Inspired by the need for efficient and automated mining pool management.

---

## Contact

For issues, questions, or suggestions, please:
- Open an issue on [GitHub](https://github.com/yourusername/smart-mining-utility/issues).
- Contact [your email or preferred contact method].
![image](https://github.com/user-attachments/assets/00ffbbc1-97fc-4c8e-a9be-51f91453b687)
