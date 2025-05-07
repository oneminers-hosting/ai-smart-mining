# ai-smart-mining
AI smart mining utility for Bitcoin mining on ASIC miners

Smart Mining Utility

An open-source Python tool for monitoring and optimizing ASIC miners on a local network. This utility scans for miners, monitors mining pool performance, and intelligently switches miners to the most profitable pools based on luck and other metrics. It supports multiple cryptocurrencies including Bitcoin (BTC), Litecoin (LTC), Ethereum (ETH), and Dogecoin (DOGE).

Features





Network Scanning: Automatically discovers ASIC miners on the local network using nmap.



Pool Monitoring: Tracks pool luck, hashrate, and worker count for multiple pools.



Smart Pool Switching: Switches miners to the best pool based on luck and priority.



Multi-Coin Support: Configurable for various cryptocurrencies.



Configuration Utility: Command-line interface to add miners, pools, and list configurations.



Real-Time Monitoring: Monitors miner status, hashrate, and temperature with overheating alerts.



YAML Configuration: Easy-to-edit configuration file for miners and pools.



Logging: Detailed logs for debugging and monitoring.

Prerequisites





Python 3.8+



nmap installed on your system



Network access to ASIC miners and pool APIs

Installation





Clone the repository:

git clone https://github.com/yourusername/smart-mining-utility.git
cd smart-mining-utility



Install Python dependencies:

pip install requests pyyaml python-nmap



Install nmap:





On Ubuntu/Debian:

sudo apt-get install nmap



On macOS:

brew install nmap



On Windows: Download and install from nmap.org

Configuration

Edit mining_config.yaml to configure your network, miners, and pools. Example configuration:

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





network_range: CIDR notation for your local network.



monitor_interval: Seconds between optimization cycles.



pools: List of mining pools with their stratum URLs, luck APIs, priorities, and coin types.



miners: List of ASIC miners with their IP addresses, credentials, and models.

Usage

Run the utility with the following commands:

Start the Mining Utility

python smart_mining_utility.py --config mining_config.yaml

Configuration Commands





Scan for miners:

python smart_mining_utility.py --config mining_config.yaml --scan



Add a miner:

python smart_mining_utility.py --config mining_config.yaml --add-miner 192.168.1.102 admin admin Antminer_S19



Add a pool:

python smart_mining_utility.py --config mining_config.yaml --add-pool http://pool3.example.com



List configuration:

python smart_mining_utility.py --config mining_config.yaml --list

Notes





Miner APIs: The utility assumes miners support HTTP-based configuration (e.g., CGMiner API). Modify configure_miner_pool in smart_mining_utility.py for specific miner models or protocols (e.g., SSH).



Pool APIs: Pool APIs should return JSON with luck, hashrate, and workers. Adjust get_pool_stats for specific API formats.



Security: Ensure miner credentials are secure and the network is protected.



Logging: Logs are saved to smart_mining.log for debugging and monitoring.

Contributing

Contributions are welcome! Please follow these steps:





Fork the repository.



Create a new branch (git checkout -b feature/your-feature).



Commit your changes (git commit -m 'Add your feature').



Push to the branch (git push origin feature/your-feature).



Open a Pull Request.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments





Built with Python and open-source libraries.



Designed for ASIC miners such as Antminer and Whatsminer.



Inspired by the need for efficient mining pool management.

Contact

For issues or questions, please open an issue on GitHub or contact info@oneminers.com
