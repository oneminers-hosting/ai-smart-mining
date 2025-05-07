import requests
import time
import json
import logging
import nmap
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import argparse
import sys
import threading
import queue
import socket
import re
from urllib.parse import urlparse
import yaml
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template, jsonify, request
import statistics
from ratelimit import limits, sleep_and_retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='smart_mining.log',
    filemode='a'
)

class MiningPool:
    def __init__(self, name: str, url: str, luck_api: str, priority: int, coin: str, fee: float, backup_url: str = None):
        self.name = name
        self.url = url
        self.luck_api = luck_api
        self.priority = priority
        self.coin = coin.upper()
        self.fee = fee
        self.backup_url = backup_url
        self.luck = 0.0
        self.hashrate = 0.0
        self.workers = 0
        self.uptime = 0.0
        self.performance_history = []

class ASICMiner:
    def __init__(self, ip: str, username: str, password: str, model: str = "Unknown"):
        self.ip = ip
        self.username = username
        self.password = password
        self.model = model
        self.current_pool = None
        self.hashrate = 0.0
        self.status = "Unknown"
        self.temperature = 0.0
        self.fan_speed = 0
        self.uptime = 0
        self.error_rate = 0.0
        self.performance_history = []

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS pool_stats
                        (timestamp TEXT, pool_name TEXT, coin TEXT, luck REAL, hashrate REAL, workers INTEGER)''')
            c.execute('''CREATE TABLE IF NOT EXISTS miner_stats
                        (timestamp TEXT, miner_ip TEXT, hashrate REAL, temperature REAL, fan_speed INTEGER, error_rate REAL)''')
            conn.commit()

    def log_pool_stats(self, pool: MiningPool):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO pool_stats (timestamp, pool_name, coin, luck, hashrate, workers)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), pool.name, pool.coin, pool.luck, pool.hashrate, pool.workers))
            conn.commit()

    def log_miner_stats(self, miner: ASICMiner):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO miner_stats (timestamp, miner_ip, hashrate, temperature, fan_speed, error_rate)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), miner.ip, miner.hashrate, miner.temperature, miner.fan_speed, miner.error_rate))
            conn.commit()

    def get_pool_history(self, pool_name: str, hours: int = 24) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''SELECT timestamp, luck, hashrate, workers FROM pool_stats
                        WHERE pool_name = ? AND timestamp > ?''',
                      (pool_name, (datetime.now() - timedelta(hours=hours)).isoformat()))
            return [{'timestamp': r[0], 'luck': r[1], 'hashrate': r[2], 'workers': r[3]} for r in c.fetchall()]

    def get_miner_history(self, miner_ip: str, hours: int = 24) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''SELECT timestamp, hashrate, temperature, fan_speed, error_rate FROM miner_stats
                        WHERE miner_ip = ? AND timestamp > ?''',
                      (miner_ip, (datetime.now() - timedelta(hours=hours)).isoformat()))
            return [{'timestamp': r[0], 'hashrate': r[1], 'temperature': r[2], 'fan_speed': r[3], 'error_rate': r[4]} for r in c.fetchall()]

class AlertSystem:
    def __init__(self, smtp_config: Dict, webhook_url: str):
        self.smtp_config = smtp_config
        self.webhook_url = webhook_url

    def send_email_alert(self, subject: str, message: str):
        try:
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = self.smtp_config['from_email']
            msg['To'] = self.smtp_config['to_email']

            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
            logging.info(f"Sent email alert: {subject}")
        except Exception as e:
            logging.error(f"Failed to send email alert: {str(e)}")

    def send_webhook_alert(self, message: Dict):
        try:
            requests.post(self.webhook_url, json=message, timeout=5)
            logging.info(f"Sent webhook alert: {message}")
        except Exception as e:
            logging.error(f"Failed to send webhook alert: {str(e)}")

class SmartMiningUtility:
    def __init__(self, config_path: str):
        self.pools: List[MiningPool] = []
        self.miners: List[ASICMiner] = []
        self.config_path = config_path
        self.monitor_interval = 300
        self.network_range = "192.168.1.0/24"
        self.supported_coins = ["BTC", "LTC", "ETH", "DOGE"]
        self.pool_queue = queue.Queue()
        self.db = Database("mining_stats.db")
        self.alert_system = None
        self.nm = nmap.PortScanner()
        self.app = Flask(__name__)
        self.load_config()
        self.setup_web_routes()

    def load_config(self) -> None:
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            self.network_range = config.get('network_range', self.network_range)
            self.monitor_interval = config.get('monitor_interval', self.monitor_interval)
            smtp_config = config.get('smtp', {})
            webhook_url = config.get('webhook_url', '')
            self.alert_system = AlertSystem(smtp_config, webhook_url)
            
            for pool_config in config.get('pools', []):
                pool = MiningPool(
                    name=pool_config['name'],
                    url=pool_config['url'],
                    luck_api=pool_config['luck_api'],
                    priority=pool_config['priority'],
                    coin=pool_config['coin'],
                    fee=pool_config['fee'],
                    backup_url=pool_config.get('backup_url')
                )
                self.pools.append(pool)
                
            for miner_config in config.get('miners', []):
                miner = ASICMiner(
                    ip=miner_config['ip'],
                    username=miner_config['username'],
                    password=miner_config['password'],
                    model=miner_config.get('model', "Unknown")
                )
                self.miners.append(miner)
                
            logging.info(f"Loaded {len(self.pools)} pools and {len(self.miners)} miners")
        except Exception as e:
            logging.error(f"Failed to load config: {str(e)}")
            raise

    def save_config(self) -> None:
        config = {
            'network_range': self.network_range,
            'monitor_interval': self.monitor_interval,
            'smtp': {
                'server': self.alert_system.smtp_config.get('server', ''),
                'port': self.alert_system.smtp_config.get('port', 587),
                'username': self.alert_system.smtp_config.get('username', ''),
                'password': self.alert_system.smtp_config.get('password', ''),
                'from_email': self.alert_system.smtp_config.get('from_email', ''),
                'to_email': self.alert_system.smtp_config.get('to_email', '')
            },
            'webhook_url': self.alert_system.webhook_url,
            'pools': [
                {
                    'name': pool.name,
                    'url': pool.url,
                    'luck_api': pool.luck_api,
                    'priority': pool.priority,
                    'coin': pool.coin,
                    'fee': pool.fee,
                    'backup_url': pool.backup_url
                } for pool in self.pools
            ],
            'miners': [
                {
                    'ip': miner.ip,
                    'username': miner.username,
                    'password': miner.password,
                    'model': miner.model
                } for miner in self.miners
            ]
        }
        
        with open(self.config_path, 'w') as f:
            yaml.safe_dump(config, f)
        logging.info(f"Configuration saved to {self.config_path}")

    def scan_network(self) -> List[Dict]:
        logging.info(f"Scanning network range: {self.network_range}")
        try:
            self.nm.scan(hosts=self.network_range, arguments='-p80,443,3333 --open')
            miners = []
            
            for host in self.nm.all_hosts():
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp']:
                        if port in [80, 443, 3333]:
                            miner = {
                                'ip': host,
                                'ports': list(self.nm[host]['tcp'].keys()),
                                'status': self.nm[host]['status']['state']
                            }
                            miners.append(miner)
                            logging.info(f"Found potential miner at {host}")
            
            return miners
        except Exception as e:
            logging.error(f"Network scan failed: {str(e)}")
            return []

    def discover_pool(self, url: str) -> Optional[MiningPool]:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json() if response.headers['content-type'].startswith('application/json') else {}
            
            name = data.get('name', urlparse(url).hostname)
            coin = data.get('coin', 'BTC').upper()
            luck_api = f"{url}/stats/luck" if not data.get('luck_api') else data['luck_api']
            fee = float(data.get('fee', 1.0))
            
            pool = MiningPool(
                name=name,
                url=url,
                luck_api=luck_api,
                priority=len(self.pools) + 1,
                coin=coin,
                fee=fee
            )
            logging.info(f"Discovered pool: {name} ({coin})")
            return pool
        except Exception as e:
            logging.error(f"Failed to discover pool at {url}: {str(e)}")
            return None

    @sleep_and_retry
    @limits(calls=10, period=60)
    def get_pool_stats(self, pool: MiningPool) -> Dict:
        try:
            response = requests.get(pool.luck_api, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            pool.luck = float(data.get('luck', 0))
            pool.hashrate = float(data.get('hashrate', 0))
            pool.workers = int(data.get('workers', 0))
            pool.uptime = float(data.get('uptime', 100))
            
            self.db.log_pool_stats(pool)
            pool.performance_history.append({
                'timestamp': datetime.now(),
                'luck': pool.luck,
                'hashrate': pool.hashrate
            })
            pool.performance_history = pool.performance_history[-100:]  # Keep last 100 records
            
            logging.info(f"Pool {pool.name} stats: Luck={pool.luck}%, Hashrate={pool.hashrate}, Workers={pool.workers}, Uptime={pool.uptime}%")
            return {
                'luck': pool.luck,
                'hashrate': pool.hashrate,
                'workers': pool.workers,
                'uptime': pool.uptime
            }
        except Exception as e:
            logging.error(f"Failed to fetch stats for {pool.name}: {str(e)}")
            self.alert_system.send_email_alert(
                f"Pool Failure: {pool.name}",
                f"Failed to fetch stats for {pool.name}: {str(e)}"
            )
            return {}

    def get_miner_stats(self, miner: ASICMiner) -> Dict:
        try:
            url = f"http://{miner.ip}/cgi-bin/minerStatus.cgi"
            response = requests.get(url, auth=(miner.username, miner.password), timeout=10)
            response.raise_for_status()
            data = response.json()
            
            miner.hashrate = float(data.get('hashrate', 0))
            miner.status = data.get('status', 'Unknown')
            miner.temperature = float(data.get('temperature', 0))
            miner.fan_speed = int(data.get('fan_speed', 0))
            miner.uptime = int(data.get('uptime', 0))
            miner.error_rate = float(data.get('error_rate', 0))
            
            self.db.log_miner_stats(miner)
            miner.performance_history.append({
                'timestamp': datetime.now(),
                'hashrate': miner.hashrate,
                'temperature': miner.temperature
            })
            miner.performance_history = miner.performance_history[-100:]
            
            logging.info(f"Miner {miner.ip} stats: Status={miner.status}, Hashrate={miner.hashrate}, Temp={miner.temperature}C")
            return {
                'hashrate': miner.hashrate,
                'status': miner.status,
                'temperature': miner.temperature,
                'fan_speed': miner.fan_speed,
                'uptime': miner.uptime,
                'error_rate': miner.error_rate
            }
        except Exception as e:
            logging.error(f"Failed to fetch stats for miner {miner.ip}: {str(e)}")
            self.alert_system.send_email_alert(
                f"Miner Failure: {miner.ip}",
                f"Failed to fetch stats for miner {miner.ip}: {str(e)}"
            )
            return {}

    def restart_miner(self, miner: ASICMiner) -> bool:
        try:
            url = f"http://{miner.ip}/cgi-bin/reboot.cgi"
            response = requests.post(url, auth=(miner.username, miner.password), timeout=10)
            response.raise_for_status()
            logging.info(f"Restarted miner {miner.ip}")
            self.alert_system.send_webhook_alert({
                'event': 'miner_restart',
                'miner_ip': miner.ip,
                'timestamp': datetime.now().isoformat()
            })
            return True
        except Exception as e:
            logging.error(f"Failed to restart miner {miner.ip}: {str(e)}")
            return False

    def configure_miner_pool(self, miner: ASICMiner, pool: MiningPool) -> bool:
        try:
            url = f"http://{miner.ip}/cgi-bin/set_miner_conf.cgi"
            payload = {
                'pool1url': pool.url,
                'pool1user': f"{miner.username}.worker1",
                'pool1pw': miner.password
            }
            if pool.backup_url:
                payload['pool2url'] = pool.backup_url
            
            response = requests.post(
                url,
                auth=(miner.username, miner.password),
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            miner.current_pool = pool
            logging.info(f"Configured miner {miner.ip} to use pool {pool.name} ({pool.coin})")
            return True
        except Exception as e:
            logging.error(f"Failed to configure miner {miner.ip}: {str(e)}")
            return False

    def calculate_pool_score(self, pool: MiningPool) -> float:
        history = self.db.get_pool_history(pool.name)
        if not history:
            return 0.0
            
        avg_luck = statistics.mean([h['luck'] for h in history]) if history else pool.luck
        avg_hashrate = statistics.mean([h['hashrate'] for h in history]) if history else pool.hashrate
        score = (avg_luck * 0.5) + (avg_hashrate * 0.3) - (pool.fee * 10) + (pool.uptime * 0.2)
        return max(score, 0)

    def select_best_pool(self, coin: str) -> Optional[MiningPool]:
        valid_pools = [pool for pool in self.pools if pool.luck > 0 and pool.coin == coin]
        if not valid_pools:
            logging.warning(f"No valid pools available for {coin}")
            return None
            
        best_pool =physics.set_physics(True)
        best_pool = max(valid_pools, key=lambda p: self.calculate_pool_score(p))
        logging.info(f"Selected best pool for {coin}: {best_pool.name} (Score: {self.calculate_pool_score(best_pool)})")
        return best_pool

    def monitor_pools(self) -> None:
        while True:
            try:
                for pool in self.pools:
                    self.get_pool_stats(pool)
                time.sleep(60)
            except Exception as e:
                logging.error(f"Pool monitoring error: {str(e)}")
                time.sleep(60)

    def monitor_miners(self) -> None:
        while True:
            try:
                for miner in self.miners:
                    stats = self.get_miner_stats(miner)
                    if stats.get('temperature', 0) > 85:
                        self.alert_system.send_email_alert(
                            f"Miner Overheating: {miner.ip}",
                            f"Miner {miner.ip} temperature: {stats.get('temperature')}C"
                        )
                    if stats.get('error_rate', 0) > 5.0 or stats.get('status') == "Offline":
                        self.restart_miner(miner)
                time.sleep(120)
            except Exception as e:
                logging.error(f"Miner monitoring error: {str(e)}")
                time.sleep(60)

    def optimize_mining(self) -> None:
        while True:
            try:
                logging.info("Starting optimization cycle")
                
                for pool in self.pools:
                    self.get_pool_stats(pool)
                
                for coin in self.supported_coins:
                    best_pool = self.select_best_pool(coin)
                    if not best_pool:
                        continue
                        
                    for miner in self.miners:
                        if miner.current_pool != best_pool:
                            success = self.configure_miner_pool(miner, best_pool)
                            if success:
                                logging.info(f"Switched miner {miner.ip} to {best_pool.name} ({coin})")
                
                logging.info(f"Optimization cycle completed. Sleeping for {self.monitor_interval} seconds")
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                logging.error(f"Optimization loop error: {str(e)}")
                time.sleep(60)

    def setup_web_routes(self):
        @self.app.route('/')
        def dashboard():
            return render_template('dashboard.html', miners=self.miners, pools=self.pools)

        @self.app.route('/api/stats')
        def api_stats():
            return jsonify({
                'miners': [{
                    'ip': m.ip,
                    'model': m.model,
                    'hashrate': m.hashrate,
                    'temperature': m.temperature,
                    'fan_speed': m.fan_speed,
                    'status': m.status
                } for m in self.miners],
                'pools': [{
                    'name': p.name,
                    'coin': p.coin,
                    'luck': p.luck,
                    'hashrate': p.hashrate,
                    'workers': p.workers
                } for p in self.pools]
            })

        @self.app.route('/api/history/<type>/<id>')
        def api_history(type, id):
            if type == 'miner':
                history = self.db.get_miner_history(id)
            elif type == 'pool':
                history = self.db.get_pool_history(id)
            else:
                return jsonify({'error': 'Invalid type'}), 400
            return jsonify(history)

    def configuration_utility(self, args: Dict) -> None:
        if args['scan']:
            miners = self.scan_network()
            for miner in miners:
                print(f"Found miner: IP={miner['ip']}, Ports={miner['ports']}, Status={miner['status']}")
                
        if args['add_miner']:
            ip, username, password, model = args['add_miner']
            miner = ASICMiner(ip, username, password, model)
            self.miners.append(miner)
            self.save_config()
            print(f"Added miner: {ip}")
            
        if args['add_pool']:
            url = args['add_pool']
            pool = self.discover_pool(url)
            if pool:
                self.pools.append(pool)
                self.save_config()
                print(f"Added pool: {pool.name} ({pool.coin})")
                
        if args['list']:
            print("\nMiners:")
            for miner in self.miners:
                print(f"IP: {miner.ip}, Model: {miner.model}, Pool: {miner.current_pool.name if miner.current_pool else 'None'}")
            print("\nPools:")
            for pool in self.pools:
                print(f"Name: {pool.name}, Coin: {pool.coin}, URL: {pool.url}, Luck: {pool.luck}%")

    def run(self) -> None:
        pool_thread = threading.Thread(target=self.monitor_pools, daemon=True)
        miner_thread = threading.Thread(target=self.monitor_miners, daemon=True)
        web_thread = threading.Thread(target=lambda: self.app.run(host='0.0.0.0', port=5000), daemon=True)
        
        pool_thread.start()
        miner_thread.start()
        web_thread.start()
        
        self.optimize_mining()

def main():
    parser = argparse.ArgumentParser(description="Smart Mining Utility - Advanced ASIC Miner Management")
    parser.add_argument('--config', default='mining_config.yaml', help='Path to configuration file')
    parser.add_argument('--scan', action='store_true', help='Scan network for miners')
    parser.add_argument('--add-miner', nargs=4, metavar=('IP', 'USERNAME', 'PASSWORD', 'MODEL'),
                        help='Add a new miner (IP, username, password, model)')
    parser.add_argument('--add-pool', help='Add a new pool by URL')
    parser.add_argument('--list', action='store_true', help='List all miners and pools')
    
    args = parser.parse_args()
    
    try:
        utility = SmartMiningUtility(args.config)
        
        if any([args.scan, args.add_miner, args.add_pool, args.list]):
            utility.configuration_utility(vars(args))
        else:
            utility.run()
            
    except KeyboardInterrupt:
        logging.info("Smart Mining Utility stopped by user")
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
