#!/usr/bin/env python3
import os
import sys
import time
import socket
import threading
import subprocess
import random
import json
import platform
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import requests
import psutil
import readline  # for better command line input

# Configuration
CONFIG_FILE = "netmon_config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "monitored_ips": [],
    "traffic_threshold": 1000,  # packets per second
    "theme": {
        "primary": "\033[91m",  # red
        "secondary": "\033[31m",  # dark red
        "info": "\033[93m",  # yellow
        "success": "\033[92m",  # green
        "reset": "\033[0m",
        "banner": """
        \033[91m
   ___  _____ ______ _   _ _____  _____ _____ _   _ 
  / _ \|  _  \| ___ \ | | |  ___|/  ___|  ___| \ | |
 / /_\ \ | | || |_/ / | | | |__  \ `--.| |__ |  \| |
 |  _  | | | ||    /| | | |  __|  `--. \  __|| . ` |
 | | | \ \_/ /| |\ \\\\ \_/ / |___ /\__/ / |___| |\  |
 \_| |_/\___/ \_| \_|\___/\____/ \____/\____/\_| \_/
 \033[0m
        """
    }
}

# Global variables
monitoring_active = False
traffic_generation_active = False
current_status = "Idle"
monitored_ips = []
packet_counts = {}
telegram_bot = None
last_report = {}
traffic_thread = None
monitor_thread = None

class TelegramBot:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}/"

    def send_message(self, text):
        url = self.base_url + "sendMessage"
        data = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            response = requests.post(url, data=data)
            return response.json()
        except Exception as e:
            print(f"Error sending Telegram message: {e}")
            return None

    def send_document(self, file_path, caption=""):
        url = self.base_url + "sendDocument"
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': self.chat_id, 'caption': caption}
            try:
                response = requests.post(url, files=files, data=data)
                return response.json()
            except Exception as e:
                print(f"Error sending document to Telegram: {e}")
                return None

def load_config():
    global monitored_ips, telegram_bot
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                CONFIG.update(config)
                monitored_ips = CONFIG.get('monitored_ips', [])
                if CONFIG['telegram_token'] and CONFIG['telegram_chat_id']:
                    telegram_bot = TelegramBot(CONFIG['telegram_token'], CONFIG['telegram_chat_id'])
                return True
    except Exception as e:
        print(f"Error loading config: {e}")
    return False

def save_config():
    CONFIG['monitored_ips'] = monitored_ips
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(CONFIG, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

def print_color(text, color_type="primary"):
    color = CONFIG['theme'].get(color_type, CONFIG['theme']['primary'])
    print(f"{color}{text}{CONFIG['theme']['reset']}")

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def display_banner():
    clear_screen()
    print_color(CONFIG['theme']['banner'], "banner")
    print_color(f"Network Monitoring & Traffic Generation Tool", "secondary")
    print_color(f"Version 2.0 | Status: {current_status}", "info")
    print()

def ping_ip(ip):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', ip]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print_color(f"Ping results for {ip}:", "info")
        print(output)
        return True
    except subprocess.CalledProcessError as e:
        print_color(f"Failed to ping {ip}: {e.output}", "secondary")
        return False

def traceroute(ip):
    try:
        param = '-d' if platform.system().lower() == 'windows' else ''
        command = ['tracert', param, ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print_color(f"Traceroute to {ip}:", "info")
        print(output)
        return True
    except subprocess.CalledProcessError as e:
        print_color(f"Failed to traceroute {ip}: {e.output}", "secondary")
        return False

def netstat_info(ip=None):
    try:
        connections = psutil.net_connections()
        print_color("Active Network Connections:", "info")
        
        if ip:
            filtered = [conn for conn in connections if conn.raddr and conn.raddr.ip == ip]
            connections = filtered
            
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                print(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} [{conn.status}]")
        return True
    except Exception as e:
        print_color(f"Failed to get netstat info: {e}", "secondary")
        return False

def generate_traffic(target_ip, duration=60, intensity=10):
    global traffic_generation_active, current_status
    traffic_generation_active = True
    current_status = f"Generating traffic to {target_ip}"
    
    packets_sent = 0
    start_time = time.time()
    
    print_color(f"Starting traffic generation to {target_ip} for {duration} seconds", "info")
    
    if telegram_bot:
        telegram_bot.send_message(f"🚀 Starting traffic generation to {target_ip} for {duration} seconds")
    
    protocols = [TCP, UDP]
    ports = [80, 443, 22, 21, 53, 3389]
    
    try:
        while time.time() - start_time < duration and traffic_generation_active:
            # Randomize packet parameters
            protocol = random.choice(protocols)
            sport = random.randint(1024, 65535)
            dport = random.choice(ports)
            payload = random._urandom(random.randint(100, 1500))
            
            # Create and send packet
            packet = IP(dst=target_ip)/protocol(sport=sport, dport=dport)/payload
            send(packet, verbose=0)
            packets_sent += 1
            
            # Adjust intensity
            time.sleep(1.0 / intensity)
            
            # Randomly vary intensity
            if random.random() < 0.1:
                intensity = random.randint(5, 20)
    
    except Exception as e:
        print_color(f"Traffic generation error: {e}", "secondary")
    
    traffic_generation_active = False
    current_status = "Idle"
    end_time = time.time()
    duration_actual = end_time - start_time
    rate = packets_sent / duration_actual if duration_actual > 0 else 0
    
    report = {
        "target_ip": target_ip,
        "start_time": datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S'),
        "end_time": datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S'),
        "duration_seconds": round(duration_actual, 2),
        "total_packets": packets_sent,
        "packets_per_second": round(rate, 2),
        "status": "Completed" if duration_actual >= duration else "Interrupted"
    }
    
    print_color("\nTraffic Generation Report:", "info")
    for key, value in report.items():
        print(f"{key:>20}: {value}")
    
    # Save report
    report_filename = f"traffic_report_{target_ip}_{int(start_time)}.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=4)
    
    if telegram_bot:
        telegram_bot.send_message(
            f"📊 Traffic Generation Report for {target_ip}:\n"
            f"Duration: {round(duration_actual, 2)}s\n"
            f"Packets Sent: {packets_sent}\n"
            f"Rate: {round(rate, 2)} pkt/s\n"
            f"Status: {report['status']}"
        )
        telegram_bot.send_document(report_filename, f"Traffic report for {target_ip}")
    
    return report

def packet_handler(packet):
    global packet_counts
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if either src or dst is in our monitored IPs
        monitored_ip = None
        if src_ip in monitored_ips:
            monitored_ip = src_ip
        elif dst_ip in monitored_ips:
            monitored_ip = dst_ip
            
        if monitored_ip:
            # Update packet count
            if monitored_ip not in packet_counts:
                packet_counts[monitored_ip] = {'count': 0, 'timestamps': []}
            
            packet_counts[monitored_ip]['count'] += 1
            packet_counts[monitored_ip]['timestamps'].append(time.time())
            
            # Check for traffic spikes
            timestamps = packet_counts[monitored_ip]['timestamps']
            now = time.time()
            
            # Remove timestamps older than 1 second
            timestamps = [t for t in timestamps if now - t <= 1]
            packet_counts[monitored_ip]['timestamps'] = timestamps
            
            # Check threshold
            if len(timestamps) > CONFIG['traffic_threshold']:
                alert_msg = f"🚨 High traffic detected for {monitored_ip}: {len(timestamps)} pkt/s (threshold: {CONFIG['traffic_threshold']})"
                print_color(alert_msg, "secondary")
                if telegram_bot:
                    telegram_bot.send_message(alert_msg)

def start_monitoring():
    global monitoring_active, monitor_thread, current_status
    
    if not monitored_ips:
        print_color("No IPs to monitor. Use 'add ip' first.", "secondary")
        return
    
    if monitoring_active:
        print_color("Monitoring is already active.", "info")
        return
    
    monitoring_active = True
    current_status = f"Monitoring {len(monitored_ips)} IP(s)"
    
    print_color(f"Starting network monitoring for IPs: {', '.join(monitored_ips)}", "info")
    
    if telegram_bot:
        telegram_bot.send_message(f"👁️ Starting network monitoring for IPs: {', '.join(monitored_ips)}")
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=sniff, kwargs={
        'prn': packet_handler,
        'store': 0,
        'filter': f"ip and ( {' or '.join([f'host {ip}' for ip in monitored_ips])} )"
    })
    monitor_thread.daemon = True
    monitor_thread.start()

def stop_monitoring():
    global monitoring_active, current_status
    
    if not monitoring_active:
        print_color("Monitoring is not active.", "info")
        return
    
    monitoring_active = False
    current_status = "Idle"
    
    # Stop sniffing by creating a dummy packet
    send(IP(dst="127.0.0.1")/ICMP(), verbose=0)
    
    print_color("Network monitoring stopped.", "info")
    
    if telegram_bot:
        telegram_bot.send_message("🛑 Network monitoring stopped")

def stop_traffic_generation():
    global traffic_generation_active, current_status
    
    if not traffic_generation_active:
        print_color("Traffic generation is not active.", "info")
        return
    
    traffic_generation_active = False
    current_status = "Idle"
    print_color("Stopping traffic generation...", "info")
    
    if telegram_bot:
        telegram_bot.send_message("🛑 Traffic generation stopped")

def export_to_telegram():
    if not telegram_bot:
        print_color("Telegram bot not configured.", "secondary")
        return
    
    # Create a status report
    report = {
        "status": current_status,
        "monitored_ips": monitored_ips,
        "telegram_chat_id": CONFIG['telegram_chat_id'],
        "packet_counts": {ip: data['count'] for ip, data in packet_counts.items()}
    }
    
    # Save to temporary file
    report_filename = "network_status_report.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=4)
    
    # Send via Telegram
    if telegram_bot.send_document(report_filename, "Network Status Report"):
        print_color("Report sent to Telegram successfully.", "success")
    else:
        print_color("Failed to send report to Telegram.", "secondary")
    
    os.remove(report_filename)

def view_status():
    print_color("\nCurrent System Status", "info")
    print(f"{'Status:':>20} {current_status}")
    print(f"{'Monitoring Active:':>20} {'Yes' if monitoring_active else 'No'}")
    print(f"{'Traffic Generation Active:':>20} {'Yes' if traffic_generation_active else 'No'}")
    
    print_color("\nMonitored IPs", "info")
    for ip in monitored_ips:
        count = packet_counts.get(ip, {}).get('count', 0)
        print(f"{ip:>20}: {count} packets")
    
    print_color("\nTelegram Configuration", "info")
    print(f"{'Bot Configured:':>20} {'Yes' if telegram_bot else 'No'}")
    if telegram_bot:
        print(f"{'Chat ID:':>20} {CONFIG['telegram_chat_id']}")

def add_ip(ip):
    if ip in monitored_ips:
        print_color(f"IP {ip} is already being monitored.", "info")
        return
    
    # Validate IP address
    try:
        socket.inet_aton(ip)
        monitored_ips.append(ip)
        packet_counts[ip] = {'count': 0, 'timestamps': []}
        save_config()
        print_color(f"Added IP {ip} to monitoring list.", "success")
        
        if telegram_bot:
            telegram_bot.send_message(f"➕ Added IP {ip} to monitoring list")
    except socket.error:
        print_color(f"Invalid IP address: {ip}", "secondary")

def delete_ip(ip):
    if ip not in monitored_ips:
        print_color(f"IP {ip} is not being monitored.", "info")
        return
    
    monitored_ips.remove(ip)
    packet_counts.pop(ip, None)
    save_config()
    print_color(f"Removed IP {ip} from monitoring list.", "success")
    
    if telegram_bot:
        telegram_bot.send_message(f"➖ Removed IP {ip} from monitoring list")

def config_telegram(token, chat_id):
    CONFIG['telegram_token'] = token
    CONFIG['telegram_chat_id'] = chat_id
    global telegram_bot
    telegram_bot = TelegramBot(token, chat_id)
    save_config()
    print_color("Telegram bot configured successfully.", "success")
    
    # Test the configuration
    if telegram_bot.send_message("🔔 Test message from Network Monitoring Tool"):
        print_color("Telegram test message sent successfully.", "success")
    else:
        print_color("Failed to send Telegram test message.", "secondary")

def print_help():
    print_color("\nAvailable Commands:", "info")
    print("help                 - Show this help message")
    print("exit                 - Exit the program")
    print("clear                - Clear the screen")
    print("ping <ip>            - Ping an IP address")
    print("tracert <ip>         - Trace route to an IP address")
    print("netstat [ip]         - Show network connections (optionally filtered by IP)")
    print("start monitoring     - Start monitoring network traffic")
    print("stop                 - Stop monitoring or traffic generation")
    print("view                 - View current status")
    print("add <ip>             - Add an IP to monitor")
    print("delete <ip>          - Remove an IP from monitoring")
    print("generate <ip> [duration] [intensity] - Generate network traffic")
    print("export               - Export current status to Telegram")
    print("config telegram <token> <chat_id> - Configure Telegram bot")
    print("status               - Show detailed status information")

def main():
    global traffic_generation_active, monitoring_active, current_status, CONFIG
    
    # Load configuration
    if not load_config():
        print_color("Using default configuration", "info")
    
    # Initialize packet counts for monitored IPs
    for ip in monitored_ips:
        packet_counts[ip] = {'count': 0, 'timestamps': []}
    
    display_banner()
    
    # Main command loop
    while True:
        try:
            command = input(f"{CONFIG['theme']['primary']}netmon> {CONFIG['theme']['reset']}").strip().lower()
            
            if not command:
                continue
                
            elif command == "help":
                print_help()
                
            elif command == "exit":
                if monitoring_active or traffic_generation_active:
                    confirm = input("Monitoring or traffic generation is active. Are you sure you want to exit? (y/n): ")
                    if confirm.lower() != 'y':
                        continue
                
                stop_monitoring()
                stop_traffic_generation()
                print_color("Exiting...", "info")
                break
                
            elif command == "clear":
                clear_screen()
                display_banner()
                
            elif command.startswith("ping "):
                ip = command[5:].strip()
                ping_ip(ip)
                
            elif command.startswith("tracert "):
                ip = command[8:].strip()
                traceroute(ip)
                
            elif command.startswith("netstat"):
                parts = command.split()
                ip = parts[1] if len(parts) > 1 else None
                netstat_info(ip)
                
            elif command == "start monitoring":
                start_monitoring()
                
            elif command == "stop":
                if monitoring_active:
                    stop_monitoring()
                elif traffic_generation_active:
                    stop_traffic_generation()
                else:
                    print_color("Nothing to stop.", "info")
                    
            elif command == "view":
                view_status()
                
            elif command == "status":
                view_status()
                
            elif command.startswith("add "):
                ip = command[4:].strip()
                add_ip(ip)
                
            elif command.startswith("delete "):
                ip = command[7:].strip()
                delete_ip(ip)
                
            elif command.startswith("generate "):
                parts = command.split()
                if len(parts) < 2:
                    print_color("Usage: generate <ip> [duration=60] [intensity=10]", "secondary")
                    continue
                
                ip = parts[1]
                duration = int(parts[2]) if len(parts) > 2 else 60
                intensity = int(parts[3]) if len(parts) > 3 else 10
                
                if traffic_generation_active:
                    print_color("Traffic generation is already active.", "info")
                    continue
                
                # Start traffic generation in a separate thread
                threading.Thread(
                    target=generate_traffic,
                    args=(ip, duration, intensity),
                    daemon=True
                ).start()
                
            elif command == "export":
                export_to_telegram()
                
            elif command.startswith("config telegram "):
                parts = command.split()
                if len(parts) != 4:
                    print_color("Usage: config telegram <token> <chat_id>", "secondary")
                    continue
                
                token = parts[2]
                chat_id = parts[3]
                config_telegram(token, chat_id)
                
            else:
                print_color(f"Unknown command: {command}", "secondary")
                print("Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit or 'help' for commands.")
            
        except Exception as e:
            print_color(f"Error: {e}", "secondary")

if __name__ == "__main__":
    # Initialize CONFIG as a global variable
    CONFIG = DEFAULT_CONFIG.copy()
    main()