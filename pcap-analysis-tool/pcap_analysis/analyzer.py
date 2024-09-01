from scapy.all import rdpcap
from collections import defaultdict, Counter
import csv
from datetime import datetime, timedelta
import numpy as np
import math
import re

def calculate_entropy(counts):
    if not counts:
        return 0
    total = sum(counts.values())
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

def extract_login_info(packet):
    # This is a placeholder function. You'll need to adapt this based on your specific protocol.
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load.decode('utf-8', errors='ignore')
        username_match = re.search(r'username[=:]\s*(\S+)', payload, re.IGNORECASE)
        password_match = re.search(r'password[=:]\s*(\S+)', payload, re.IGNORECASE)
        success_match = re.search(r'login_status[=:]\s*(\w+)', payload, re.IGNORECASE)
        return (username_match.group(1) if username_match else None,
                password_match.group(1) if password_match else None,
                success_match.group(1).lower() == 'success' if success_match else False)
    return None, None, False

def analyze_pcap(pcap_file, dst_ip, dst_port, time_window=60, burst_window=5):
    packets = rdpcap(pcap_file)

    filtered_packets = [pkt for pkt in packets if pkt.haslayer('IP') and pkt['IP'].dst == dst_ip and 
                        (pkt.haslayer('TCP') or pkt.haslayer('UDP')) and 
                        (pkt.haslayer('TCP') and pkt['TCP'].dport == dst_port or 
                         pkt.haslayer('UDP') and pkt['UDP'].dport == dst_port)]
    filtered_packets.sort(key=lambda x: float(x.time))

    if not filtered_packets:
        print("No packets found matching the specified criteria.")
        return None

    start_time = datetime.fromtimestamp(float(filtered_packets[0].time))
    current_time = start_time
    window_data = defaultdict(lambda: {
        "login_frequency": 0,
        "inter_login_times": [],
        "login_burst_count": 0,
        "unique_source_ips": set(),
        "ip_counts": Counter(),
        "new_ips": set(),
        "total_ips": set(),
        "ip_entropy": 0,
        "new_ip_ratio": 0,
        "unique_source_ports": set(),
        "port_counts": Counter(),
        "port_entropy": 0,
        "protocol_changes": 0,
        "last_protocol": None,
        "unique_usernames": set(),
        "username_counts": Counter(),
        "username_entropy": 0,
        "password_counts": Counter(),
        "password_entropy": 0,
        "successful_logins": 0,
        "account_attempts": Counter(),
        "packet_sizes": [],
        "total_failed_attempts": 0,
        "distinct_ip_port_combinations": set()
    })

    all_ips = set()
    prev_time = None
    burst_start_time = None

    for packet in filtered_packets:
        packet_time = datetime.fromtimestamp(float(packet.time))
        source_ip = packet['IP'].src
        source_port = packet['TCP'].sport if packet.haslayer('TCP') else packet['UDP'].sport
        protocol = 'TCP' if packet.haslayer('TCP') else 'UDP'

        # Extract username, password, and login status
        username, password, login_success = extract_login_info(packet)

        # Move to next window if necessary
        while packet_time >= current_time + timedelta(seconds=time_window):
            # Finalize data for the current window
            data = window_data[current_time]
            data["ip_entropy"] = calculate_entropy(data["ip_counts"])
            data["new_ip_ratio"] = len(data["new_ips"]) / len(data["total_ips"]) if data["total_ips"] else 0
            data["port_entropy"] = calculate_entropy(data["port_counts"])
            data["username_entropy"] = calculate_entropy(data["username_counts"])
            data["password_entropy"] = calculate_entropy(data["password_counts"])
            data["login_success_ratio"] = data["successful_logins"] / data["login_frequency"] if data["login_frequency"] else 0
            data["account_attempt_diversity"] = len(data["account_attempts"])
            data["packet_size_mean"] = np.mean(data["packet_sizes"]) if data["packet_sizes"] else 0
            data["packet_size_std"] = np.std(data["packet_sizes"]) if data["packet_sizes"] else 0
            
            # Reset for next window
            current_time += timedelta(seconds=time_window)
            window_data[current_time] = {
                "login_frequency": 0,
                "inter_login_times": [],
                "login_burst_count": 0,
                "unique_source_ips": set(),
                "ip_counts": Counter(),
                "new_ips": set(),
                "total_ips": set(all_ips),
                "ip_entropy": 0,
                "new_ip_ratio": 0,
                "unique_source_ports": set(),
                "port_counts": Counter(),
                "port_entropy": 0,
                "protocol_changes": 0,
                "last_protocol": data["last_protocol"],
                "unique_usernames": set(),
                "username_counts": Counter(),
                "username_entropy": 0,
                "password_counts": Counter(),
                "password_entropy": 0,
                "successful_logins": 0,
                "account_attempts": Counter(),
                "packet_sizes": [],
                "total_failed_attempts": 0,
                "distinct_ip_port_combinations": set()
            }

        # Update current window data
        data = window_data[current_time]
        data["login_frequency"] += 1
        data["unique_source_ips"].add(source_ip)
        data["ip_counts"][source_ip] += 1
        data["total_ips"].add(source_ip)
        if source_ip not in all_ips:
            data["new_ips"].add(source_ip)
        all_ips.add(source_ip)

        # Update port data
        data["unique_source_ports"].add(source_port)
        data["port_counts"][source_port] += 1

        # Update protocol changes
        if data["last_protocol"] is not None and data["last_protocol"] != protocol:
            data["protocol_changes"] += 1
        data["last_protocol"] = protocol

        # Update username and password data
        if username:
            data["unique_usernames"].add(username)
            data["username_counts"][username] += 1
            data["account_attempts"][username] += 1
        if password:
            data["password_counts"][password] += 1

        # Update login success data
        if login_success:
            data["successful_logins"] += 1
        else:
            data["total_failed_attempts"] += 1

        # Update packet size data
        packet_size = len(packet)
        data["packet_sizes"].append(packet_size)

        # Update distinct IP-port combinations
        data["distinct_ip_port_combinations"].add((source_ip, source_port))

        # Calculate inter-login time
        if prev_time is not None:
            inter_login_time = (packet_time - prev_time).total_seconds()
            data["inter_login_times"].append(inter_login_time)

        # Count login bursts
        if burst_start_time is None or packet_time - burst_start_time > timedelta(seconds=burst_window):
            burst_start_time = packet_time
        elif packet_time - burst_start_time <= timedelta(seconds=burst_window):
            data["login_burst_count"] += 1

        prev_time = packet_time

    # Calculate final statistics for the last window
    if window_data:
        last_window = window_data[max(window_data.keys())]
        last_window["ip_entropy"] = calculate_entropy(last_window["ip_counts"])
        last_window["new_ip_ratio"] = len(last_window["new_ips"]) / len(last_window["total_ips"]) if last_window["total_ips"] else 0
        last_window["port_entropy"] = calculate_entropy(last_window["port_counts"])
        last_window["username_entropy"] = calculate_entropy(last_window["username_counts"])
        last_window["password_entropy"] = calculate_entropy(last_window["password_counts"])
        last_window["login_success_ratio"] = last_window["successful_logins"] / last_window["login_frequency"] if last_window["login_frequency"] else 0
        last_window["account_attempt_diversity"] = len(last_window["account_attempts"])
        last_window["packet_size_mean"] = np.mean(last_window["packet_sizes"]) if last_window["packet_sizes"] else 0
        last_window["packet_size_std"] = np.std(last_window["packet_sizes"]) if last_window["packet_sizes"] else 0

    return window_data

def save_to_csv(window_data, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'Timestamp', 'Login Frequency', 'Inter-Login Time Mean (s)', 'Inter-Login Time Std Dev (s)',
            'Login Burst Count', 'Unique Source IPs', 'IP Entropy', 'New IP Ratio',
            'Unique Source Ports', 'Port Entropy', 'Protocol Changes',
            'Unique Usernames', 'Username Entropy', 'Password Entropy',
            'Login Success Ratio', 'Account Attempt Diversity',
            'Packet Size Mean', 'Packet Size Std Dev',
            'Total Failed Attempts', 'Distinct IP-Port Combinations'
        ])
        
        for timestamp, data in sorted(window_data.items()):
            writer.writerow([
                timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                data["login_frequency"],
                f'{np.mean(data["inter_login_times"]):.2f}' if data["inter_login_times"] else '0.00',
                f'{np.std(data["inter_login_times"]):.2f}' if data["inter_login_times"] else '0.00',
                data["login_burst_count"],
                len(data["unique_source_ips"]),
                f'{data["ip_entropy"]:.2f}',
                f'{data["new_ip_ratio"]:.2f}',
                len(data["unique_source_ports"]),
                f'{data["port_entropy"]:.2f}',
                data["protocol_changes"],
                len(data["unique_usernames"]),
                f'{data["username_entropy"]:.2f}',
                f'{data["password_entropy"]:.2f}',
                f'{data["login_success_ratio"]:.2f}',
                data["account_attempt_diversity"],
                f'{data["packet_size_mean"]:.2f}',
                f'{data["packet_size_std"]:.2f}',
                data["total_failed_attempts"],
                len(data["distinct_ip_port_combinations"])
            ])

def main():
    parser = argparse.ArgumentParser(description="Analyze PCAP files for login attempt features.")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("dst_ip", help="Destination IP address to filter")
    parser.add_argument("dst_port", type=int, help="Destination port number to filter")
    parser.add_argument("output_file", help="Output CSV file name")
    args = parser.parse_args()

    window_data = analyze_pcap(args.pcap_file, args.dst_ip, args.dst_port)

  
    
    if window_data is not None:
        save_to_csv(window_data, args.output_file)
        print(f"Analysis complete. Results saved to {args.output_file}")
        
        # Print summary statistics
        all_frequencies = [data["login_frequency"] for data in window_data.values()]
        all_bursts = [data["login_burst_count"] for data in window_data.values()]
        all_unique_ips = [len(data["unique_source_ips"]) for data in window_data.values()]
        all_ip_entropies = [data["ip_entropy"] for data in window_data.values()]
        all_new_ip_ratios = [data["new_ip_ratio"] for data in window_data.values()]
        all_unique_ports = [len(data["unique_source_ports"]) for data in window_data.values()]
        all_port_entropies = [data["port_entropy"] for data in window_data.values()]
        all_protocol_changes = [data["protocol_changes"] for data in window_data.values()]
        all_unique_usernames = [len(data["unique_usernames"]) for data in window_data.values()]
        all_username_entropies = [data["username_entropy"] for data in window_data.values()]
        all_password_entropies = [data["password_entropy"] for data in window_data.values()]
        all_login_success_ratios = [data["login_success_ratio"] for data in window_data.values()]
        all_account_attempt_diversities = [data["account_attempt_diversity"] for data in window_data.values()]
        all_packet_size_means = [data["packet_size_mean"] for data in window_data.values()]
        all_packet_size_stds = [data["packet_size_std"] for data in window_data.values()]
        all_total_failed_attempts = [data["total_failed_attempts"] for data in window_data.values()]
        all_distinct_ip_port_combinations = [len(data["distinct_ip_port_combinations"]) for data in window_data.values()]

if __name__ == "__main__":
    main()

        