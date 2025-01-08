import scapy.all as scapy
import argparse
from datetime import datetime
import csv
import os

class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.packet_log = []
        self.suspicious_ips = set()
        
    def capture_packets(self, packet_count=100):
        """Capture and analyze network packets"""
        print(f"Starting packet capture on interface {self.interface}")
        packets = scapy.sniff(iface=self.interface, count=packet_count)
        
        for packet in packets:
            if scapy.IP in packet:
                packet_info = self.analyze_packet(packet)
                self.packet_log.append(packet_info)
                
    def analyze_packet(self, packet):
        """Analyze individual packets for suspicious patterns"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        # Check for common security flags
        suspicious = False
        reason = []
        
        # Check for potential port scanning
        if scapy.TCP in packet:
            flags = packet[scapy.TCP].flags
            if flags == 2:  # SYN flag only
                suspicious = True
                reason.append("Potential port scan detected")
                self.suspicious_ips.add(src_ip)
        
        return {
            'timestamp': timestamp,
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'protocol': protocol,
            'suspicious': suspicious,
            'reason': reason
        }
    
    def generate_report(self, filename="security_report.csv"):
        """Generate a CSV report of captured packets"""
        with open(filename, 'w', newline='') as file:
            writer = csv.DictWriter(file, 
                fieldnames=['timestamp', 'source_ip', 'dest_ip', 
                           'protocol', 'suspicious', 'reason'])
            writer.writeheader()
            writer.writerows(self.packet_log)
        
        # Generate summary statistics
        total_packets = len(self.packet_log)
        suspicious_packets = len([p for p in self.packet_log if p['suspicious']])
        
        print(f"\nNetwork Security Report Summary:")
        print(f"Total packets analyzed: {total_packets}")
        print(f"Suspicious packets detected: {suspicious_packets}")
        print(f"Unique suspicious IPs: {len(self.suspicious_ips)}")
        
def main():
    parser = argparse.ArgumentParser(description='Network Security Monitoring Tool')
    parser.add_argument('-i', '--interface', required=True, 
                       help='Network interface to monitor')
    parser.add_argument('-c', '--count', type=int, default=100,
                       help='Number of packets to capture')
    
    args = parser.parse_args()
    
    monitor = NetworkMonitor(args.interface)
    monitor.capture_packets(args.count)
    monitor.generate_report()

if __name__ == "__main__":
    main()
