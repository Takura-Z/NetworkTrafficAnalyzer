import scapy.all as scapy
import pandas as pd
import time
import os
from datetime import datetime
import traceback
import sys

#class to represent and manage a network flow
class NetworkFlow:
    """
    This class holds all the necessary information and features for a single network flow.
    A flow is defined by the 5-tuple: (Source IP, Destination IP, Source Port, Destination Port, Protocol).
    """
    def __init__(self, start_time, ip_src, ip_dst, src_port, dst_port, protocol, is_forward_direction):
        # The 5-tuple that defines the flow
        self.flow_key = (ip_src, ip_dst, src_port, dst_port, protocol)
        self.is_forward_direction = is_forward_direction

        # Convert EDecimal to float to avoid TypeError
        self.start_time = float(start_time)
        self.end_time = float(start_time)

        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.total_byte_count = 0
        self.fwd_byte_count = 0
        self.bwd_byte_count = 0

        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.all_packet_lengths = []

        self.fwd_iat = []
        self.bwd_iat = []
        self.last_fwd_timestamp = float(start_time)
        self.last_bwd_timestamp = float(start_time)

        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1
        self.flow_syn_count = 0
        self.flow_ack_count = 0
        self.flow_fin_count = 0
        self.flow_psh_count = 0
        self.flow_urg_count = 0
        self.flow_ece_count = 0
        self.flow_cwr_count = 0
        
        self.active_times = []
        self.idle_times = []
        self.last_timestamp = float(start_time)
        
        self.packet_count_in_flow = 0
        
        # New features for bulk transfer
        self.fwd_bulk_bytes = 0
        self.fwd_bulk_packets = 0
        self.fwd_bulk_rate = 0
        self.bwd_bulk_bytes = 0
        self.bwd_bulk_packets = 0
        self.bwd_bulk_rate = 0
        self.last_fwd_bulk_timestamp = float(start_time)
        self.last_bwd_bulk_timestamp = float(start_time)


    def add_packet(self, packet, current_time):
        """
        Adds a packet to the current flow and updates the features accordingly.
        """
        # Convert EDecimal to float to avoid TypeError
        current_time = float(current_time)
        self.end_time = current_time
        self.packet_count_in_flow += 1

        # Calculate and update active/idle times
        if self.packet_count_in_flow > 1:
            time_since_last_packet = current_time - self.last_timestamp
            if time_since_last_packet > 1: # Assuming idle if gap > 1 second
                self.idle_times.append(time_since_last_packet)
                self.active_times.append(0) # Start new active time
            else:
                if self.active_times:
                    self.active_times[-1] += time_since_last_packet
                else:
                    self.active_times.append(time_since_last_packet)

        self.last_timestamp = current_time

        packet_size = len(packet)
        self.all_packet_lengths.append(packet_size)
        self.total_byte_count += packet_size
        
        # Determine if the packet is in the forward or backward direction
        is_packet_forward = (packet[scapy.IP].src, packet[scapy.IP].dst) == self.is_forward_direction
        
        if is_packet_forward:
            self.fwd_packet_count += 1
            self.fwd_byte_count += packet_size
            self.fwd_packet_lengths.append(packet_size)
            if self.fwd_packet_count > 1:
                self.fwd_iat.append(current_time - self.last_fwd_timestamp)
            self.last_fwd_timestamp = current_time
        else:
            self.bwd_packet_count += 1
            self.bwd_byte_count += packet_size
            self.bwd_packet_lengths.append(packet_size)
            if self.bwd_packet_count > 1:
                self.bwd_iat.append(current_time - self.last_bwd_timestamp)
            self.last_bwd_timestamp = current_time

        if scapy.TCP in packet:
            header_len = packet[scapy.TCP].dataofs * 4
            if is_packet_forward:
                self.fwd_header_length += header_len
                if self.init_win_bytes_fwd == -1:
                    self.init_win_bytes_fwd = packet[scapy.TCP].window
            else:
                self.bwd_header_length += header_len
                if self.init_win_bytes_bwd == -1:
                    self.init_win_bytes_bwd = packet[scapy.TCP].window

            flags = packet[scapy.TCP].flags
            if 'S' in flags: self.flow_syn_count += 1
            if 'A' in flags: self.flow_ack_count += 1
            if 'F' in flags: self.flow_fin_count += 1
            if 'P' in flags: self.flow_psh_count += 1
            if 'U' in flags: self.flow_urg_count += 1
            if 'E' in flags: self.flow_ece_count += 1
            if 'C' in flags: self.flow_cwr_count += 1
            
            # Update Bulk features
            if packet.haslayer(scapy.Raw):
                data_len = len(packet[scapy.Raw])
                if is_packet_forward:
                    self.fwd_bulk_bytes += data_len
                    self.fwd_bulk_packets += 1
                    self.fwd_bulk_rate = self.fwd_bulk_bytes / (current_time - self.last_fwd_bulk_timestamp) if (current_time - self.last_fwd_bulk_timestamp) > 0 else 0
                    self.last_fwd_bulk_timestamp = current_time
                else:
                    self.bwd_bulk_bytes += data_len
                    self.bwd_bulk_packets += 1
                    self.bwd_bulk_rate = self.bwd_bulk_bytes / (current_time - self.last_bwd_bulk_timestamp) if (current_time - self.last_bwd_bulk_timestamp) > 0 else 0
                    self.last_bwd_bulk_timestamp = current_time


    def get_features(self):
        """
        Calculates and returns a dictionary of all extracted features for the flow.
        """
        duration = self.end_time - self.start_time

        # Calculate statistical features with error handling for empty lists
        fwd_iat_mean = sum(self.fwd_iat) / len(self.fwd_iat) if self.fwd_iat else 0
        bwd_iat_mean = sum(self.bwd_iat) / len(self.bwd_iat) if self.bwd_iat else 0
        all_iat = self.fwd_iat + self.bwd_iat
        flow_iat_mean = sum(all_iat) / len(all_iat) if all_iat else 0
        
        fwd_pkt_len_mean = sum(self.fwd_packet_lengths) / len(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        bwd_pkt_len_mean = sum(self.bwd_packet_lengths) / len(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        all_pkt_len_mean = sum(self.all_packet_lengths) / len(self.all_packet_lengths) if self.all_packet_lengths else 0
        
        # Calculate new features from your list
        fwd_iat_total = sum(self.fwd_iat)
        bwd_iat_total = sum(self.bwd_iat)
        fwd_packets_per_second = self.fwd_packet_count / duration if duration > 0 else 0
        bwd_packets_per_second = self.bwd_packet_count / duration if duration > 0 else 0
        pkt_len_std = pd.Series(self.all_packet_lengths).std() if len(self.all_packet_lengths) > 1 else 0
        pkt_len_var = pd.Series(self.all_packet_lengths).var() if len(self.all_packet_lengths) > 1 else 0

        # Calculate Bulk Features
        fwd_avg_bytes_bulk = self.fwd_bulk_bytes / self.fwd_bulk_packets if self.fwd_bulk_packets > 0 else 0
        bwd_avg_bytes_bulk = self.bwd_bulk_bytes / self.bwd_bulk_packets if self.bwd_bulk_packets > 0 else 0
        fwd_avg_packets_bulk = self.fwd_bulk_packets / self.fwd_packet_count if self.fwd_packet_count > 0 else 0
        bwd_avg_packets_bulk = self.bwd_bulk_packets / self.bwd_packet_count if self.bwd_packet_count > 0 else 0
        fwd_avg_bulk_rate = self.fwd_bulk_rate
        bwd_avg_bulk_rate = self.bwd_bulk_rate


        # Define a single dictionary with only the features you requested
        features = {
            'Destination Port': self.flow_key[3],
            'Flow Duration': duration,
            'Total Fwd Packets': self.fwd_packet_count,
            'Total Backward Packets': self.bwd_packet_count,
            'Total Length of Fwd Packets': self.fwd_byte_count,
            'Total Length of Bwd Packets': self.bwd_byte_count,
            'Fwd Packet Length Max': max(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'Fwd Packet Length Min': min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'Fwd Packet Length Mean': fwd_pkt_len_mean,
            'Fwd Packet Length Std': (pd.Series(self.fwd_packet_lengths).std() if len(self.fwd_packet_lengths) > 1 else 0),
            'Bwd Packet Length Max': max(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'Bwd Packet Length Min': min(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'Bwd Packet Length Mean': bwd_pkt_len_mean,
            'Bwd Packet Length Std': (pd.Series(self.bwd_packet_lengths).std() if len(self.bwd_packet_lengths) > 1 else 0),
            'Flow Bytes/s': self.total_byte_count / duration if duration > 0 else 0,
            'Flow Packets/s': (self.fwd_packet_count + self.bwd_packet_count) / duration if duration > 0 else 0,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Std': (pd.Series(all_iat).std() if all_iat else 0),
            'Flow IAT Max': max(all_iat) if all_iat else 0,
            'Flow IAT Min': min(all_iat) if all_iat else 0,
            'Fwd IAT Total': fwd_iat_total,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Std': (pd.Series(self.fwd_iat).std() if self.fwd_iat else 0),
            'Fwd IAT Max': max(self.fwd_iat) if self.fwd_iat else 0,
            'Fwd IAT Min': min(self.fwd_iat) if self.fwd_iat else 0,
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Std': (pd.Series(self.bwd_iat).std() if self.bwd_iat else 0),
            'Bwd IAT Max': max(self.bwd_iat) if self.bwd_iat else 0,
            'Bwd IAT Min': min(self.bwd_iat) if self.bwd_iat else 0,
            'Fwd PSH Flags': self.flow_psh_count if self.flow_key[4] == 'TCP' else 0,
            'Bwd PSH Flags': 0, # Note: Not a standard feature in many datasets, always 0.
            'Fwd URG Flags': self.flow_urg_count if self.flow_key[4] == 'TCP' else 0,
            'Bwd URG Flags': 0, # Note: Not a standard feature in many datasets, always 0.
            'Fwd Header Length': self.fwd_header_length if self.flow_key[4] == 'TCP' else 0,
            'Bwd Header Length': self.bwd_header_length if self.flow_key[4] == 'TCP' else 0,
            'Fwd Packets/s': fwd_packets_per_second,
            'Bwd Packets/s': bwd_packets_per_second,
            'Min Packet Length': min(self.all_packet_lengths) if self.all_packet_lengths else 0,
            'Max Packet Length': max(self.all_packet_lengths) if self.all_packet_lengths else 0,
            'Packet Length Mean': all_pkt_len_mean,
            'Packet Length Std': pkt_len_std,
            'Packet Length Variance': pkt_len_var,
            'FIN Flag Count': self.flow_fin_count,
            'SYN Flag Count': self.flow_syn_count,
            'RST Flag Count': 0, # Our script doesn't explicitly track RST, but we can set it to 0.
            'PSH Flag Count': self.flow_psh_count,
            'ACK Flag Count': self.flow_ack_count,
            'URG Flag Count': self.flow_urg_count,
            'CWE Flag Count': self.flow_cwr_count,
            'ECE Flag Count': self.flow_ece_count,
            'Down/Up Ratio': self.bwd_packet_count / self.fwd_packet_count if self.fwd_packet_count > 0 else 0,
            'Average Packet Size': all_pkt_len_mean,
            'Avg Fwd Segment Size': fwd_pkt_len_mean,
            'Avg Bwd Segment Size': bwd_pkt_len_mean,
            'Fwd Avg Bytes/Bulk': fwd_avg_bytes_bulk,
            'Fwd Avg Packets/Bulk': fwd_avg_packets_bulk,
            'Fwd Avg Bulk Rate': fwd_avg_bulk_rate,
            'Bwd Avg Bytes/Bulk': bwd_avg_bytes_bulk,
            'Bwd Avg Packets/Bulk': bwd_avg_packets_bulk,
            'Bwd Avg Bulk Rate': bwd_avg_bulk_rate,
            'Subflow Fwd Packets': self.fwd_packet_count,
            'Subflow Fwd Bytes': self.fwd_byte_count,
            'Subflow Bwd Packets': self.bwd_packet_count,
            'Subflow Bwd Bytes': self.bwd_byte_count,
            'Init_Win_bytes_forward': self.init_win_bytes_fwd,
            'Init_Win_bytes_backward': self.init_win_bytes_bwd,
            'act_data_pkt_fwd': self.fwd_packet_count,
            'min_seg_size_forward': min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'Active Mean': sum(self.active_times) / len(self.active_times) if self.active_times else 0,
            'Active Std': pd.Series(self.active_times).std() if len(self.active_times) > 1 else 0,
            'Active Max': max(self.active_times) if self.active_times else 0,
            'Active Min': min(self.active_times) if self.active_times else 0,
            'Idle Mean': sum(self.idle_times) / len(self.idle_times) if self.idle_times else 0,
            'Idle Std': pd.Series(self.idle_times).std() if len(self.idle_times) > 1 else 0,
            'Idle Max': max(self.idle_times) if self.idle_times else 0,
            'Idle Min': min(self.idle_times) if self.idle_times else 0,
            'Label': 'Benign'
        }
        return features

def process_pcap_file(file_path):
    """
    Processes a single pcap file, extracts flows, and saves features to a CSV.
    This version processes the entire file in memory for simplicity and reliability.
    """
    print(f"Processing {os.path.basename(file_path)}...")
    flows = {}
    
    try:
        # PcapReader is more memory-efficient than rdpcap for large files
        packets = scapy.PcapReader(file_path)
        packet_count = 0
        
        for packet in packets:
            packet_count += 1
            if not packet.haslayer(scapy.IP):
                continue
            
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            protocol = None
            src_port = None
            dst_port = None

            if packet.haslayer(scapy.TCP):
                protocol = 'TCP'
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                protocol = 'UDP'
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
            else:
                continue

            # Create a consistent flow key regardless of direction
            # The CICFlowMeter approach uses a canonical key
            if ip_src > ip_dst:
                flow_key_tuple = (ip_dst, ip_src, dst_port, src_port, protocol)
                is_forward_direction = (ip_dst, ip_src)
            else:
                flow_key_tuple = (ip_src, ip_dst, src_port, dst_port, protocol)
                is_forward_direction = (ip_src, ip_dst)
            
            if flow_key_tuple not in flows:
                flows[flow_key_tuple] = NetworkFlow(packet.time, ip_src, ip_dst, src_port, dst_port, protocol, is_forward_direction)
            
            flows[flow_key_tuple].add_packet(packet, packet.time)
            
        print(f"\nSuccessfully processed all {packet_count} packets and extracted flows.")
        
        features_list = [f.get_features() for f in flows.values()]
        
        # Desired column order for the header
        cic_features_order = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
            'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
            'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
            'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
            'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
            'Label'
        ]
        
        df = pd.DataFrame(features_list).reindex(columns=cic_features_order, fill_value=0)
        
        # Explicitly get the current working directory to save the file
        current_dir = os.getcwd()
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_csv_path = os.path.join(current_dir, f"{base_name}.csv")

        df.to_csv(output_csv_path, index=False)
        print(f"\nSUCCESS: Features extracted and saved to {output_csv_path}.")
        
        # Read the file to print the first 5 rows for confirmation
        df_preview = pd.read_csv(output_csv_path, nrows=5)
        print("\nHere are the first 5 rows of the generated CSV file:\n")
        print(df_preview.to_string())
        print("\n")
        
        return output_csv_path

    except Exception as e:
        print(f"An error occurred while processing {file_path}:")
        traceback.print_exc()
        return None

def main():
    """
    Main function to find and process all pcap files in the current directory.
    """
    print("Starting PCAP file processing...")
    pcap_folder = os.getcwd()
    
    processed_files_count = 0
    for file_name in os.listdir(pcap_folder):
        if file_name.endswith('.pcap') or file_name.endswith('.pcapng'):
            file_path = os.path.join(pcap_folder, file_name)
            output_csv_path = process_pcap_file(file_path)
            if output_csv_path:
                processed_files_count += 1
    
    if processed_files_count > 0:
        print("\nAll processing complete.")
    else:
        print("No PCAP files found in the current directory.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An unexpected error occurred during script startup:")
        traceback.print_exc()
