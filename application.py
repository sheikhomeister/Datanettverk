#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 26 12:58:57 2025
@author: sheikhomeister

Original application logic with:
- Argparse for command-line arguments (Guideline).
- DRTP guideline header: SeqNum (2B), AckNum (2B), Flags (2B), RecvWnd (2B).
- RST flag added.
- Payload length is implicit.
"""

import socket
import sys # Still imported, but argparse will be primary for CLI
import struct
import time
import os
import random
import argparse # Added for argument parsing

# DRTP Header Format (Guideline Aligned)
header_format = '!HHHH' # 4 unsigned short integers
header_size = struct.calcsize(header_format)
max_seq_num = 65535 # For 2-byte sequence and ack numbers

# DRTP Flags (within the 2-byte flags field)
syn_flag_val = 1 << 0  # SYN
ack_flag_val = 1 << 1  # ACK
fin_flag_val = 1 << 2  # FIN
rst_flag_val = 1 << 3  # RST (New)

default_receiver_window = 10 # Example receiver window size (in packets)
default_timeout = 0.4 # 400ms as per guidelines

def create_packet(seq_num, ack_num, flags, window_size, payload=b''):
    """Creates a DRTP packet with the new header."""
    seq_num &= max_seq_num
    ack_num &= max_seq_num
    header = struct.pack(header_format, seq_num, ack_num, flags, window_size)
    return header + payload

def parse_packet(packet):
    """Parses a DRTP packet with the new header."""
    if len(packet) < header_size:
        print("Error: Packet too short to parse header.")
        return None, None, None, None, None
        
    header_part = packet[:header_size]
    payload_part = packet[header_size:]
    
    seq_num, ack_num, flags, window_size = struct.unpack(header_format, header_part)
    return seq_num, ack_num, flags, window_size, payload_part

# Server specific ISN, can be random
server_isn_val = random.randint(0, max_seq_num // 2)
# Client specific ISN
client_isn_val = random.randint(max_seq_num // 2 + 1, max_seq_num -100)

def run_server_logic(ip_address, port, server_discard_mode):
    """Contains the original server logic, now called by argparse dispatch."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((ip_address, port))
        print(f"Server mode: Listening on {ip_address}:{port}")
        if server_discard_mode:
            print("Server: Discard mode enabled (will randomly drop one ACK).")

        current_client_address = None
        server_connection_established = False
        expected_data_seq_num = 1
        output_file_handle = None
        server_dropped_ack_for_test = False

        while True:
            try:
                packet, addr = sock.recvfrom(header_size + 2048)
                parsed_data = parse_packet(packet)
                if parsed_data[0] is None:
                    continue
                r_seq, r_ack, r_flags, r_wnd, r_payload = parsed_data

                if not server_connection_established:
                    if r_flags & syn_flag_val:
                        current_client_address = addr
                        print(f"Server: Received SYN (Seq={r_seq}) from {current_client_address}")
                        syn_ack_pkt = create_packet(server_isn_val, r_seq, syn_flag_val | ack_flag_val, default_receiver_window)
                        sock.sendto(syn_ack_pkt, current_client_address)
                        print(f"Server: Sent SYN-ACK (Seq={server_isn_val}, Ack={r_seq})")
                    elif r_flags & ack_flag_val and current_client_address == addr:
                        if r_ack == server_isn_val:
                            print(f"Server: Received ACK for SYN-ACK (ClientSeq={r_seq}, AckForMySYN={r_ack}). Connection established with {current_client_address}")
                            server_connection_established = True
                            expected_data_seq_num = 1
                            output_filename = f"received_orig_argparse_{current_client_address[0]}_{current_client_address[1]}.dat"
                            output_file_handle = open(output_filename, 'wb')
                            print(f"Server: Receiving file as {output_filename}")
                            server_dropped_ack_for_test = False
                        else:
                            print(f"Server: Received ACK during handshake with wrong AckNum {r_ack}, expected {server_isn_val}")
                elif server_connection_established and current_client_address == addr:
                    if r_flags & fin_flag_val:
                        print(f"Server: Received FIN (Seq={r_seq}) from {current_client_address}, closing file...")
                        if output_file_handle: output_file_handle.close()
                        fin_ack_server_seq = (server_isn_val + 1) & max_seq_num
                        fin_ack_resp = create_packet(fin_ack_server_seq, r_seq, fin_flag_val | ack_flag_val, default_receiver_window)
                        sock.sendto(fin_ack_resp, current_client_address)
                        print(f"Server: Sent FIN-ACK (Seq={fin_ack_server_seq}, Ack={r_seq}).")
                        server_connection_established = False
                        current_client_address = None
                        output_file_handle = None
                        expected_data_seq_num = 1
                        continue
                    elif not (r_flags & syn_flag_val or r_flags & fin_flag_val):
                        if r_seq == expected_data_seq_num:
                            if output_file_handle: output_file_handle.write(r_payload)
                            ack_pkt_for_data = create_packet((server_isn_val + 1) & max_seq_num, r_seq, ack_flag_val, default_receiver_window)
                            if server_discard_mode and not server_dropped_ack_for_test and random.random() < 0.2:
                                print(f"Server: DISCARDING ACK for packet {r_seq} (Test Drop)")
                                server_dropped_ack_for_test = True
                            else:
                                sock.sendto(ack_pkt_for_data, current_client_address)
                            expected_data_seq_num = (expected_data_seq_num + 1)
                            if expected_data_seq_num > max_seq_num: expected_data_seq_num = 1
                        elif r_seq < expected_data_seq_num:
                            print(f"Server: Received duplicate DATA (Seq={r_seq}), expected {expected_data_seq_num}. Re-ACKing {r_seq}.")
                            ack_pkt_for_dup_data = create_packet((server_isn_val + 1) & max_seq_num, r_seq, ack_flag_val, default_receiver_window)
                            sock.sendto(ack_pkt_for_dup_data, current_client_address)
                        else:
                            print(f"Server: Received out-of-order DATA (Seq={r_seq}), expected {expected_data_seq_num}. Discarding.")
            except Exception as e:
                print(f"Server main loop error: {e}")
                if output_file_handle and not output_file_handle.closed: output_file_handle.close()
                server_connection_established = False
    except OSError as e:
        print(f"Server socket error: {e}")
    finally:
        print("Server shutting down.")
        if sock: sock.close()

def run_client_logic(ip_address, port, filename, effective_window_size):
    """Contains the original client logic, now called by argparse dispatch."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(default_timeout)
    server_addr_tuple_main = (ip_address, port) # Used for sending

    try:
        client_current_seq = client_isn_val
        print(f"Client mode: Sending {filename} to {ip_address}:{port} with window {effective_window_size}")
        print(f"Client: Sending SYN (Seq={client_current_seq})...")
        syn_packet = create_packet(client_current_seq, 0, syn_flag_val, default_receiver_window)
        sock.sendto(syn_packet, server_addr_tuple_main)

        try:
            packet, server_addr_tuple_recv = sock.recvfrom(header_size + 2048) # server_addr_tuple_recv might be different if NAT etc.
            r_seq, r_ack, r_flags, r_wnd, _ = parse_packet(packet)

            if r_flags & syn_flag_val and r_flags & ack_flag_val and r_ack == client_current_seq:
                print(f"Client: Received SYN-ACK (ServerSeq={r_seq}, AckForMySYN={r_ack})")
                server_isn_from_synack = r_seq
                client_current_seq = (client_current_seq + 1) & max_seq_num
                ack_for_server_syn_pkt = create_packet(client_current_seq, server_isn_from_synack, ack_flag_val, default_receiver_window)
                sock.sendto(ack_for_server_syn_pkt, server_addr_tuple_main) # Send to the known server address
                print(f"Client: Sent ACK for SYN-ACK (MySeq={client_current_seq}, AckForServerISN={server_isn_from_synack}). Connection established.")
            else:
                print(f"Client: Handshake failed. Flags={hex(r_flags)}, Ack={r_ack}, Expected Ack={client_current_seq}")
                if r_flags & rst_flag_val: print("Client: Received RST from server.")
                sys.exit(1) # Use sys.exit as in original
        except socket.timeout:
            print("Client: Timeout waiting for SYN-ACK. Connection failed.")
            sys.exit(1)
        
        start_time = time.time()
        base_data_seq_num = 1 
        next_data_seq_to_send = base_data_seq_num
        window_buffer = [] 
        
        try:
            with open(filename, 'rb') as f:
                file_fully_read = False
                while True:
                    while len(window_buffer) < effective_window_size and not file_fully_read:
                        data_payload = f.read(1000)
                        if not data_payload:
                            file_fully_read = True
                            break
                        data_pkt_to_send = create_packet(next_data_seq_to_send, server_isn_from_synack, 0, default_receiver_window, data_payload)
                        sock.sendto(data_pkt_to_send, server_addr_tuple_main)
                        window_buffer.append((next_data_seq_to_send, data_pkt_to_send))
                        next_data_seq_to_send = (next_data_seq_to_send + 1)
                        if next_data_seq_to_send > max_seq_num: next_data_seq_to_send = 1
                    
                    if not window_buffer and file_fully_read:
                        break

                    try:
                        ack_packet_raw, _ = sock.recvfrom(header_size)
                        r_seq_serv_ack, r_ack_for_my_data, r_flags_serv_ack, _, _ = parse_packet(ack_packet_raw)

                        if r_flags_serv_ack & ack_flag_val:
                            new_window_buffer = []
                            acked_something = False
                            for seq_in_win, pkt_in_win in window_buffer:
                                if seq_in_win <= r_ack_for_my_data or \
                                   (r_ack_for_my_data < base_data_seq_num and seq_in_win > max_seq_num - effective_window_size):
                                    acked_something = True
                                else:
                                    new_window_buffer.append((seq_in_win, pkt_in_win))
                            window_buffer = new_window_buffer
                            if acked_something:
                                base_data_seq_num = (r_ack_for_my_data + 1)
                                if base_data_seq_num > max_seq_num: base_data_seq_num = 1
                        elif r_flags_serv_ack & rst_flag_val:
                            print("Client: Received RST from server during data transfer. Aborting.")
                            sys.exit(1)
                    except socket.timeout:
                        print(f"Client: Timeout. Resending window (Oldest unacked: {base_data_seq_num})...")
                        for seq_to_resend, pkt_to_resend in window_buffer:
                            sock.sendto(pkt_to_resend, server_addr_tuple_main)
            
            fin_client_seq = next_data_seq_to_send if next_data_seq_to_send > base_data_seq_num else (client_current_seq +1) & max_seq_num
            fin_packet_to_send = create_packet(fin_client_seq, server_isn_from_synack, fin_flag_val, default_receiver_window)
            sock.sendto(fin_packet_to_send, server_addr_tuple_main)
            print(f"Client: Sent FIN (Seq={fin_client_seq})")

            try:
                fin_ack_reply_raw, _ = sock.recvfrom(header_size)
                s_seq, s_ack, s_flags, _, _ = parse_packet(fin_ack_reply_raw)
                if (s_flags & fin_flag_val and s_flags & ack_flag_val and s_ack == fin_client_seq) or \
                   (s_flags & ack_flag_val and s_ack == fin_client_seq):
                    print(f"Client: Received ACK/FIN-ACK for FIN (AckForMyFIN={s_ack}). Closing connection.")
                else:
                    print(f"Client: No proper FIN-ACK received (Flags={hex(s_flags)}, Ack={s_ack}). Closing anyway.")
            except socket.timeout:
                print("Client: No FIN-ACK received from server, closing anyway.")
        except FileNotFoundError:
            print(f"Error: File {filename} not found.")
            rst_pkt = create_packet((client_current_seq + 1) & max_seq_num, server_isn_from_synack if 'server_isn_from_synack' in locals() else 0, rst_flag_val, 0)
            sock.sendto(rst_pkt, server_addr_tuple_main)
            sys.exit(1)
        except Exception as e:
            print(f"Client data transfer/teardown error: {e}")
            sys.exit(1) # Use sys.exit as in original
        finally:
            end_time = time.time()
            if os.path.exists(filename):
                file_size_bytes = os.path.getsize(filename)
                time_taken = end_time - start_time
                if time_taken > 0:
                    throughput_bits_sec = (file_size_bytes * 8) / time_taken
                    print(f"Client: File transfer for '{filename}' finished.")
                    print(f"Client: Size = {file_size_bytes} bytes. Time = {time_taken:.2f} s. Throughput = {throughput_bits_sec / 1_000_000:.2f} Mbps.")
                else:
                    print(f"Client: File transfer for '{filename}' finished. Time too short for throughput calculation.")
            print("Client shutting down.")
            if sock: sock.close()
    except OSError as e: # For socket creation errors etc.
        print(f"Client socket error: {e}")
        sys.exit(1) # Use sys.exit as in original
    except Exception as e: # Catch-all for other client setup errors
        print(f"Client general error: {e}")
        sys.exit(1) # Use sys.exit as in original


# --- Argparse Setup ---
# This setup expects -i and -p as global options BEFORE the mode (server/client)
parser = argparse.ArgumentParser(
    description="DRTP File Transfer Application (Original Logic with Argparse)",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    "-i", "--ip", 
    type=str, 
    required=True, 
    help="IP address.\nFor server: IP to bind to.\nFor client: IP of the server to connect to."
)
parser.add_argument(
    "-p", "--port", 
    type=int, 
    required=True, 
    help="Port number for server to listen on or client to connect to."
)

subparsers = parser.add_subparsers(
    dest="mode_selected", # Changed dest to avoid conflict with original 'mode_arg'
    required=True, 
    title="Modes of operation",
    description="Choose to run as 'server' or 'client'.",
    help="Select mode: 'server' or 'client'"
)

# Server mode sub-parser
server_parser = subparsers.add_parser(
    "server", 
    help="Run in server mode.",
    description="Starts the DRTP server to receive a file."
)
server_parser.add_argument(
    "-d", "--discard", 
    action="store_true", 
    help="Enable server's packet discard mode for testing (randomly drops one ACK)."
)
# The lambda now calls run_server_logic with args from argparse
server_parser.set_defaults(func=lambda args_ns: run_server_logic(args_ns.ip, args_ns.port, args_ns.discard)) 

# Client mode sub-parser
client_parser = subparsers.add_parser(
    "client", 
    help="Run in client mode.",
    description="Starts the DRTP client to send a file."
)
client_parser.add_argument(
    "-f", "--file", 
    type=str, 
    required=True, 
    help="Filename of the file to send."
)
client_parser.add_argument(
    "-w", "--window", 
    type=int, 
    default=1, # Original default window size was 1
    help="Client's sending window size in packets (default: 1)."
)
# The lambda now calls run_client_logic with args from argparse
client_parser.set_defaults(func=lambda args_ns: run_client_logic(args_ns.ip, args_ns.port, args_ns.file, args_ns.window)) 

# --- Main Execution (using argparse) ---
if __name__ == "__main__":
    try:
        args_namespace = parser.parse_args() 
        
        if args_namespace.mode_selected == "client":
            if not hasattr(args_namespace, 'file'):
                 parser.error("Client mode requires -f/--file argument.") # Should be caught by required=True
            if hasattr(args_namespace, 'window') and args_namespace.window < 1:
                parser.error("Window size (-w/--window) must be at least 1 for client mode.")
        
        if hasattr(args_namespace, 'func'):
            args_namespace.func(args_namespace) 
        else:
            print("Error: Mode function not found (internal setup issue).")
            parser.print_help()

    except argparse.ArgumentError as e: 
        print(f"Argument error: {e}")
    except SystemExit:
        pass 
    except Exception as e:
        print(f"An unexpected error occurred at the top level: {e}")

