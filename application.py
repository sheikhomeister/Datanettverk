#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DRTP File Transfer Application
Author: Your Name
Date: May 19, 2025

Implements a reliable file transfer protocol (DRTP) over UDP.
Features:
- Client and Server modes.
- Argument parsing using argparse.
  - Global -i IP and -p PORT options.
  - Subcommands for server and client modes.
- 8-byte DRTP header: SeqNum (2B), AckNum (2B), Flags (2B), Window (2B).
- Flags: SYN, ACK, FIN, RST.
- Connection establishment (3-way handshake).
- Reliable data transfer (Go-Back-N like).
- Connection teardown (2-way handshake).
- Optional packet discard mode for server testing.
- Configurable window size for client.
"""

import socket
import struct
import time
import os
import random
import argparse

# DRTP Header Format:
#   Sequence Number (2 bytes, unsigned short, !H)
#   Acknowledgment Number (2 bytes, unsigned short, !H)
#   Flags (2 bytes, unsigned short, !H)
#   Receiver Window (2 bytes, unsigned short, !H)
# Total = 8 bytes
header_format = '!HHHH'
header_size = struct.calcsize(header_format)
max_payload_size = 1000  # Max bytes of data per packet
max_seq_num = 65535 # Maximum sequence number (2^16 - 1)

# DRTP Flags (fit within the 2-byte flags field)
# Using distinct bit positions
syn_flag = 1 << 0  # 0000000000000001
ack_flag = 1 << 1  # 0000000000000010
fin_flag = 1 << 2  # 0000000000000100
rst_flag = 1 << 3  # 0000000000001000 (Reset flag)

default_timeout = 0.4  # 400 ms as per guidelines
default_receiver_window = 10  # Example default receiver window (in packets)

def create_packet(seq_num, ack_num, flags, window_size, payload=b''):
    """Creates a DRTP packet."""
    # Ensure sequence and ack numbers are within 16-bit range
    seq_num &= max_seq_num
    ack_num &= max_seq_num
    header = struct.pack(header_format, seq_num, ack_num, flags, window_size)
    return header + payload

def parse_packet(packet):
    """Parses a DRTP packet."""
    if len(packet) < header_size:
        return None, None, None, None, None # Packet too short
    header = packet[:header_size]
    payload = packet[header_size:]
    seq_num, ack_num, flags, window_size = struct.unpack(header_format, header)
    return seq_num, ack_num, flags, window_size, payload

def run_server(ip_address, port, discard_mode):
    """Runs the DRTP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((ip_address, port))
        print(f"Server is ready and listening at {ip_address}:{port}")
        if discard_mode:
            print("Server: Discard mode enabled (will randomly drop some ACKs).")

        # Server state
        client_address = None
        connection_active = False
        expected_seq_num = 0 
        server_isn = random.randint(0, max_seq_num) 

        output_file = None
        packets_dropped_for_test = 0

        while True:
            try:
                packet, addr = sock.recvfrom(header_size + max_payload_size)
                
                parsed = parse_packet(packet)
                if parsed[0] is None: 
                    print(f"Server: Received invalid packet from {addr}")
                    continue
                
                r_seq, r_ack, r_flags, r_wnd, r_payload = parsed

                if not connection_active:
                    if r_flags & syn_flag:
                        client_address = addr
                        print(f"Server: Received SYN from {client_address} (Seq={r_seq}, Wnd={r_wnd})")
                        
                        # Data sequence numbers start at 1 after handshake
                        expected_seq_num = 1 
                        
                        server_seq_num = server_isn # Server's ISN for SYN-ACK
                        ack_to_client_isn = r_seq  # Acknowledge client's SYN sequence
                        
                        syn_ack_packet = create_packet(
                            seq_num=server_seq_num,
                            ack_num=ack_to_client_isn, 
                            flags=syn_flag | ack_flag,
                            window_size=default_receiver_window
                        )
                        sock.sendto(syn_ack_packet, client_address)
                        print(f"Server: Sent SYN-ACK (Seq={server_seq_num}, Ack={ack_to_client_isn}) to {client_address}")
                    
                    elif r_flags & ack_flag and client_address == addr:
                        # This ACK is for our SYN-ACK
                        # Client's ACK should acknowledge server_isn
                        if r_ack == server_seq_num : # Client ACKs server's SYN
                            print(f"Server: Received ACK for SYN-ACK (Ack={r_ack}). Connection established with {client_address}.")
                            connection_active = True
                            # Prepare to receive file
                            filename = f"received_file_from_{client_address[0]}_{client_address[1]}.dat"
                            output_file = open(filename, 'wb')
                            print(f"Server: Receiving file as {filename}")
                        else:
                            print(f"Server: Received ACK with wrong ack_num {r_ack}, expected {server_seq_num}")
                
                elif connection_active and client_address == addr: # Connection is active
                    if r_flags & fin_flag:
                        print(f"Server: Received FIN (Seq={r_seq}) from {client_address}")
                        if output_file and not output_file.closed:
                            output_file.close()
                            print("Server: File closed.")
                        
                        # Send FIN-ACK
                        # Server can use a new seq num or increment its ISN for its part of FIN exchange
                        fin_ack_seq_num = (server_isn + 1) & max_seq_num 
                        fin_ack_packet = create_packet(
                            seq_num=fin_ack_seq_num, 
                            ack_num=r_seq,      # Acknowledge the FIN's sequence number
                            flags=fin_flag | ack_flag,
                            window_size=default_receiver_window
                        )
                        sock.sendto(fin_ack_packet, client_address)
                        print(f"Server: Sent FIN-ACK (Seq={fin_ack_seq_num}, Ack={r_seq}). Closing connection with {client_address}.")
                        
                        # Reset for next potential connection
                        connection_active = False
                        client_address = None
                        output_file = None
                        expected_seq_num = 1 
                        packets_dropped_for_test = 0
                        continue # Go to top of while loop to wait for new SYN

                    # Data packet handling (not SYN or FIN)
                    elif not (r_flags & syn_flag or r_flags & fin_flag): 
                        if r_seq == expected_seq_num:
                            if output_file:
                                output_file.write(r_payload)
                            # print(f"Server: Received DATA (Seq={r_seq}), Len={len(r_payload)}. Wrote to file.") # Verbose
                            
                            # Send ACK for received data
                            # Server's ACK packet seq_num can be static or incremented. ack_num acknowledges received data.
                            ack_data_packet = create_packet(
                                seq_num=(server_isn + 1) & max_seq_num, 
                                ack_num=r_seq,          
                                flags=ack_flag,
                                window_size=default_receiver_window
                            )
                            
                            if discard_mode and packets_dropped_for_test == 0 and random.random() < 0.2: # Drop first ACK sometimes
                                print(f"Server: DISCARDING ACK for packet {r_seq} (Test Drop)")
                                packets_dropped_for_test += 1 # Only drop one for this test
                            else:
                                sock.sendto(ack_data_packet, client_address)
                                # print(f"Server: Sent ACK for data packet {r_seq}") # Verbose
                            
                            expected_seq_num = (expected_seq_num + 1)
                            if expected_seq_num > max_seq_num: expected_seq_num = 1 # Wrap around for data seq
                        
                        elif r_seq < expected_seq_num: # Received an old, already processed packet
                            print(f"Server: Received duplicate DATA (Seq={r_seq}), expected {expected_seq_num}. Re-sending ACK for {r_seq}.")
                            # Re-send ACK for the old packet
                            ack_old_data_packet = create_packet(
                                seq_num=(server_isn + 1) & max_seq_num,
                                ack_num=r_seq, # ACK the sequence number of the duplicate packet
                                flags=ack_flag,
                                window_size=default_receiver_window
                            )
                            sock.sendto(ack_old_data_packet, client_address)
                        else: # Out-of-order packet (GBN: server discards it and waits for expected_seq_num)
                            print(f"Server: Received out-of-order DATA (Seq={r_seq}), expected {expected_seq_num}. Discarding.")
                            # Server does NOT send an ACK for out-of-order packets in GBN.
                            # It will re-send an ACK for the last correctly received in-order packet if client retransmits it.

            except socket.timeout:
                # Server socket doesn't have a timeout in this main loop by default
                pass
            except Exception as e:
                print(f"Server error: {e}")
                if output_file and not output_file.closed:
                    output_file.close()
                # Consider sending RST if connection was active
                if connection_active and client_address:
                    # Use a sequence number for RST, can be server_isn or an increment
                    rst_packet = create_packet((server_isn + 1) & max_seq_num, r_seq if 'r_seq' in locals() else 0, rst_flag, 0)
                    sock.sendto(rst_packet, client_address)
                    print(f"Server: Sent RST to {client_address} due to error.")
                connection_active = False # Reset state
                client_address = None


    except OSError as e: # For socket binding errors etc.
        print(f"Server socket error: {e}")
    finally:
        print("Server shutting down.")
        if sock:
            sock.close()

def run_client(ip_address, port, filename, window_size_arg):
    """Runs the DRTP client."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(default_timeout)
    server_address = (ip_address, port)

    try:
        # --- Connection Establishment (3-way handshake) ---
        client_isn = random.randint(1, max_seq_num // 2) # Client's initial sequence number
        
        print(f"Client: Sending SYN (Seq={client_isn}, Wnd={default_receiver_window}) to {server_address}...")
        syn_packet = create_packet(client_isn, 0, syn_flag, default_receiver_window)
        sock.sendto(syn_packet, server_address)

        # Wait for SYN-ACK
        try:
            packet, _ = sock.recvfrom(header_size + max_payload_size) # Server might send payload with SYN-ACK
            r_seq, r_ack, r_flags, r_wnd, _ = parse_packet(packet)

            if r_flags & syn_flag and r_flags & ack_flag and r_ack == client_isn:
                print(f"Client: Received SYN-ACK (Seq={r_seq}, Ack={r_ack}, Wnd={r_wnd})")
                server_isn = r_seq # Server's ISN

                # Send ACK for SYN-ACK
                # Client's ACK packet uses its next sequence number, client_isn + 1
                # It acknowledges server's ISN (r_seq)
                ack_for_syn_ack_seq = (client_isn + 1) & max_seq_num
                ack_packet = create_packet(
                    seq_num=ack_for_syn_ack_seq, 
                    ack_num=server_isn, 
                    flags=ack_flag, 
                    window_size=default_receiver_window
                )
                sock.sendto(ack_packet, server_address)
                print(f"Client: Sent ACK for SYN-ACK (Seq={ack_for_syn_ack_seq}, Ack={server_isn}). Connection established.")
                
                # Data transfer starts with sequence number 1 as per guideline hint
                # This means client_isn for handshake is separate from data sequence space.
                current_data_seq_num = 1 
                
            else:
                print(f"Client: Handshake failed. Received unexpected packet or flags/ack. Flags={hex(r_flags)}, Ack={r_ack}, Expected Ack={client_isn}")
                if r_flags & rst_flag: print("Client: Received RST from server.")
                return # Exit client
        except socket.timeout:
            print("Client: Timeout waiting for SYN-ACK. Connection failed.")
            return # Exit client

        # --- Data Transfer (Go-Back-N like) ---
        print(f"Client: Starting file transfer of '{filename}' with window size {window_size_arg}")
        start_time = time.time()
        
        try:
            with open(filename, 'rb') as f:
                # send_base = current_data_seq_num # For GBN, tracks the oldest unacknowledged packet
                next_seq_to_send = current_data_seq_num
                
                # Window stores dicts: {'seq': sequence_number, 'pkt': packet_bytes, 'time': time_sent}
                window = [] 
                
                file_ended = False
                last_acked_seq = 0 # Tracks the highest ACK received from server for data

                while True:
                    # Fill window if space available and data exists
                    while len(window) < window_size_arg and not file_ended:
                        data_chunk = f.read(max_payload_size)
                        if not data_chunk:
                            file_ended = True
                            break
                        
                        # Packet for data_chunk
                        # ack_num in data packets can be set to server_isn (last thing acked from server)
                        # or 0 if not actively acknowledging something specific from server in this data packet.
                        data_packet = create_packet(next_seq_to_send, server_isn, 0, default_receiver_window, data_chunk)
                        window.append({'seq': next_seq_to_send, 'pkt': data_packet, 'time': 0}) 
                        
                        next_seq_to_send = (next_seq_to_send + 1)
                        if next_seq_to_send > max_seq_num: next_seq_to_send = 1 # Wrap around data seq

                    # Send packets in window that haven't been sent (time = 0)
                    for i in range(len(window)):
                        if window[i]['time'] == 0: 
                           sock.sendto(window[i]['pkt'], server_address)
                           window[i]['time'] = time.time()
                           # print(f"Client: Sent DATA (Seq={window[i]['seq']})") # Verbose
                    
                    if not window and file_ended: # All packets sent and ACKed
                        break

                    # Wait for ACKs or timeout
                    try:
                        ack_packet_raw, _ = sock.recvfrom(header_size) # ACK packets only have header
                        # Server's ACK packet seq_num is its own, ack_num acknowledges client's data packet seq_num
                        r_seq_ack, r_ack_ack, r_flags_ack, r_wnd_ack, _ = parse_packet(ack_packet_raw)

                        if r_flags_ack & ack_flag:
                            # print(f"Client: Received ACK (ServerSeq={r_seq_ack}, AckNumForMyData={r_ack_ack})") # Verbose
                            
                            # In GBN, an ACK for sequence N implies all packets up to N are received.
                            # Here, server sends ACK for specific r_seq received by it, which is in r_ack_ack.
                            acked_data_seq = r_ack_ack 
                            
                            if acked_data_seq > last_acked_seq or \
                               (last_acked_seq > max_seq_num - window_size_arg and acked_data_seq < window_size_arg): # Handle wrap-around for comparison
                                last_acked_seq = acked_data_seq
                            
                            # Remove ACKed packets from the window (all up to and including acked_data_seq)
                            new_window = []
                            for pkt_info in window:
                                # Handle sequence number wrap-around for comparison
                                if pkt_info['seq'] <= acked_data_seq or \
                                   (acked_data_seq < window[0]['seq'] and pkt_info['seq'] > window[0]['seq']-window_size_arg) : # If ACK wrapped
                                    if pkt_info['seq'] == acked_data_seq:
                                         print(f"Client: DATA (Seq={acked_data_seq}) confirmed ACKed.")
                                else:
                                    new_window.append(pkt_info)
                            window = new_window
                            
                            if not window and file_ended: break 

                        elif r_flags_ack & rst_flag:
                            print("Client: Received RST from server during data transfer. Aborting.")
                            return # Exit client

                    except socket.timeout:
                        print(f"Client: Timeout. Resending window (Oldest unacked Seq={(window[0]['seq'] if window else 'N/A')}).")
                        for i in range(len(window)): # Resend all outstanding packets in the window
                            sock.sendto(window[i]['pkt'], server_address)
                            window[i]['time'] = time.time() # Update sent time
                            # print(f"Client: Re-sent DATA (Seq={window[i]['seq']})") # Verbose
                        if not window and file_ended: # Should not happen if timeout occurred with items in window
                             break
            
            end_time = time.time()
            file_size_bytes = os.path.getsize(filename)
            time_taken = end_time - start_time
            if time_taken > 0:
                throughput_bps = (file_size_bytes * 8) / time_taken
                print(f"Client: File transfer complete for '{filename}'.")
                print(f"Client: Size = {file_size_bytes} bytes. Time = {time_taken:.2f} s. Throughput = {throughput_bps / 1_000_000:.2f} Mbps.")
            else:
                print(f"Client: File transfer complete for '{filename}'. Size = {file_size_bytes} bytes. Time too short to calculate throughput.")


        except FileNotFoundError:
            print(f"Client: Error - File '{filename}' not found.")
            # Send RST if connection was established
            if 'server_isn' in locals(): # Check if handshake completed
                 rst_packet = create_packet( (client_isn + 2) & max_seq_num, server_isn, rst_flag, 0)
                 sock.sendto(rst_packet, server_address)
            return # Exit client
        except Exception as e:
            print(f"Client: Error during file transfer: {e}")
            if 'server_isn' in locals():
                rst_packet = create_packet( (client_isn + 2) & max_seq_num, server_isn, rst_flag, 0)
                sock.sendto(rst_packet, server_address)
            return # Exit client


        # --- Connection Teardown ---
        # Client's FIN sequence number can be its next logical sequence, e.g., client_isn + 2, or next data seq
        fin_seq = ( (client_isn + 2) & max_seq_num ) if not 'next_seq_to_send' in locals() or next_seq_to_send == 1 else next_seq_to_send

        print(f"Client: Sending FIN (Seq={fin_seq}) to {server_address}...")
        # ack_num in FIN can be server_isn or last acked server sequence.
        fin_packet = create_packet(fin_seq, server_isn if 'server_isn' in locals() else 0, fin_flag, default_receiver_window) 
        sock.sendto(fin_packet, server_address)

        try:
            # Wait for server's FIN-ACK (or just ACK for our FIN)
            packet, _ = sock.recvfrom(header_size)
            r_seq_fin, r_ack_fin, r_flags_fin, r_wnd_fin, _ = parse_packet(packet)

            if (r_flags_fin & fin_flag and r_flags_fin & ack_flag and r_ack_fin == fin_seq) or \
               (r_flags_fin & ack_flag and r_ack_fin == fin_seq): # Server might just ACK our FIN
                print(f"Client: Received ACK/FIN-ACK for FIN (ServerSeq={r_seq_fin}, AckForMyFIN={r_ack_fin}). Closing connection.")
            else:
                print(f"Client: Did not receive proper ACK/FIN-ACK (Flags={hex(r_flags_fin)}, Ack={r_ack_fin}, Expected AckForMyFIN={fin_seq}). Closing anyway.")
                if r_flags_fin & rst_flag: print("Client: Received RST from server during teardown.")

        except socket.timeout:
            print("Client: Timeout waiting for FIN-ACK. Closing connection anyway.")

    except OSError as e: # For socket creation errors etc.
        print(f"Client socket error: {e}")
    except Exception as e:
        print(f"Client general error: {e}")
    finally:
        print("Client shutting down.")
        if sock:
            sock.close()

# --- Main execution logic (argparse setup) ---
# This setup expects -i and -p as global options BEFORE the mode (server/client)
parser = argparse.ArgumentParser(
    description="DRTP File Transfer Application",
    formatter_class=argparse.RawTextHelpFormatter # To better format help text
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
    dest="mode", 
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
server_parser.set_defaults(func=lambda args_ns: run_server(args_ns.ip, args_ns.port, args_ns.discard)) 

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
    default=5, 
    help="Client's sending window size in packets (default: 5)."
)
client_parser.set_defaults(func=lambda args_ns: run_client(args_ns.ip, args_ns.port, args_ns.file, args_ns.window)) 

try:
    args_namespace = parser.parse_args() 
    
    # Client-specific window size validation (if client mode is chosen)
    if args_namespace.mode == "client":
        if not hasattr(args_namespace, 'file'): # Should be caught by required=True
             parser.error("Client mode requires -f/--file argument.")
        if hasattr(args_namespace, 'window') and args_namespace.window < 1:
            parser.error("Window size (-w/--window) must be at least 1 for client mode.")
    
    if hasattr(args_namespace, 'func'):
        args_namespace.func(args_namespace) # Call the appropriate run_server or run_client
    else:
        # This case should not be reached if mode is required and subparsers are set up correctly.
        # However, as a fallback, print help.
        print("Error: Mode function not found. This indicates an internal setup issue.")
        parser.print_help()

except argparse.ArgumentError as e: # Catch specific argparse errors
    print(f"Argument error: {e}")
    # parser.print_help() # Argparse usually prints help on error automatically
except SystemExit:
    # Argparse raises SystemExit for -h or errors, allow it to exit cleanly
    pass 
except Exception as e:
    print(f"An unexpected error occurred at the top level: {e}")

