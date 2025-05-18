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
HEADER_FORMAT = '!HHHH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD_SIZE = 1000  # Max bytes of data per packet
MAX_SEQ_NUM = 65535 # Maximum sequence number (2^16 - 1)

# DRTP Flags (fit within the 2-byte flags field)
# Using distinct bit positions
SYN_FLAG = 1 << 0  # 0000000000000001
ACK_FLAG = 1 << 1  # 0000000000000010
FIN_FLAG = 1 << 2  # 0000000000000100
RST_FLAG = 1 << 3  # 0000000000001000 (Reset flag)

DEFAULT_TIMEOUT = 0.4  # 400 ms as per guidelines
DEFAULT_RECEIVER_WINDOW = 10  # Example default receiver window (in packets)

def create_packet(seq_num, ack_num, flags, window_size, payload=b''):
    """Creates a DRTP packet."""
    # Ensure sequence and ack numbers are within 16-bit range
    seq_num &= MAX_SEQ_NUM
    ack_num &= MAX_SEQ_NUM
    header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, window_size)
    return header + payload

def parse_packet(packet):
    """Parses a DRTP packet."""
    if len(packet) < HEADER_SIZE:
        return None, None, None, None, None # Packet too short
    header = packet[:HEADER_SIZE]
    payload = packet[HEADER_SIZE:]
    seq_num, ack_num, flags, window_size = struct.unpack(HEADER_FORMAT, header)
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
        expected_seq_num = 0 # Server expects client's first data packet with seq_num 1 after handshake
        server_isn = random.randint(0, MAX_SEQ_NUM) # Server's initial sequence number

        output_file = None
        packets_dropped_for_test = 0

        while True:
            try:
                packet, addr = sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD_SIZE)
                
                parsed = parse_packet(packet)
                if parsed[0] is None: # Invalid packet
                    print(f"Server: Received invalid packet from {addr}")
                    continue
                
                r_seq, r_ack, r_flags, r_wnd, r_payload = parsed

                if not connection_active:
                    if r_flags & SYN_FLAG:
                        client_address = addr
                        print(f"Server: Received SYN from {client_address} (Seq={r_seq}, Wnd={r_wnd})")
                        
                        # Client's ISN is r_seq. Server expects data starting from r_seq + 1
                        # For simplicity, let's assume data starts at 1 after handshake.
                        # The assignment says "data can start with sequence 1" (page 15).
                        # Let's assume client's first data packet will be seq 1.
                        expected_seq_num = 1 # After handshake, expect data packet 1
                        
                        # Send SYN-ACK
                        server_seq_num = server_isn
                        ack_to_client_isn = r_seq # Acknowledge the client's ISN
                        
                        syn_ack_packet = create_packet(
                            seq_num=server_seq_num,
                            ack_num=ack_to_client_isn, # Acknowledging client's SYN seq num
                            flags=SYN_FLAG | ACK_FLAG,
                            window_size=DEFAULT_RECEIVER_WINDOW
                        )
                        sock.sendto(syn_ack_packet, client_address)
                        print(f"Server: Sent SYN-ACK (Seq={server_seq_num}, Ack={ack_to_client_isn}) to {client_address}")
                    
                    elif r_flags & ACK_FLAG and client_address == addr:
                        # This ACK is for our SYN-ACK
                        # Client's ACK should acknowledge server_isn
                        if r_ack == server_seq_num : # Client ACKs server's SYN
                            print(f"Server: Received ACK for SYN-ACK (Ack={r_ack}). Connection established with {client_address}.")
                            connection_active = True
                            # Prepare to receive file
                            # Let's use a fixed name or derive from client info if possible
                            filename = f"received_file_from_{client_address[0]}_{client_address[1]}.dat"
                            output_file = open(filename, 'wb')
                            print(f"Server: Receiving file as {filename}")
                        else:
                            print(f"Server: Received ACK with wrong ack_num {r_ack}, expected {server_seq_num}")
                
                elif connection_active and client_address == addr:
                    if r_flags & FIN_FLAG:
                        print(f"Server: Received FIN (Seq={r_seq}) from {client_address}")
                        if output_file:
                            output_file.close()
                            print("Server: File closed.")
                        
                        # Send FIN-ACK
                        fin_ack_packet = create_packet(
                            seq_num=server_isn + 1, # Server can use a new seq num or increment
                            ack_num=r_seq,      # Acknowledge the FIN's sequence number
                            flags=FIN_FLAG | ACK_FLAG,
                            window_size=DEFAULT_RECEIVER_WINDOW
                        )
                        sock.sendto(fin_ack_packet, client_address)
                        print(f"Server: Sent FIN-ACK. Closing connection with {client_address}.")
                        
                        # Reset for next connection
                        connection_active = False
                        client_address = None
                        output_file = None
                        expected_seq_num = 1 # Reset for a new potential handshake
                        packets_dropped_for_test = 0
                        continue

                    # Data packet
                    elif not (r_flags & SYN_FLAG or r_flags & FIN_FLAG): # Regular data packet
                        if r_seq == expected_seq_num:
                            if output_file:
                                output_file.write(r_payload)
                            print(f"Server: Received DATA (Seq={r_seq}), Len={len(r_payload)}. Wrote to file.")
                            
                            # Send ACK for received data
                            ack_packet = create_packet(
                                seq_num=server_isn + 1, # Server's current sequence (can be static for pure ACKs)
                                ack_num=r_seq,          # Acknowledge the data packet's sequence number
                                flags=ACK_FLAG,
                                window_size=DEFAULT_RECEIVER_WINDOW
                            )
                            
                            if discard_mode and packets_dropped_for_test == 0 and random.random() < 0.2: # Drop first ACK sometimes
                                print(f"Server: DISCARDING ACK for packet {r_seq} (Test Drop)")
                                packets_dropped_for_test += 1
                            else:
                                sock.sendto(ack_packet, client_address)
                                # print(f"Server: Sent ACK for data packet {r_seq}")
                            
                            expected_seq_num = (expected_seq_num + 1) & MAX_SEQ_NUM
                            if expected_seq_num == 0: expected_seq_num = 1 # Wrap around, avoid 0 for data
                        
                        elif r_seq < expected_seq_num:
                            # Duplicate of an old packet, re-ACK it
                            print(f"Server: Received duplicate DATA (Seq={r_seq}), expected {expected_seq_num}. Re-sending ACK.")
                            ack_packet = create_packet(
                                seq_num=server_isn + 1,
                                ack_num=r_seq,
                                flags=ACK_FLAG,
                                window_size=DEFAULT_RECEIVER_WINDOW
                            )
                            sock.sendto(ack_packet, client_address)
                        else:
                            # Out-of-order packet (GBN: ignore, wait for expected)
                            print(f"Server: Received out-of-order DATA (Seq={r_seq}), expected {expected_seq_num}. Discarding.")
                            # GBN server does not ACK out-of-order packets. Client will timeout.

            except socket.timeout:
                # Server socket doesn't have a timeout in this loop by default
                pass
            except Exception as e:
                print(f"Server error: {e}")
                if output_file and not output_file.closed:
                    output_file.close()
                # Consider sending RST if connection was active
                if connection_active and client_address:
                    rst_packet = create_packet(server_isn + 1, r_seq if 'r_seq' in locals() else 0, RST_FLAG, 0)
                    sock.sendto(rst_packet, client_address)
                    print(f"Server: Sent RST to {client_address} due to error.")
                connection_active = False
                client_address = None


    except OSError as e:
        print(f"Server socket error: {e}")
    finally:
        print("Server shutting down.")
        sock.close()

def run_client(ip_address, port, filename, window_size_arg):
    """Runs the DRTP client."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    server_address = (ip_address, port)

    try:
        # --- Connection Establishment (3-way handshake) ---
        client_isn = random.randint(1, MAX_SEQ_NUM // 2) # Client's initial sequence number, start at 1
        current_seq_num = client_isn
        server_expected_ack_for_syn = current_seq_num # Server should ACK this
        
        print(f"Client: Sending SYN (Seq={current_seq_num}, Wnd={DEFAULT_RECEIVER_WINDOW}) to {server_address}...")
        syn_packet = create_packet(current_seq_num, 0, SYN_FLAG, DEFAULT_RECEIVER_WINDOW)
        sock.sendto(syn_packet, server_address)

        # Wait for SYN-ACK
        try:
            packet, _ = sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD_SIZE)
            r_seq, r_ack, r_flags, r_wnd, _ = parse_packet(packet)

            if r_flags & SYN_FLAG and r_flags & ACK_FLAG and r_ack == server_expected_ack_for_syn:
                print(f"Client: Received SYN-ACK (Seq={r_seq}, Ack={r_ack}, Wnd={r_wnd})")
                server_isn = r_seq # Server's ISN

                # Send ACK for SYN-ACK
                # Client's next sequence number for data will be client_isn + 1 (or just 1 as per simplified data seq)
                # The ACK packet itself will have a sequence number.
                ack_for_syn_ack_seq = current_seq_num # Can re-use ISN or ISN+1 for this ACK packet's seq
                                                    # Let's use client_isn for this specific ACK packet's seq_num
                
                # The ack_num field in this ACK packet acknowledges the server's SYN packet's sequence number
                ack_packet = create_packet(
                    seq_num=ack_for_syn_ack_seq, 
                    ack_num=server_isn, # Acknowledging server's ISN from SYN-ACK
                    flags=ACK_FLAG, 
                    window_size=DEFAULT_RECEIVER_WINDOW
                )
                sock.sendto(ack_packet, server_address)
                print(f"Client: Sent ACK for SYN-ACK (Seq={ack_for_syn_ack_seq}, Ack={server_isn}). Connection established.")
                
                # Data transfer starts with sequence number 1 as per guideline hint
                # This means client_isn for handshake is separate from data sequence space.
                # Or, if client_isn is 0, first data is 1. Let's use a dedicated data sequence counter.
                data_seq_num_base = 1 
                
            else:
                print(f"Client: Handshake failed. Received unexpected packet or flags/ack. Flags={r_flags}, Ack={r_ack}, Expected Ack={server_expected_ack_for_syn}")
                if r_flags & RST_FLAG: print("Client: Received RST from server.")
                return
        except socket.timeout:
            print("Client: Timeout waiting for SYN-ACK. Connection failed.")
            return

        # --- Data Transfer (Go-Back-N like) ---
        print(f"Client: Starting file transfer of '{filename}' with window size {window_size_arg}")
        start_time = time.time()
        
        try:
            with open(filename, 'rb') as f:
                send_base = data_seq_num_base
                next_seq_num = data_seq_num_base
                window = [] # Stores (seq_num, packet_data, sent_time)
                
                file_ended = False

                while True:
                    # Fill window if space available and data exists
                    while len(window) < window_size_arg and not file_ended:
                        data_chunk = f.read(MAX_PAYLOAD_SIZE)
                        if not data_chunk:
                            file_ended = True
                            break
                        
                        # Packet for data_chunk
                        # ack_num in data packets can be set to server_isn (last thing acked from server)
                        data_packet = create_packet(next_seq_num, server_isn, 0, DEFAULT_RECEIVER_WINDOW, data_chunk)
                        window.append({'seq': next_seq_num, 'pkt': data_packet, 'time': 0}) # time will be set on send
                        next_seq_num = (next_seq_num + 1)
                        if next_seq_num > MAX_SEQ_NUM: next_seq_num = data_seq_num_base # Wrap around

                    # Send packets in window that haven't been sent or need resending
                    for i in range(len(window)):
                        if window[i]['time'] == 0: # Not yet sent or first time for this chunk in window
                           sock.sendto(window[i]['pkt'], server_address)
                           window[i]['time'] = time.time()
                           # print(f"Client: Sent DATA (Seq={window[i]['seq']})")
                    
                    if not window and file_ended: # All packets sent and ACKed
                        break

                    # Wait for ACKs or timeout
                    try:
                        ack_packet_raw, _ = sock.recvfrom(HEADER_SIZE) # Only header for ACK
                        r_seq, r_ack, r_flags, r_wnd, _ = parse_packet(ack_packet_raw)

                        if r_flags & ACK_FLAG:
                            # print(f"Client: Received ACK (AckNum={r_ack})")
                            # GBN: ACK for r_ack means all packets up to r_ack are received
                            # Our server sends ACK for specific seq_num received
                            
                            new_window = []
                            acked_upto = -1
                            for pkt_info in window:
                                if pkt_info['seq'] == r_ack:
                                    acked_upto = r_ack
                                    # This packet is ACKed, subsequent ones in GBN are implicitly acked by cumulative.
                                    # However, our server ACKs individual packets.
                                    # So, remove only the specifically ACKed packet.
                                    # For a more GBN-like cumulative ACK, client would update send_base.
                                    # Let's stick to removing the specific packet acked.
                                    print(f"Client: DATA (Seq={r_ack}) ACKed.")
                                else:
                                    new_window.append(pkt_info)
                            
                            window = new_window
                            if acked_upto != -1:
                                # Update send_base if using cumulative ACKs.
                                # For individual ACKs, this logic is simpler.
                                if not window and file_ended: break # All sent and acked

                        elif r_flags & RST_FLAG:
                            print("Client: Received RST from server during data transfer. Aborting.")
                            return


                    except socket.timeout:
                        print(f"Client: Timeout. Resending window (Base={window[0]['seq'] if window else 'N/A'}).")
                        for i in range(len(window)): # Resend all outstanding packets in the window
                            sock.sendto(window[i]['pkt'], server_address)
                            window[i]['time'] = time.time() # Update sent time
                            # print(f"Client: Re-sent DATA (Seq={window[i]['seq']})")
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
            return
        except Exception as e:
            print(f"Client: Error during file transfer: {e}")
            # Consider sending RST
            rst_packet = create_packet(next_seq_num if 'next_seq_num' in locals() else client_isn, server_isn if 'server_isn' in locals() else 0, RST_FLAG, 0)
            sock.sendto(rst_packet, server_address)
            return


        # --- Connection Teardown ---
        # Client's next sequence number for FIN. Can be next_seq_num or a new one.
        fin_seq = next_seq_num if 'next_seq_num' in locals() and next_seq_num > data_seq_num_base else data_seq_num_base
        if file_ended and 'next_seq_num' not in locals() : fin_seq = client_isn +1 # if no data was sent

        print(f"Client: Sending FIN (Seq={fin_seq}) to {server_address}...")
        fin_packet = create_packet(fin_seq, server_isn, FIN_FLAG, DEFAULT_RECEIVER_WINDOW) # ack_num can be last server_isn
        sock.sendto(fin_packet, server_address)

        try:
            packet, _ = sock.recvfrom(HEADER_SIZE)
            r_seq, r_ack, r_flags, r_wnd, _ = parse_packet(packet)

            if r_flags & FIN_FLAG and r_flags & ACK_FLAG and r_ack == fin_seq:
                print(f"Client: Received FIN-ACK (Seq={r_seq}, Ack={r_ack}). Closing connection.")
            elif r_flags & ACK_FLAG and r_ack == fin_seq : # Simpler FIN ACK from server
                print(f"Client: Received ACK for FIN (Seq={r_seq}, Ack={r_ack}). Closing connection.")
            else:
                print("Client: Did not receive proper FIN-ACK. Closing anyway.")
                if r_flags & RST_FLAG: print("Client: Received RST from server during teardown.")

        except socket.timeout:
            print("Client: Timeout waiting for FIN-ACK. Closing connection anyway.")

    except OSError as e:
        print(f"Client socket error: {e}")
    except Exception as e:
        print(f"Client general error: {e}")
    finally:
        print("Client shutting down.")
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DRTP File Transfer Application")
    parser.add_argument("-i", "--ip", type=str, required=True, help="IP address of the server (or client to connect to). For server, IP to bind to.")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port number.")

    subparsers = parser.add_subparsers(dest="mode", required=True, help="Mode of operation")

    # Server mode
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument("-d", "--discard", action="store_true", help="Enable packet discard mode for testing (server only).")
    server_parser.set_defaults(func=lambda args: run_server(args.ip, args.port, args.discard))

    # Client mode
    client_parser = subparsers.add_parser("client", help="Run in client mode")
    client_parser.add_argument("-f", "--file", type=str, required=True, help="Filename to send (client only).")
    client_parser.add_argument("-w", "--window", type=int, default=5, help="Window size in packets (client only). Default is 5.")
    client_parser.set_defaults(func=lambda args: run_client(args.ip, args.port, args.file, args.window))
    
    try:
        args = parser.parse_args()
        if args.window is not None and args.window < 1: # client specific check
            parser.error("Window size must be at least 1.")
        args.func(args)
    except AttributeError:
        parser.print_help()
    except argparse.ArgumentError as e:
        print(f"Argument error: {e}")
        parser.print_help()

