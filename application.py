#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DRTP File Transfer Application
Supports client and server modes for reliable file transfer over UDP.
"""

import socket
import struct
import time
import os
import random
import argparse

# DRTP Header Constants
# Sequence Number (4 bytes), Acknowledgment Number (4 bytes), Flags (2 bytes), Receiver Window (2 bytes)
# Total header size = 12 bytes
HEADER_FORMAT = '!IIHH' # I for unsigned int (4 bytes), H for unsigned short (2 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_DATA_SIZE = 1000  # Max bytes of data in a packet
PACKET_BUFFER_SIZE = HEADER_SIZE + MAX_DATA_SIZE # Max size for receiving packets

# DRTP Flags (using lower 4 bits of the 2-byte flags field)
RST_FLAG = 0x1  # Reset connection
ACK_FLAG = 0x2  # Acknowledgment
SYN_FLAG = 0x4  # Synchronize sequence numbers
FIN_FLAG = 0x8  # Finish connection

# GBN Timeout
GBN_TIMEOUT = 0.4  # 400 milliseconds

def create_packet(seq_num, ack_num, flags, receiver_window, data=b''):
    """
    Creates a DRTP packet.
    Args:
        seq_num (int): Sequence number.
        ack_num (int): Acknowledgment number.
        flags (int): Combination of DRTP flags (SYN, ACK, FIN, RST).
        receiver_window (int): Receiver window size.
        data (bytes): Payload data.
    Returns:
        bytes: The packed DRTP packet.
    """
    # Ensure data length is not included in the main header fields as per diagram,
    # but it's implicitly known by UDP datagram length or handled by application.
    # For this implementation, we'll rely on receiver knowing how to get data.
    # The previous version had data_length in header, but the new spec (Page 11) doesn't show it.
    # We'll assume the data part is everything after the 12-byte header.
    header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, receiver_window)
    return header + data

def parse_packet(packet):
    """
    Parses a DRTP packet.
    Args:
        packet (bytes): The raw packet received.
    Returns:
        tuple: (seq_num, ack_num, flags, receiver_window, data)
               Returns None if packet is too short.
    """
    if len(packet) < HEADER_SIZE:
        return None, None, None, None, None # Packet too short
    header_part = packet[:HEADER_SIZE]
    data_part = packet[HEADER_SIZE:]
    seq_num, ack_num, flags, receiver_window = struct.unpack(HEADER_FORMAT, header_part)
    return seq_num, ack_num, flags, receiver_window, data_part

def run_server(ip_address, port, discard_mode):
    """Runs the DRTP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((ip_address, port))
        print(f"Server is ready and listening at {ip_address}:{port}")
        if discard_mode:
            print("Server: Discard mode enabled (will randomly drop an ACK for testing)")

        # Connection Establishment
        print("Server: Waiting for SYN...")
        syn_packet_raw, client_address = sock.recvfrom(PACKET_BUFFER_SIZE)
        seq_num, ack_num, flags, recv_win, data = parse_packet(syn_packet_raw)

        if flags and flags & SYN_FLAG:
            print(f"Server: Received SYN from {client_address} (Seq: {seq_num})")
            # Server's initial sequence number can be random or fixed. Let's use 0 for simplicity.
            server_seq_num = random.randint(0, 65535)
            # Acknowledge client's sequence number
            syn_ack_packet = create_packet(server_seq_num, seq_num + 1, SYN_FLAG | ACK_FLAG, 0) # Receiver window can be set
            sock.sendto(syn_ack_packet, client_address)
            print(f"Server: Sent SYN-ACK (Seq: {server_seq_num}, Ack: {seq_num + 1})")

            # Wait for ACK from client to complete handshake
            ack_packet_raw, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
            final_ack_seq, final_ack_ack_num, final_ack_flags, _, _ = parse_packet(ack_packet_raw)
            
            if final_ack_flags and final_ack_flags & ACK_FLAG and final_ack_ack_num == server_seq_num + 1:
                print(f"Server: Received ACK. Connection established with {client_address} (Client Acked Seq: {final_ack_ack_num})")
                expected_data_seq_num = seq_num + 1 # Client's data will start after its SYN
            else:
                print("Server: Handshake failed. Did not receive correct final ACK.")
                # Optionally send RST
                rst_packet = create_packet(server_seq_num, final_ack_seq +1 if final_ack_seq is not None else 0, RST_FLAG, 0)
                sock.sendto(rst_packet, client_address)
                return
        else:
            print("Server: Did not receive SYN. Packet ignored.")
            # Optionally send RST
            rst_packet = create_packet(0, seq_num + 1 if seq_num is not None else 0, RST_FLAG, 0) # Seq 0, Ack their seq if available
            sock.sendto(rst_packet, client_address)
            return

        # Data Transfer
        output_filename = f"received_file_from_{client_address[0]}_{client_address[1]}.dat"
        with open(output_filename, 'wb') as output_file:
            print(f"Server: Receiving data and saving to {output_filename}")
            dropped_ack_for_testing = False # For discard mode

            while True:
                try:
                    data_packet_raw, r_addr = sock.recvfrom(PACKET_BUFFER_SIZE)
                    if r_addr != client_address: # Ignore packets from other sources
                        print(f"Server: Received packet from unexpected source {r_addr}. Ignored.")
                        continue

                    d_seq, d_ack, d_flags, d_recv_win, d_data = parse_packet(data_packet_raw)

                    if d_flags is None: # Malformed packet
                        print("Server: Received malformed packet.")
                        continue
                    
                    if d_flags & RST_FLAG:
                        print(f"Server: Received RST from {client_address}. Closing connection.")
                        break

                    if d_flags & FIN_FLAG:
                        print(f"Server: Received FIN (Seq: {d_seq}). Closing file.")
                        # Acknowledge FIN
                        fin_ack_packet = create_packet(server_seq_num, d_seq + 1, FIN_FLAG | ACK_FLAG, 0)
                        sock.sendto(fin_ack_packet, client_address)
                        print(f"Server: Sent FIN-ACK (Ack: {d_seq + 1})")
                        # According to typical TCP, server might wait for a bit (TIME_WAIT)
                        # For simplicity here, we break after sending FIN-ACK.
                        break
                    
                    # If it's a data packet (no SYN, FIN, RST flags, or just ACK if it's a keep-alive)
                    if not (d_flags & (SYN_FLAG | FIN_FLAG | RST_FLAG)):
                        if d_seq == expected_data_seq_num:
                            output_file.write(d_data)
                            print(f"Server: Received packet (Seq: {d_seq}), wrote {len(d_data)} bytes.")
                            
                            # Send ACK for the received data packet
                            ack_response_packet = create_packet(server_seq_num, d_seq + 1, ACK_FLAG, 0) # Ack next expected byte from client
                            
                            if discard_mode and not dropped_ack_for_testing and random.random() < 0.3: # Drop ~30% of ACKs in discard mode
                                print(f"Server (Discard Mode): Dropping ACK for packet (Seq: {d_seq})")
                                dropped_ack_for_testing = True # Drop only one for simple test
                            else:
                                sock.sendto(ack_response_packet, client_address)
                                # print(f"Server: Sent ACK for data packet (Seq: {d_seq}, Ack: {d_seq + 1})")
                            
                            expected_data_seq_num += 1 # Naive increment; for GBN, this is okay.
                        elif d_seq < expected_data_seq_num:
                            # Duplicate packet, re-ACK previous
                            print(f"Server: Received duplicate packet (Seq: {d_seq}), expected (Seq: {expected_data_seq_num}). Resending ACK.")
                            ack_response_packet = create_packet(server_seq_num, expected_data_seq_num, ACK_FLAG, 0) # Ack for the next one client should send
                            sock.sendto(ack_response_packet, client_address)
                        else:
                            # Out-of-order packet (GBN receiver discards and re-sends ACK for last in-order packet)
                            print(f"Server: Received out-of-order packet (Seq: {d_seq}), expected (Seq: {expected_data_seq_num}). Discarding and re-ACKing.")
                            ack_response_packet = create_packet(server_seq_num, expected_data_seq_num, ACK_FLAG, 0)
                            sock.sendto(ack_response_packet, client_address)
                except socket.timeout:
                    print("Server: Socket timeout (should not happen in basic server listen loop unless set).")
                    continue # Or handle as error
                except Exception as e:
                    print(f"Server: Error during data reception: {e}")
                    break
        print(f"Server: File transfer complete. Received file saved as {output_filename}")

    except Exception as e:
        print(f"Server error: {e}")
    finally:
        sock.close()
        print("Server: Socket closed.")


def run_client(server_ip, server_port, filename, window_size):
    """Runs the DRTP client."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server_ip, server_port)
    
    # Client's initial sequence number
    client_seq_num = random.randint(0, 65535)
    expected_server_seq_num = 0 # Will be updated after SYN-ACK

    try:
        # Connection Establishment (3-way handshake)
        print(f"Client: Sending SYN to {server_address} (Seq: {client_seq_num})")
        syn_packet = create_packet(client_seq_num, 0, SYN_FLAG, 0) # Ack num 0, Recv window 0 for SYN
        sock.sendto(syn_packet, server_address)
        sock.settimeout(GBN_TIMEOUT * 5) # Longer timeout for handshake

        try:
            syn_ack_raw, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
        except socket.timeout:
            print("Client: Timeout waiting for SYN-ACK. Connection failed.")
            # Optionally send RST if we had a partial exchange, but here it's just initial timeout
            # rst_packet = create_packet(client_seq_num, 0, RST_FLAG, 0)
            # sock.sendto(rst_packet, server_address) # This might not be received if server is down
            return

        s_ack_seq, s_ack_ack_num, s_ack_flags, s_ack_recv_win, _ = parse_packet(syn_ack_raw)

        if s_ack_flags and (s_ack_flags & SYN_FLAG) and (s_ack_flags & ACK_FLAG) and s_ack_ack_num == client_seq_num + 1:
            print(f"Client: Received SYN-ACK (Server Seq: {s_ack_seq}, Server Ack: {s_ack_ack_num})")
            expected_server_seq_num = s_ack_seq + 1
            client_seq_num +=1 # Increment client sequence number after SYN

            # Send final ACK for handshake
            ack_packet = create_packet(client_seq_num, expected_server_seq_num, ACK_FLAG, 0)
            sock.sendto(ack_packet, server_address)
            print(f"Client: Sent ACK for SYN-ACK. Connection established. (My Seq: {client_seq_num}, My Ack for Server: {expected_server_seq_num})")
        else:
            print("Client: Handshake failed. Invalid SYN-ACK received.")
            if s_ack_flags and s_ack_flags & RST_FLAG:
                print("Client: Received RST from server during handshake.")
            else: # Send RST if handshake failed due to other reasons
                 rst_packet = create_packet(client_seq_num, s_ack_seq + 1 if s_ack_seq is not None else 0, RST_FLAG, 0)
                 sock.sendto(rst_packet, server_address)
            return

        # Data Transfer (Go-Back-N)
        start_time = time.time()
        sock.settimeout(GBN_TIMEOUT) # Set GBN timeout for data transfer

        with open(filename, 'rb') as f:
            base = client_seq_num # Start of the window, first packet to send
            next_seq_num = client_seq_num # Next sequence number to use for a new packet
            window = {} # Stores (packet_data_bytes, sent_time) for packets in flight, keyed by seq_num
            
            eof_reached = False
            total_bytes_sent = 0

            while True:
                # Send new packets if window has space and there's data
                while len(window) < window_size and not eof_reached:
                    data_chunk = f.read(MAX_DATA_SIZE)
                    if not data_chunk:
                        eof_reached = True
                        break 
                    
                    packet_to_send = create_packet(next_seq_num, expected_server_seq_num, 0, 0, data_chunk) # Flags 0 for data
                    sock.sendto(packet_to_send, server_address)
                    window[next_seq_num] = (packet_to_send, time.time()) # Store packet and send time
                    # print(f"Client: Sent packet (Seq: {next_seq_num}), WinSize: {len(window)}")
                    next_seq_num += 1
                
                if eof_reached and not window: # All data sent and all ACKs received
                    break

                # Try to receive ACK
                try:
                    ack_raw, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
                    ack_s_seq, ack_s_ack_num, ack_s_flags, _, _ = parse_packet(ack_raw)

                    if ack_s_flags is None: # Malformed
                        continue

                    if ack_s_flags & RST_FLAG:
                        print("Client: Received RST from server. Aborting.")
                        return # Or raise error

                    if ack_s_flags & ACK_FLAG:
                        # print(f"Client: Received ACK (Server Acking my Seq up to: {ack_s_ack_num -1})")
                        # GBN uses cumulative ACKs, so an ACK for N means all packets up to N-1 are received.
                        # Our server sends ACK for d_seq + 1, meaning it received d_seq.
                        # So, if server sends ack_s_ack_num, it means it has received our packet with seq_num = ack_s_ack_num - 1
                        acked_seq = ack_s_ack_num -1
                        
                        if acked_seq >= base:
                            # print(f"Client: ACK confirms receipt up to {acked_seq}.")
                            new_base = acked_seq + 1
                            # Remove acknowledged packets from window
                            for seq_to_remove in range(base, new_base):
                                if seq_to_remove in window:
                                    total_bytes_sent += len(window[seq_to_remove][0]) - HEADER_SIZE
                                    del window[seq_to_remove]
                            base = new_base
                            # print(f"Client: Window advanced. Base: {base}, Win: {list(window.keys())}")
                        # else:
                            # print(f"Client: Received duplicate/old ACK for {acked_seq}, Base is {base}")


                except socket.timeout:
                    print(f"Client: Timeout! Resending window starting from base {base}.")
                    for seq_num_to_resend in sorted(window.keys()): # Resend all in current window
                        if seq_num_to_resend >= base: # GBN resends all unacked in window
                            packet_bytes, _ = window[seq_num_to_resend]
                            sock.sendto(packet_bytes, server_address)
                            window[seq_num_to_resend] = (packet_bytes, time.time()) # Update sent time
                            # print(f"Client: Resent packet (Seq: {seq_num_to_resend})")
                    if not window and eof_reached: # If window became empty after potential ACKs before timeout logic
                        break
                
                # Check for timed-out packets individually (more precise than single timer for whole window)
                # This is an alternative to the single GBN timer approach.
                # For strict GBN, one timer for the oldest unacked packet (base) is common.
                # The current implementation uses socket timeout for any ACK, then resends whole window.
                # This is a simpler GBN retransmission strategy.

            client_seq_num = next_seq_num # Update client_seq_num to the next available

        # Connection Teardown
        print(f"Client: File transfer supposedly complete. Sending FIN (Seq: {client_seq_num})")
        fin_packet = create_packet(client_seq_num, expected_server_seq_num, FIN_FLAG, 0)
        sock.sendto(fin_packet, server_address)
        sock.settimeout(GBN_TIMEOUT * 3) # Timeout for FIN-ACK

        try:
            fin_ack_raw, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
            f_ack_s_seq, f_ack_s_ack_num, f_ack_s_flags, _, _ = parse_packet(fin_ack_raw)
            if f_ack_s_flags and f_ack_s_flags & ACK_FLAG and f_ack_s_flags & FIN_FLAG and f_ack_s_ack_num == client_seq_num + 1:
                print(f"Client: Received FIN-ACK from server (Server Ack: {f_ack_s_ack_num}). Closing connection.")
                # Client could send a final ACK for server's FIN, but assignment shows 2-way teardown initiated by client
            elif f_ack_s_flags and f_ack_s_flags & RST_FLAG:
                 print("Client: Received RST from server during teardown.")
            else:
                print("Client: Did not receive valid FIN-ACK. Flags:", f_ack_s_flags, "Ack Num:", f_ack_s_ack_num, "Expected Ack:", client_seq_num + 1)
        except socket.timeout:
            print("Client: Timeout waiting for FIN-ACK. Closing connection anyway.")

        end_time = time.time()
        file_size_bytes = os.path.getsize(filename)
        time_taken = end_time - start_time
        if time_taken > 0:
            throughput_bps = (file_size_bytes * 8) / time_taken
            print(f"Client: File '{filename}' ({file_size_bytes} bytes) sent.")
            print(f"Client: Time taken: {time_taken:.2f} seconds.")
            print(f"Client: Throughput: {throughput_bps / 1_000_000:.2f} Mbit/s.")
        else:
            print(f"Client: File '{filename}' ({file_size_bytes} bytes) sent too quickly to measure throughput.")


    except FileNotFoundError:
        print(f"Client Error: File '{filename}' not found.")
    except ConnectionRefusedError:
        print(f"Client Error: Connection refused by server {server_ip}:{server_port}.")
    except Exception as e:
        print(f"Client error: {e}")
        # Send RST if an unexpected error occurs mid-connection
        try:
            rst_packet = create_packet(client_seq_num, expected_server_seq_num, RST_FLAG, 0)
            sock.sendto(rst_packet, server_address)
            print("Client: Sent RST due to an error.")
        except Exception as rst_e:
            print(f"Client: Failed to send RST: {rst_e}")
    finally:
        sock.close()
        print("Client: Socket closed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DRTP File Transfer Application (Client/Server)")
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-s", "--server", action="store_true", help="Run in server mode")
    mode_group.add_argument("-c", "--client", action="store_true", help="Run in client mode")

    # Common arguments
    parser.add_argument("-i", "--ip", type=str, required=True, help="IP address to bind (server) or connect to (client)")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port number to use")

    # Client-specific arguments
    parser.add_argument("-f", "--file", type=str, help="Filename to send (client mode only)")
    parser.add_argument("-w", "--window", type=int, default=1, help="Window size for Go-Back-N (client mode only, max 15)")

    # Server-specific arguments
    parser.add_argument("-d", "--discard", action="store_true", help="Enable packet discard mode for testing (server mode only)")

    args = parser.parse_args()

    # Validate window size for client
    effective_window_size = 1
    if args.client:
        if not args.file:
            parser.error("-f/--file is required for client mode")
        if args.window < 1:
            print("Warning: Window size cannot be less than 1. Using 1.")
            effective_window_size = 1
        elif args.window > 15: # As per original script's effective_window_size logic
            print("Warning: Window size capped at 15. Using 15.")
            effective_window_size = 15
        else:
            effective_window_size = args.window
        print(f"Client mode: Effective window size = {effective_window_size}")


    if args.server:
        print(f"Starting server on {args.ip}:{args.port}")
        if args.discard:
            print("Packet discard mode enabled for server.")
        run_server(args.ip, args.port, args.discard)
    elif args.client:
        print(f"Starting client to send '{args.file}' to {args.ip}:{args.port} with window size {effective_window_size}")
        run_client(args.ip, args.port, args.file, effective_window_size)
