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
# Sequence Number (2 bytes), Acknowledgment Number (2 bytes), Flags (2 bytes), Receiver Window (2 bytes)
# Total header size = 8 bytes
HEADER_FORMAT = '!HHHH' # H for unsigned short (2 bytes)
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
        seq_num (int): Sequence number (0-65535).
        ack_num (int): Acknowledgment number (0-65535).
        flags (int): Combination of DRTP flags (SYN, ACK, FIN, RST).
        receiver_window (int): Receiver window size.
        data (bytes): Payload data.
    Returns:
        bytes: The packed DRTP packet.
    """
    # Ensure seq_num and ack_num are within 0-65535 for H format
    if not (0 <= seq_num <= 65535 and 0 <= ack_num <= 65535):
        raise ValueError("Sequence or Acknowledgment number out of 0-65535 range for 2-byte field.")
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

        if flags is not None and flags & SYN_FLAG: # Check flags is not None
            print(f"Server: Received SYN from {client_address} (Seq: {seq_num})")
            # Server's initial sequence number can be random or fixed.
            server_seq_num = random.randint(0, 65535) # Stays within H range
            # Acknowledge client's sequence number
            # Ensure seq_num + 1 doesn't overflow 65535 or handle wraparound if necessary
            # For simplicity, we assume it won't immediately overflow here in handshake.
            # A more robust implementation might use modular arithmetic for sequence numbers.
            syn_ack_packet = create_packet(server_seq_num, (seq_num + 1) % 65536, SYN_FLAG | ACK_FLAG, 0) # Receiver window can be set
            sock.sendto(syn_ack_packet, client_address)
            print(f"Server: Sent SYN-ACK (Seq: {server_seq_num}, Ack: {(seq_num + 1) % 65536})")

            # Wait for ACK from client to complete handshake
            ack_packet_raw, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
            final_ack_seq, final_ack_ack_num, final_ack_flags, _, _ = parse_packet(ack_packet_raw)
            
            if final_ack_flags is not None and final_ack_flags & ACK_FLAG and final_ack_ack_num == (server_seq_num + 1) % 65536:
                print(f"Server: Received ACK. Connection established with {client_address} (Client Acked Seq: {final_ack_ack_num})")
                expected_data_seq_num = (seq_num + 1) % 65536 # Client's data will start after its SYN
            else:
                print("Server: Handshake failed. Did not receive correct final ACK.")
                rst_packet = create_packet(server_seq_num, (final_ack_seq + 1 if final_ack_seq is not None else 0) % 65536, RST_FLAG, 0)
                sock.sendto(rst_packet, client_address)
                return
        else:
            print("Server: Did not receive SYN or packet was malformed. Packet ignored.")
            # Optionally send RST
            rst_packet = create_packet(0, (seq_num + 1 if seq_num is not None else 0) % 65536, RST_FLAG, 0) # Seq 0, Ack their seq if available
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
                        fin_ack_packet = create_packet(server_seq_num, (d_seq + 1) % 65536, FIN_FLAG | ACK_FLAG, 0)
                        sock.sendto(fin_ack_packet, client_address)
                        print(f"Server: Sent FIN-ACK (Ack: {(d_seq + 1) % 65536})")
                        break
                    
                    # If it's a data packet (no SYN, FIN, RST flags, or just ACK if it's a keep-alive)
                    if not (d_flags & (SYN_FLAG | FIN_FLAG | RST_FLAG)):
                        if d_seq == expected_data_seq_num:
                            output_file.write(d_data)
                            print(f"Server: Received packet (Seq: {d_seq}), wrote {len(d_data)} bytes.")
                            
                            # Send ACK for the received data packet
                            ack_response_packet = create_packet(server_seq_num, (d_seq + 1) % 65536, ACK_FLAG, 0) # Ack next expected byte from client
                            
                            if discard_mode and not dropped_ack_for_testing and random.random() < 0.3: # Drop ~30% of ACKs in discard mode
                                print(f"Server (Discard Mode): Dropping ACK for packet (Seq: {d_seq})")
                                dropped_ack_for_testing = True # Drop only one for simple test
                            else:
                                sock.sendto(ack_response_packet, client_address)
                                # print(f"Server: Sent ACK for data packet (Seq: {d_seq}, Ack: {(d_seq + 1) % 65536})")
                            
                            expected_data_seq_num = (expected_data_seq_num + 1) % 65536 # Increment for next expected
                        elif d_seq < expected_data_seq_num: # Handle sequence number wraparound if comparing
                            # This simple comparison might be tricky with wraparound if not handled carefully.
                            # For now, assume standard GBN duplicate detection.
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
    client_seq_num = random.randint(0, 65535) # Stays within H range
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
            return

        s_ack_seq, s_ack_ack_num, s_ack_flags, s_ack_recv_win, _ = parse_packet(syn_ack_raw)

        if s_ack_flags is not None and (s_ack_flags & SYN_FLAG) and (s_ack_flags & ACK_FLAG) and s_ack_ack_num == (client_seq_num + 1) % 65536:
            print(f"Client: Received SYN-ACK (Server Seq: {s_ack_seq}, Server Ack: {s_ack_ack_num})")
            expected_server_seq_num = (s_ack_seq + 1) % 65536
            client_seq_num = (client_seq_num + 1) % 65536 # Increment client sequence number after SYN

            # Send final ACK for handshake
            ack_packet = create_packet(client_seq_num, expected_server_seq_num, ACK_FLAG, 0)
            sock.sendto(ack_packet, server_address)
            print(f"Client: Sent ACK for SYN-ACK. Connection established. (My Seq: {client_seq_num}, My Ack for Server: {expected_server_seq_num})")
        else:
            print("Client: Handshake failed. Invalid SYN-ACK received.")
            if s_ack_flags is not None and s_ack_flags & RST_FLAG:
                print("Client: Received RST from server during handshake.")
            else: # Send RST if handshake failed due to other reasons
                rst_packet = create_packet(client_seq_num, (s_ack_seq + 1 if s_ack_seq is not None else 0) % 65536, RST_FLAG, 0)
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
            total_bytes_sent_payload = 0 # Renamed to avoid confusion with packet size

            while True:
                # Send new packets if window has space and there's data
                while len(window) < window_size and not eof_reached:
                    data_chunk = f.read(MAX_DATA_SIZE)
                    if not data_chunk:
                        eof_reached = True
                        break 
                    
                    packet_to_send = create_packet(next_seq_num, expected_server_seq_num, 0, 0, data_chunk) # Flags 0 for data
                    sock.sendto(packet_to_send, server_address)
                    window[next_seq_num] = (packet_to_send, time.time(), len(data_chunk)) # Store packet, send time, and payload length
                    # print(f"Client: Sent packet (Seq: {next_seq_num}), WinSize: {len(window)}")
                    next_seq_num = (next_seq_num + 1) % 65536
                
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
                        acked_seq = (ack_s_ack_num - 1 + 65536) % 65536 # Handle potential underflow with modulo

                        # GBN: ACK for 'acked_seq' means all packets up to 'acked_seq' (inclusive) are acknowledged.
                        # The 'base' is the oldest unacknowledged packet.
                        # If acked_seq is greater than or equal to base (considering wraparound)
                        
                        # This condition needs to correctly handle sequence number wraparound.
                        # A common way is to check if acked_seq is "between" base and next_seq_num
                        # in a circular sense.
                        # If base <= acked_seq < next_seq_num (no wraparound for this segment)
                        # OR if next_seq_num < base AND (acked_seq >= base OR acked_seq < next_seq_num) (wraparound for this segment)
                        
                        # Simplified check for GBN: advance base to acked_seq + 1
                        # All sequence numbers from current base up to acked_seq are now acknowledged.
                        current_seq = base
                        while True:
                            is_acked = False
                            # Check if current_seq is "less than or equal to" acked_seq in circular space
                            if base <= next_seq_num: # No wrap of the window itself
                                if current_seq <= acked_seq and current_seq >= base :
                                    is_acked = True
                            else: # Window has wrapped
                                if current_seq >= base or current_seq <= acked_seq:
                                     is_acked = True
                            
                            if is_acked and current_seq in window:
                                total_bytes_sent_payload += window[current_seq][2] # Add payload length
                                del window[current_seq]
                                # print(f"Client: ACKed packet Seq: {current_seq}. Advancing base.")
                                if current_seq == acked_seq: # Stop if we processed up to the acked_seq
                                    base = (acked_seq + 1) % 65536
                                    break
                            elif current_seq == base and current_seq not in window and base != (acked_seq + 1) % 65536 : # Base has moved past this
                                # This means base was already advanced past current_seq
                                # this can happen if ack for base was received, and now a later ack comes in.
                                pass # Do nothing, base is already ahead or will be updated
                            elif current_seq != acked_seq : # continue to next only if not yet acked_seq
                                pass
                            else: # current_seq is not acked or not in window and is not base
                                # Or, if acked_seq itself is older than base, it's a duplicate/old ACK
                                if base <= next_seq_num: # no wrap
                                    if acked_seq < base:
                                        # print(f"Client: Received old/duplicate ACK for {acked_seq}, Base is {base}")
                                        pass
                                else: # wrap
                                    if acked_seq < base and acked_seq >= next_seq_num : # acked_seq is in the "dead zone"
                                        # print(f"Client: Received old/duplicate ACK for {acked_seq}, Base is {base}")
                                        pass
                                break # Break from while loop if condition not met for advancing base further

                            if not window or current_seq == (next_seq_num -1 + 65536) % 65536 : # Stop if window empty or iterated all possible sent packets
                                break
                            current_seq = (current_seq + 1) % 65536
                            if current_seq == base and acked_seq != (base -1 + 65536)%65536 : # Full circle check if base hasn't moved much
                                break # Avoid infinite loop if base is not advancing for some reason

                        # print(f"Client: Window advanced. Base: {base}, Win: {sorted(list(window.keys()))}")


                except socket.timeout:
                    print(f"Client: Timeout! Resending window starting from base {base}.")
                    # Resend all packets currently in the window (from base to next_seq_num-1, effectively)
                    sorted_window_keys = sorted(list(window.keys())) # Get a stable order for resending
                    
                    # Adjust for wraparound when sorting/iterating if base > some keys due to wraparound
                    # This simple sort might not be ideal if sequence numbers have wrapped around 65535.
                    # A more robust way is to iterate from base up to (next_seq_num - 1 + 65536) % 65536,
                    # checking if each seq is in the window.
                    
                    current_resend_seq = base
                    while current_resend_seq != next_seq_num:
                        if current_resend_seq in window:
                            packet_bytes, _, _ = window[current_resend_seq]
                            sock.sendto(packet_bytes, server_address)
                            window[current_resend_seq] = (packet_bytes, time.time(), window[current_resend_seq][2]) # Update sent time
                            # print(f"Client: Resent packet (Seq: {current_resend_seq})")
                        current_resend_seq = (current_resend_seq + 1) % 65536
                        if not window : break # Safety break if window becomes empty during this loop

                    if not window and eof_reached: # If window became empty after potential ACKs before timeout logic
                        break
                
            client_seq_num = next_seq_num # Update client_seq_num to the next available for FIN

        # Connection Teardown
        print(f"Client: File transfer supposedly complete. Sending FIN (Seq: {client_seq_num})")
        fin_packet = create_packet(client_seq_num, expected_server_seq_num, FIN_FLAG, 0) # ack for server's current seq
        sock.sendto(fin_packet, server_address)
        sock.settimeout(GBN_TIMEOUT * 3) # Timeout for FIN-ACK

        try:
            fin_ack_raw, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
            f_ack_s_seq, f_ack_s_ack_num, f_ack_s_flags, _, _ = parse_packet(fin_ack_raw)
            if f_ack_s_flags is not None and f_ack_s_flags & ACK_FLAG and f_ack_s_flags & FIN_FLAG and f_ack_s_ack_num == (client_seq_num + 1) % 65536:
                print(f"Client: Received FIN-ACK from server (Server Ack: {f_ack_s_ack_num}). Closing connection.")
            elif f_ack_s_flags is not None and f_ack_s_flags & RST_FLAG:
                print("Client: Received RST from server during teardown.")
            else:
                expected_fin_ack = (client_seq_num + 1) % 65536
                print(f"Client: Did not receive valid FIN-ACK. Flags: {f_ack_s_flags}, Ack Num: {f_ack_s_ack_num}, Expected Ack: {expected_fin_ack}")
        except socket.timeout:
            print("Client: Timeout waiting for FIN-ACK. Closing connection anyway.")

        end_time = time.time()
        file_size_bytes = os.path.getsize(filename) # This is the source file size
        time_taken = end_time - start_time
        # total_bytes_sent_payload already calculated based on ACKed data
        print(f"Client: File '{filename}' ({file_size_bytes} bytes source size).")
        print(f"Client: Total payload bytes ACKed: {total_bytes_sent_payload} bytes.")
        if time_taken > 0:
            # Throughput should be based on successfully ACKed payload data
            throughput_bps = (total_bytes_sent_payload * 8) / time_taken
            print(f"Client: Time taken: {time_taken:.2f} seconds.")
            print(f"Client: Throughput: {throughput_bps / 1_000_000:.2f} Mbit/s.")
        else:
            print(f"Client: File sent too quickly to measure meaningful throughput.")


    except FileNotFoundError:
        print(f"Client Error: File '{filename}' not found.")
    except ConnectionRefusedError:
        print(f"Client Error: Connection refused by server {server_ip}:{server_port}.")
    except ValueError as ve: # Catch the explicit ValueError from create_packet
        print(f"Client error: {ve}")
    except Exception as e:
        print(f"Client error: {e}")
        # Send RST if an unexpected error occurs mid-connection
        try:
            # Use the last known client_seq_num or a new one if appropriate
            # For simplicity, using current client_seq_num which should be the next one to send
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
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-s", "--server", action="store_true", help="Run in server mode")
    mode_group.add_argument("-c", "--client", action="store_true", help="Run in client mode")

    parser.add_argument("-i", "--ip", type=str, required=True, help="IP address to bind (server) or connect to (client)")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port number to use")

    parser.add_argument("-f", "--file", type=str, help="Filename to send (client mode only)")
    parser.add_argument("-w", "--window", type=int, default=1, help="Window size for Go-Back-N (client mode only, max 15)")

    parser.add_argument("-d", "--discard", action="store_true", help="Enable packet discard mode for testing (server mode only)")

    args = parser.parse_args()

    effective_window_size = 1
    if args.client:
        if not args.file:
            parser.error("-f/--file is required for client mode")
        if args.window < 1:
            print("Warning: Window size cannot be less than 1. Using 1.")
            effective_window_size = 1
        elif args.window > 15: 
            print("Warning: Window size capped at 15. Using 15.")
            effective_window_size = 15
        else:
            effective_window_size = args.window
        # print(f"Client mode: Effective window size = {effective_window_size}") # Moved to main block


    if args.server:
        print(f"Starting server on {args.ip}:{args.port}")
        if args.discard:
            print("Packet discard mode enabled for server.")
        run_server(args.ip, args.port, args.discard)
    elif args.client:
        print(f"Starting client to send '{args.file}' to {args.ip}:{args.port} with window size {effective_window_size}")
        run_client(args.ip, args.port, args.file, effective_window_size)
