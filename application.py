#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 26 12:58:57 2025

@author: sheikhomeister
"""

# Step 1: Setup and imports 
import socket   # for network communication
import sys      # for command-line arguments
import struct   # for packing/unpacking data
import time     # for measuring throughput
import os       # for getting file size


# Step 2: Parse command-line args
if __name__ == "__main__":
    args = sys.argv

    if len(args) < 5:
        print("Usage:")
        print("Server: python3 application.py -s -i <IP> -p <PORT>")
        print("Client: python3 application.py -c -i <IP> -p <PORT> -f <FILENAME>")
        sys.exit(1)

    mode = args[1]
    ip_address = args[3]
    port = int(args[5])

    if mode == "-c":
        if len(args) < 8:
            print("Client mode requires filename (-f <FILENAME>)")
            sys.exit(1)
        filename = args[7]
        print(f"Client mode: Sending {filename} to {ip_address}:{port}")
    elif mode == "-s":
        print(f"Server mode: Listening on {ip_address}:{port}")
    else:
        print("Unknown mode. Use -s for server or -c for client.")
        sys.exit(1)


# Step 3: Create and bind socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

if mode == "-s":
    sock.bind((ip_address, port))
    print(f"Server is ready and listening at {ip_address}:{port}")

# Step 4: Build packet format
SYN = 0x1
ACK = 0x2
FIN = 0x4

def create_packet(seq_num, flags, data):
    data_length = len(data)
    header = struct.pack('!IHH', seq_num, flags, data_length)
    return header + data

def parse_packet(packet):
    header = packet[:8]
    seq_num, flags, data_length = struct.unpack('!IHH', header)
    data = packet[8:8+data_length]
    return seq_num, flags, data

# Step 5-6: Main Logic
if mode == "-s":
    # ====== SERVER CODE ======

    # Wait for SYN
    print("Server: Waiting for SYN...")
    packet, client_address = sock.recvfrom(4096)
    seq_num, flags, data = parse_packet(packet)

    if flags & SYN:
        print("Server: Received SYN")

        # Send SYN-ACK
        response = create_packet(seq_num=0, flags=SYN | ACK, data=b'')
        sock.sendto(response, client_address)
        print("Server: Sent SYN-ACK")

        # Wait for ACK
        packet, client_address = sock.recvfrom(4096)
        seq_num, flags, data = parse_packet(packet)
        if flags & ACK:
            print("Server: Connection established with", client_address)

    # Now ready to receive file
    output_file = open('received_file.txt', 'wb')
    expected_seq = 0

    while True:
        packet, client_address = sock.recvfrom(4096)
        seq_num, flags, data = parse_packet(packet)

        if flags & FIN:
            print("Server: Received FIN, closing file...")
            output_file.close()
            # Send FIN-ACK
            fin_ack = create_packet(seq_num, FIN | ACK, b'')
            sock.sendto(fin_ack, client_address)
            print("Server: Sent FIN-ACK")
            break

        if seq_num == expected_seq:
            output_file.write(data)
            print(f"Server: Received packet {seq_num}, wrote data")
            # Send ACK
            ack_packet = create_packet(seq_num, ACK, b'')
            sock.sendto(ack_packet, client_address)
            expected_seq += 1
        else:
            print(f"Server: Unexpected packet {seq_num}, expected {expected_seq}")
            # Optional: re-ACK last good packet (not required now)

elif mode == "-c":
    # ====== CLIENT CODE ======

    # Start handshake
    print("Client: Sending SYN...")
    syn_packet = create_packet(seq_num=0, flags=SYN, data=b'')
    sock.sendto(syn_packet, (ip_address, port))

    # Wait for SYN-ACK
    packet, server_address = sock.recvfrom(4096)
    seq_num, flags, data = parse_packet(packet)
    if flags & SYN and flags & ACK:
        print("Client: Received SYN-ACK")

        # Send final ACK
        ack_packet = create_packet(seq_num=0, flags=ACK, data=b'')
        sock.sendto(ack_packet, server_address)
        print("Client: Connection established with", server_address)
    else:
        print("Client: Handshake failed.")
        sys.exit(1)

    # Start sending file
    start_time = time.time()

    with open(filename, 'rb') as f:
        seq_num = 0
        while True:
            data = f.read(1000)
            if not data:
                break

            packet = create_packet(seq_num, 0, data)
            sock.sendto(packet, (ip_address, port))
            print(f"Client: Sent packet {seq_num}")

            sock.settimeout(2)
            try:
                ack_packet, _ = sock.recvfrom(4096)
                ack_seq_num, ack_flags, ack_data = parse_packet(ack_packet)
                if ack_flags & ACK and ack_seq_num == seq_num:
                    print(f"Client: Received ACK for packet {seq_num}")
                    seq_num += 1
                else:
                    print("Client: Wrong ACK, resending packet...")
            except socket.timeout:
                print("Client: Timeout, resending packet...")

    # After file is sent, send FIN
    fin_packet = create_packet(seq_num, FIN, b'')
    sock.sendto(fin_packet, (ip_address, port))
    print("Client: Sent FIN")

    # (Optional) wait for FIN-ACK
    try:
        fin_ack_packet, _ = sock.recvfrom(4096)
        seq_num, flags, data = parse_packet(fin_ack_packet)
        if flags & FIN and flags & ACK:
            print("Client: Received FIN-ACK, closing connection.")
    except socket.timeout:
        print("Client: No FIN-ACK received, closing anyway.")

    end_time = time.time()

    # Calculate throughput
    file_size_bytes = os.path.getsize(filename)
    file_size_bits = file_size_bytes * 8
    time_taken = end_time - start_time
    throughput = file_size_bits / time_taken

    print(f"Client: File transfer complete.")
    print(f"Client: Throughput = {throughput:.2f} bits/second")
