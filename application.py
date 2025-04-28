#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 26 12:58:57 2025
@author: sheikhomeister
"""

import socket
import sys
import struct
import time
import os
import random

if __name__ == "__main__":
    args = sys.argv

    if len(args) < 5:
        print("Usage:")
        print("Server: python3 application.py -s -i <IP> -p <PORT> [-d]")
        print("Client: python3 application.py -c -i <IP> -p <PORT> -f <FILENAME> [-w <WINDOW_SIZE>]")
        sys.exit(1)

    mode = args[1]
    ip_address = args[3]
    port = int(args[5])

    discard_mode = False

    if mode == "-c":
        if len(args) < 8:
            print("Client mode requires filename (-f <FILENAME>)")
            sys.exit(1)
        filename = args[7]
        print(f"Client mode: Sending {filename} to {ip_address}:{port}")

        window_size = 1
        if "-w" in args:
            window_size_index = args.index("-w") + 1
            if window_size_index < len(args):
                window_size = int(args[window_size_index])
                print(f"Requested window size = {window_size}")
        else:
            print("Using default window size = 1")

        effective_window_size = min(window_size, 15)
        print(f"Effective window size = {effective_window_size}")

    elif mode == "-s":
        print(f"Server mode: Listening on {ip_address}:{port}")
        if "-d" in args:
            discard_mode = True
            print("Server: Discard mode enabled (dropping 1 packet)")
    else:
        print("Unknown mode. Use -s for server or -c for client.")
        sys.exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

if mode == "-s":
    sock.bind((ip_address, port))
    print(f"Server is ready and listening at {ip_address}:{port}")

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

if mode == "-s":
    print("Server: Waiting for SYN...")
    packet, client_address = sock.recvfrom(4096)
    seq_num, flags, data = parse_packet(packet)

    if flags & SYN:
        print("Server: Received SYN")
        response = create_packet(seq_num=0, flags=SYN | ACK, data=b'')
        sock.sendto(response, client_address)
        print("Server: Sent SYN-ACK")

        packet, client_address = sock.recvfrom(4096)
        seq_num, flags, data = parse_packet(packet)
        if flags & ACK:
            print("Server: Connection established with", client_address)

    output_file = open('received_file.txt', 'wb')
    expected_seq = 0
    dropped = False

    while True:
        packet, client_address = sock.recvfrom(4096)
        seq_num, flags, data = parse_packet(packet)

        if flags & FIN:
            print("Server: Received FIN, closing file...")
            output_file.close()
            fin_ack = create_packet(seq_num, FIN | ACK, b'')
            sock.sendto(fin_ack, client_address)
            print("Server: Sent FIN-ACK")
            break

        if seq_num == expected_seq:
            output_file.write(data)
            print(f"Server: Received packet {seq_num}, wrote data")
            ack_packet = create_packet(seq_num, ACK, b'')
            if discard_mode and not dropped and random.random() < 0.2:
                print(f"Server: Dropping ACK for packet {seq_num}")
                dropped = True
                continue
            sock.sendto(ack_packet, client_address)
            expected_seq += 1
        else:
            print(f"Server: Unexpected packet {seq_num}, expected {expected_seq}")

elif mode == "-c":
    print("Client: Sending SYN...")
    syn_packet = create_packet(seq_num=0, flags=SYN, data=b'')
    sock.sendto(syn_packet, (ip_address, port))

    packet, server_address = sock.recvfrom(4096)
    seq_num, flags, data = parse_packet(packet)
    if flags & SYN and flags & ACK:
        print("Client: Received SYN-ACK")
        ack_packet = create_packet(seq_num=0, flags=ACK, data=b'')
        sock.sendto(ack_packet, server_address)
        print("Client: Connection established with", server_address)
    else:
        print("Client: Handshake failed.")
        sys.exit(1)

    start_time = time.time()

    with open(filename, 'rb') as f:
        seq_num = 0
        window = []
        sent_in_window = []
        acked_in_window = []

        while True:
            while len(window) < effective_window_size:
                data = f.read(1000)
                if not data:
                    break
                packet = create_packet(seq_num, 0, data)
                sock.sendto(packet, (ip_address, port))
                print(f"Client: Sent packet {seq_num}")
                window.append((seq_num, packet))
                sent_in_window.append(seq_num)
                seq_num += 1

            if not window:
                break

            sock.settimeout(2)
            try:
                ack_packet, _ = sock.recvfrom(4096)
                ack_seq_num, ack_flags, ack_data = parse_packet(ack_packet)
                if ack_flags & ACK:
                    print(f"Client: Received ACK for packet {ack_seq_num}")
                    acked_in_window.append(ack_seq_num)
                    window = [pkt for pkt in window if pkt[0] != ack_seq_num]

                    if len(acked_in_window) == effective_window_size:
                        print("--- Window complete ---")
                        print(f"Sent packets: {sent_in_window}")
                        print(f"Received ACKs: {acked_in_window}")
                        sent_in_window = []
                        acked_in_window = []
            except socket.timeout:
                print("Client: Timeout, resending window...")
                for resend_seq_num, resend_packet in window:
                    sock.sendto(resend_packet, (ip_address, port))

    fin_packet = create_packet(seq_num, FIN, b'')
    sock.sendto(fin_packet, (ip_address, port))
    print("Client: Sent FIN")

    try:
        fin_ack_packet, _ = sock.recvfrom(4096)
        seq_num, flags, data = parse_packet(fin_ack_packet)
        if flags & FIN and flags & ACK:
            print("Client: Received FIN-ACK, closing connection.")
    except socket.timeout:
        print("Client: No FIN-ACK received, closing anyway.")

    end_time = time.time()

    file_size_bytes = os.path.getsize(filename)
    file_size_bits = file_size_bytes * 8
    time_taken = end_time - start_time
    throughput = file_size_bits / time_taken

    print("Client: File transfer complete.")
    print(f"Client: Throughput = {throughput / 1_000_000:.2f} Mbit/s")
