import os
import random
import select
import socket
import struct
import time

# TCP Flag Constants (Byte 13 of TCP Header)
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10

DEFAULT_WIN = 65535
DEFAULT_MSS = 1460
DEFAULT_TTL = 64


def internet_checksum(data: bytes) -> int:
    """Compute standard 16-bit 1's-complement Internet checksum (T1, T2, T4)."""
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, ip_id: int, ttl: int = DEFAULT_TTL) -> bytes:
    """Build complete 20-byte IPv4 header with checksum (T1)."""
    ver_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + payload_len
    ip_id = ip_id & 0xFFFF
    if ip_id == 0:
        ip_id = 1  # T1: Identification field must be non-zero
    frag_off = 0
    proto = socket.IPPROTO_TCP
    check = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    header_without_csum = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ip_id, frag_off, ttl, proto, check, src_addr, dst_addr
    )
    csum = internet_checksum(header_without_csum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ip_id, frag_off, ttl, proto, csum, src_addr, dst_addr
    )


def build_tcp_segment(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    win: int = DEFAULT_WIN,
    payload: bytes = b"",
    mss: int = None,
) -> bytes:
    """Build complete TCP header (+ MSS option on SYN/SYN-ACK) and payload with checksum (T2, T3)."""
    options = b""
    if mss is not None:
        # T3: SYN and SYN-ACK carry exactly one option, MSS=1460 (Kind=2, Len=4, Value=1460)
        options = struct.pack("!BBH", 2, 4, mss)

    doff = (20 + len(options)) // 4
    data_offset_res = (doff << 4)
    flags = flags & 0xFF
    urg_ptr = 0

    tcp_header_no_csum = struct.pack(
        "!HHLLBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, data_offset_res, flags, win & 0xFFFF, 0, urg_ptr
    )

    # Pseudo-header for TCP checksum calculation
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    tcp_len = len(tcp_header_no_csum) + len(options) + len(payload)
    pseudo_hdr = struct.pack("!4s4sBBH", src_addr, dst_addr, 0, socket.IPPROTO_TCP, tcp_len)

    csum = internet_checksum(pseudo_hdr + tcp_header_no_csum + options + payload)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, data_offset_res, flags, win & 0xFFFF, csum, urg_ptr
    )
    return tcp_header + options + payload


def parse_packet(raw_bytes: bytes):
    """
    Parse and verify IPv4 + TCP headers and checksums (T4).
    Returns dict of parsed fields, or None if invalid/corrupted.
    """
    if len(raw_bytes) < 40:
        return None

    ver_ihl = raw_bytes[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(raw_bytes) < ihl:
        return None

    # Verify IPv4 header checksum (T4)
    if internet_checksum(raw_bytes[:ihl]) != 0:
        return None

    _, _, total_len, ip_id, _, ttl, proto, _, src_addr, dst_addr = struct.unpack(
        "!BBHHHBBH4s4s", raw_bytes[:20]
    )
    if proto != socket.IPPROTO_TCP:
        return None
    if total_len < ihl + 20 or len(raw_bytes) < total_len:
        return None

    src_ip = socket.inet_ntoa(src_addr)
    dst_ip = socket.inet_ntoa(dst_addr)

    tcp_segment = raw_bytes[ihl:total_len]
    if len(tcp_segment) < 20:
        return None

    sport, dport, seq, ack, doff_res, flags, win, _, _ = struct.unpack("!HHLLBBHHH", tcp_segment[:20])
    doff = (doff_res >> 4) * 4
    if doff < 20 or len(tcp_segment) < doff:
        return None

    # Verify TCP checksum using pseudo-header (T4)
    ##############################################
    pseudo_hdr = struct.pack("!4s4sBBH", src_addr, dst_addr, 0, socket.IPPROTO_TCP, len(tcp_segment))
    # Only drop the packet for invalid checksums if we are NOT on localhost
    if src_ip != "127.0.0.1" and internet_checksum(pseudo_hdr + tcp_segment) != 0:
            return None

    # Parse TCP options (T4: extract peer's MSS if present, ignore others)
    mss = None
    opt_bytes = tcp_segment[20:doff]
    idx = 0
    while idx < len(opt_bytes):
        kind = opt_bytes[idx]
        if kind == 0:  # End of option list
            break
        if kind == 1:  # NOP
            idx += 1
            continue
        if idx + 1 >= len(opt_bytes):
            break
        opt_len = opt_bytes[idx + 1]
        if opt_len < 2 or idx + opt_len > len(opt_bytes):
            break
        if kind == 2 and opt_len == 4:
            mss = struct.unpack("!H", opt_bytes[idx + 2 : idx + 4])[0]
        idx += opt_len

    payload = tcp_segment[doff:]
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "ttl": ttl,
        "id": ip_id,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "win": win,
        "len": len(payload),
        "mss": mss,
        "payload": payload,
    }


class PacketLogger:
    """Exact Section 2.6 packet logger (--log FILE) with immediate flush."""

    def __init__(self, log_path: str = None):
        self.fp = open(log_path, "w", encoding="utf-8") if log_path else None

    def log(self, direction: str, pkt_info: dict):
        if not self.fp:
            return
        mss_str = str(pkt_info["mss"]) if pkt_info.get("mss") is not None else "-"
        line = (
            f"{direction} {pkt_info['src_ip']}:{pkt_info['sport']} > "
            f"{pkt_info['dst_ip']}:{pkt_info['dport']} "
            f"ttl={pkt_info['ttl']} id={pkt_info['id']} "
            f"seq={pkt_info['seq']} ack={pkt_info['ack']} "
            f"flags=0x{pkt_info['flags']:02x} win={pkt_info['win']} "
            f"len={pkt_info['len']} mss={mss_str}\n"
        )
        self.fp.write(line)
        self.fp.flush()

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None



class RawTCPConnection:
    def __init__(self, src_ip: str, src_port: int):
        self.src_ip = src_ip
        self.src_port = src_port
        
        # Open a raw socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        # Tell the OS we are building our own IP headers
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # TCP State variables
        self.seq = random.randint(1000, 50000)
        self.ack = 0
        self.dst_ip = None
        self.dst_port = None
        self.logger = PacketLogger("client_tcp.log")

    def connect(self, dst_ip: str, dst_port: int):
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 24, ip_id=101)
        tcp_seg = build_tcp_segment(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.seq, self.ack, FLAG_SYN, mss=DEFAULT_MSS
        )

        # Retransmission Loop: Send SYN and wait 1.0s for SYN-ACK
        while True:
            self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
            self.logger.log("SND", parse_packet(ip_hdr + tcp_seg))

            ready, _, _ = select.select([self.sock], [], [], 1.0)
            if not ready:
                print("Timeout waiting for SYN-ACK, retransmitting SYN...")
                continue

            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                continue

            if parsed['flags'] == (FLAG_SYN | FLAG_ACK) and parsed['ack'] == self.seq + 1:
                self.logger.log("RCV", parsed)
                self.seq += 1
                self.ack = parsed['seq'] + 1
                break

        # Send final ACK
        ip_hdr_ack = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=102)
        tcp_seg_ack = build_tcp_segment(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.seq, self.ack, FLAG_ACK
        )
        self.sock.sendto(ip_hdr_ack + tcp_seg_ack, (self.dst_ip, 0))
        self.logger.log("SND", parse_packet(ip_hdr_ack + tcp_seg_ack))
        
        print(f"Connection established with {self.dst_ip}:{self.dst_port}!")
        return True

    def send_all(self, data: bytes):
        offset = 0
        while offset < len(data):
            # Slice data into MSS-sized chunks
            chunk = data[offset:offset + DEFAULT_MSS]
            ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20 + len(chunk), ip_id=103)
            tcp_seg = build_tcp_segment(
                self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                self.seq, self.ack, FLAG_ACK | FLAG_PSH, payload=chunk
            )
            
            packet = ip_hdr + tcp_seg
            
            # Retransmission Loop: Send data chunk and wait 1.0s for ACK
            while True:
                self.sock.sendto(packet, (self.dst_ip, 0))
                self.logger.log("SND", parse_packet(packet))
                
                ready, _, _ = select.select([self.sock], [], [], 1.0)
                if not ready:
                    print(f"Timeout waiting for ACK for seq {self.seq}, retransmitting data...")
                    continue
                
                raw_bytes, _ = self.sock.recvfrom(65535)
                parsed = parse_packet(raw_bytes)
                
                if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                    continue
                
                # Check for valid ACK
                if parsed['flags'] & FLAG_ACK:
                    self.logger.log("RCV", parsed)
                    # Cumulative ACK check: if the peer acknowledges data beyond our current sequence
                    if parsed['ack'] > self.seq:
                        bytes_acked = parsed['ack'] - self.seq
                        self.seq += bytes_acked
                        offset += bytes_acked
                        break

    def recv_all(self) -> bytes:
        received_data = b""
        
        # Loop until the connection is closed or data stops arriving
        while True:
            ready, _, _ = select.select([self.sock], [], [], 2.0)
            if not ready:
                break # Timeout assuming the server has finished sending data
                
            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                continue
                
            self.logger.log("RCV", parsed)
            
            # Process in-order payload
            if parsed['len'] > 0:
                if parsed['seq'] == self.ack:
                    received_data += parsed['payload']
                    self.ack += parsed['len']
                    
                # Acknowledge the received data
                ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=104)
                tcp_seg = build_tcp_segment(
                    self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                    self.seq, self.ack, FLAG_ACK
                )
                self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
                self.logger.log("SND", parse_packet(ip_hdr + tcp_seg))
                
            # Handle Server FIN (Teardown)
            if parsed['flags'] & FLAG_FIN:
                self.ack += 1
                ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=105)
                tcp_seg = build_tcp_segment(
                    self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                    self.seq, self.ack, FLAG_ACK
                )
                self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
                self.logger.log("SND", parse_packet(ip_hdr + tcp_seg))
                break
                
        return received_data

    def close(self):
        ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=106)
        tcp_seg = build_tcp_segment(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.seq, self.ack, FLAG_FIN | FLAG_ACK
        )
        
        while True:
            self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
            self.logger.log("SND", parse_packet(ip_hdr + tcp_seg))
            
            ready, _, _ = select.select([self.sock], [], [], 1.0)
            if not ready:
                continue # Retransmit FIN
                
            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            if not parsed or parsed['src_ip'] != self.dst_ip: 
                continue
            
            if parsed['flags'] & FLAG_ACK:
                self.logger.log("RCV", parsed)
                break
        
        self.sock.close()

class RawTCPListener:
    """Server-side TCP listener to accept incoming raw connections."""
    def __init__(self, src_ip: str, src_port: int):
        self.src_ip = src_ip
        self.src_port = src_port
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.logger = PacketLogger("server_tcp.log")

    def accept(self):
        print(f"Listening for incoming connections on {self.src_ip}:{self.src_port}...")
        while True:
            # Step 1: Wait for SYN
            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            if not parsed or parsed['dst_ip'] != self.src_ip or parsed['dport'] != self.src_port:
                continue
                
            if parsed['flags'] == FLAG_SYN:
                self.logger.log("RCV", parsed)
                client_ip = parsed['src_ip']
                client_port = parsed['sport']
                
                # Generate server's Initial Sequence Number
                server_seq = random.randint(1000, 50000)
                server_ack = parsed['seq'] + 1
                
                # Step 2: Send SYN-ACK
                ip_hdr = build_ipv4_header(self.src_ip, client_ip, 24, ip_id=201)
                tcp_seg = build_tcp_segment(
                    self.src_ip, client_ip, self.src_port, client_port,
                    server_seq, server_ack, FLAG_SYN | FLAG_ACK, mss=DEFAULT_MSS
                )
                
                # Retransmission loop for SYN-ACK
                while True:
                    self.sock.sendto(ip_hdr + tcp_seg, (client_ip, 0))
                    self.logger.log("SND", parse_packet(ip_hdr + tcp_seg))
                    
                    ready, _, _ = select.select([self.sock], [], [], 1.0)
                    if not ready:
                        print("Timeout waiting for client ACK, retransmitting SYN-ACK...")
                        continue
                        
                    ack_bytes, _ = self.sock.recvfrom(65535)
                    ack_parsed = parse_packet(ack_bytes)
                    
                    if not ack_parsed or ack_parsed['src_ip'] != client_ip or ack_parsed['sport'] != client_port:
                        continue
                        
                    # Step 3: Receive final ACK
                    if ack_parsed['flags'] == FLAG_ACK and ack_parsed['ack'] == server_seq + 1:
                        self.logger.log("RCV", ack_parsed)
                        print(f"Connection accepted from {client_ip}:{client_port}!")
                        
                        # Create an established connection object to return
                        conn = RawTCPConnection(self.src_ip, self.src_port)
                        # Override the default connection properties with the established state
                        conn.dst_ip = client_ip
                        conn.dst_port = client_port
                        conn.seq = server_seq + 1
                        conn.ack = ack_parsed['seq']
                        
                        return conn

                    
if __name__ == "__main__":
    import random
    
    random_src_port = random.randint(10000, 60000)
    conn = RawTCPConnection("127.0.0.1", random_src_port)
    
    if conn.connect("127.0.0.1", 8080):
        # Send an HTTP GET request
        http_request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        conn.send_all(http_request)
        
        # Receive the HTML response
        response = conn.recv_all()
        print("\n--- Server Response ---")
        print(response.decode('utf-8', errors='ignore'))
        
        conn.close()