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
        #pass

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
            #pass

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
    def __init__(self, src_ip: str, dst_ip: str, dst_port: int, src_port: int = None, log_path: str = None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        # Pick ephemeral port in correct range if not provided
        self.src_port = src_port if src_port else random.randint(61000, 65535)
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        self.seq = random.randint(1000, 50000)
        self.ack = 0
        self.logger = PacketLogger(log_path)
        self.early_data = b""  # Buffer for piggybacked data during handshake
        self.peer_closed = False

    def connect(self):
        ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 24, ip_id=101)
        tcp_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_SYN, mss=DEFAULT_MSS)

        attempts = 0
        while attempts < 6:
            self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
            self.logger.log("SEND", parse_packet(ip_hdr + tcp_seg))

            start_time = time.time()
            syn_ack_received = False
            
            while time.time() - start_time < 1.0:
                time_left = 1.0 - (time.time() - start_time)
                if time_left <= 0: break
                
                ready, _, _ = select.select([self.sock], [], [], time_left)
                if not ready: break

                raw_bytes, _ = self.sock.recvfrom(65535)
                parsed = parse_packet(raw_bytes)
                if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                    continue

                if parsed['flags'] == (FLAG_SYN | FLAG_ACK) and parsed['ack'] == self.seq + 1:
                    self.logger.log("RECV", parsed)
                    self.seq += 1
                    self.ack = parsed['seq'] + 1
                    syn_ack_received = True
                    break
                    
            if syn_ack_received:
                break
                
            attempts += 1
        else:
            print("Handshake failed: Max retransmissions reached for SYN.")
            return False

        ip_hdr_ack = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=102)
        tcp_seg_ack = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK)
        self.sock.sendto(ip_hdr_ack + tcp_seg_ack, (self.dst_ip, 0))
        self.logger.log("SEND", parse_packet(ip_hdr_ack + tcp_seg_ack))
        print(f"Connection established with {self.dst_ip}:{self.dst_port}!")
        return True

    def send_all(self, data: bytes):
        seq_at_send_start = self.seq
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + DEFAULT_MSS]
            ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20 + len(chunk), ip_id=103)
            tcp_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK | FLAG_PSH, payload=chunk)
            packet = ip_hdr + tcp_seg
            
            attempts = 0
            while attempts < 10:
                self.sock.sendto(packet, (self.dst_ip, 0))
                self.logger.log("SEND", parse_packet(packet))
                
                start_time = time.time()
                ack_received = False
                
                while time.time() - start_time < 1.0:
                    time_left = 1.0 - (time.time() - start_time)
                    if time_left <= 0: break
                    
                    ready, _, _ = select.select([self.sock], [], [], time_left)
                    if not ready: break
                    
                    raw_bytes, _ = self.sock.recvfrom(65535)
                    parsed = parse_packet(raw_bytes)
                    if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                        continue
                    
                    # Drop connection immediately on RST
                    if parsed['flags'] & FLAG_RST:
                        self.peer_closed = True
                        raise ConnectionResetError("Connection reset by peer during send_all")
                    
                    if parsed['flags'] & FLAG_ACK and parsed['ack'] > self.seq:
                        self.logger.log("RECV", parsed)
                        
                        # Catch piggybacked data and ACK it immediately!
                        if parsed['len'] > 0 and parsed['seq'] == self.ack:
                            self.early_data += parsed['payload']
                            self.ack += parsed['len']
                            
                            ack_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=108)
                            ack_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK)
                            self.sock.sendto(ack_hdr + ack_seg, (self.dst_ip, 0))
                            self.logger.log("SEND", parse_packet(ack_hdr + ack_seg))
                            
                        self.seq += parsed['ack'] - self.seq
                        offset = self.seq - seq_at_send_start
                        ack_received = True
                        break
                            
                if ack_received:
                    break
                attempts += 1
            else:
                raise TimeoutError(f"send_all failed: 10s timeout waiting for ACK on seq {self.seq}")

            
    def recv_all(self, idle_timeout: float = 10.0) -> bytes:
        """Drains early data, waits for FIN or absolute timeout (fixes the 2s premature cutoff)"""
        received_data = b""
        if self.early_data:
            received_data += self.early_data
            self.early_data = b""
        
        last_data_time = time.time()
        
        while True:
            time_left = idle_timeout - (time.time() - last_data_time)
            if time_left <= 0:
                break
                
            ready, _, _ = select.select([self.sock], [], [], time_left)
            if not ready:
                break 
                
            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                continue
                
            self.logger.log("RECV", parsed)
            
            # Drop connection immediately on RST
            if parsed['flags'] & FLAG_RST:
                self.peer_closed = True
                break
            
            if parsed['len'] > 0 and parsed['seq'] == self.ack:
                received_data += parsed['payload']
                self.ack += parsed['len']
                last_data_time = time.time()
                    
                ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=104)
                tcp_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK)
                self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
                self.logger.log("SEND", parse_packet(ip_hdr + tcp_seg))
                
            if parsed['flags'] & FLAG_FIN:
                if parsed['seq'] + parsed['len'] == self.ack:
                    self.ack += 1
                    ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=105)
                    tcp_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK)
                    self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
                    self.logger.log("SEND", parse_packet(ip_hdr + tcp_seg))
                    self.peer_closed = True
                    break
                
        return received_data

    def close(self):
        ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=106)
        tcp_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_FIN | FLAG_ACK)
        
        # 1. Send FIN and wait for ACK (Give up after 2s / 4 attempts)
        attempts = 0
        fin_acked = False
        peer_fin_received = False
        
        while attempts < 4 and not fin_acked:
            self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
            self.logger.log("SEND", parse_packet(ip_hdr + tcp_seg))
            
            start_time = time.time()
            while time.time() - start_time < 0.5:
                time_left = 0.5 - (time.time() - start_time)
                if time_left <= 0: break
                
                ready, _, _ = select.select([self.sock], [], [], time_left)
                if not ready: break
                
                raw_bytes, _ = self.sock.recvfrom(65535)
                parsed = parse_packet(raw_bytes)
                if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                    continue
                    
                self.logger.log("RECV", parsed)
                
                # Check for piggybacked FIN
                if parsed['flags'] & FLAG_FIN:
                    peer_fin_received = True
                    if parsed['seq'] + parsed['len'] == self.ack:
                        self.ack += 1
                
                if parsed['flags'] & FLAG_ACK and parsed['ack'] == self.seq + 1:
                    fin_acked = True
                    break
            attempts += 1
            
        self.seq += 1
        
        # 2. Wait up to 2 seconds for peer's FIN ONLY if we haven't seen it yet
        if not peer_fin_received:
            start_time = time.time()
            while time.time() - start_time < 2.0:
                ready, _, _ = select.select([self.sock], [], [], 2.0 - (time.time() - start_time))
                if not ready: break
                
                raw_bytes, _ = self.sock.recvfrom(65535)
                parsed = parse_packet(raw_bytes)
                if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                    continue
                
                self.logger.log("RECV", parsed)
                if parsed['flags'] & FLAG_FIN:
                    if parsed['seq'] + parsed['len'] == self.ack:
                        self.ack += 1
                    break
        
        # 3. Send final ACK for the peer's FIN
        ip_hdr_f = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=107)
        tcp_seg_f = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK)
        self.sock.sendto(ip_hdr_f + tcp_seg_f, (self.dst_ip, 0))
        self.logger.log("SEND", parse_packet(ip_hdr_f + tcp_seg_f))
        
        self.peer_closed = True
        self.sock.close()


    def recv_some(self, timeout: float = 1.0):
        """Return arriving bytes, b'' if peer closed, or None on timeout."""
        # If we already closed the connection, return b"" immediately
        if getattr(self, 'peer_closed', False):
            return b""
            
        # Return piggybacked data from the handshake if it exists
        if self.early_data:
            data = self.early_data
            self.early_data = b""
            return data

        start_time = time.time()
        while time.time() - start_time < timeout:
            time_left = timeout - (time.time() - start_time)
            if time_left <= 0:
                break
                
            ready, _, _ = select.select([self.sock], [], [], time_left)
            if not ready:
                return None  # Real timeout

            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)

            # Ignore background network noise
            if not parsed or parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port:
                continue 

            # Drop connection on RST
            if parsed['flags'] & FLAG_RST:
                self.peer_closed = True
                return b""

            self.logger.log("RECV", parsed)

            payload = b""
            # 1. Process Data First
            if parsed['len'] > 0 and parsed['seq'] == self.ack:
                payload = parsed['payload']
                self.ack += parsed['len']
            
            # 2. Process FIN (FIN occupies 1 sequence number after the payload)
            fin_processed = False
            if (parsed['flags'] & FLAG_FIN) and (parsed['seq'] + parsed['len'] == self.ack):
                self.ack += 1
                self.peer_closed = True
                fin_processed = True
                
            # 3. Send one ACK if we consumed data or a FIN
            if payload or fin_processed:
                ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=998)
                tcp_seg = build_tcp_segment(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.seq, self.ack, FLAG_ACK)
                self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
                self.logger.log("SEND", parse_packet(ip_hdr + tcp_seg))
                
                # If there was data, return it first. Next call to recv_some will return b""
                if payload:
                    return payload
                if fin_processed:
                    return b""

            # If it is a pure ACK with no data/FIN, or an out-of-order packet, keep waiting
            continue

        return None

    def recv_until(self, delim: bytes, timeout: float = 5.0) -> bytes:
        """Buffer data until delimiter is found or timeout occurs."""
        buffer = b""
        start_time = time.time()
        while time.time() - start_time < timeout:
            chunk = self.recv_some(timeout=0.5)
            if chunk:
                buffer += chunk
                if delim in buffer:
                    return buffer
            elif chunk == b"": # Connection closed by peer
                break
        return buffer

class RawTCPListener:
    """Server-side TCP listener to accept incoming raw connections."""
    def __init__(self, src_ip: str, src_port: int, log_path: str = None):
        self.src_ip = src_ip
        self.src_port = src_port
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.logger = PacketLogger(log_path)

    def accept(self):
        while True:
            raw_bytes, _ = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            if not parsed or parsed['dport'] != self.src_port: continue
            if self.src_ip != "0.0.0.0" and parsed['dst_ip'] != self.src_ip: continue
                
            if parsed['flags'] == FLAG_SYN:
                self.logger.log("RECV", parsed)
                client_ip, client_port = parsed['src_ip'], parsed['sport']
                local_ip = parsed['dst_ip'] 
                
                server_seq, server_ack = random.randint(1000, 50000), parsed['seq'] + 1
                ip_hdr = build_ipv4_header(local_ip, client_ip, 24, ip_id=201)
                tcp_seg = build_tcp_segment(local_ip, client_ip, self.src_port, client_port, server_seq, server_ack, FLAG_SYN | FLAG_ACK, mss=DEFAULT_MSS)
                
                attempts = 0
                while attempts < 6:
                    self.sock.sendto(ip_hdr + tcp_seg, (client_ip, 0))
                    self.logger.log("SEND", parse_packet(ip_hdr + tcp_seg))
                    
                    # Inner loop prevents spurious packets from resetting the 1.0s timer
                    start_time = time.time()
                    ack_received = False
                    
                    while time.time() - start_time < 1.0:
                        time_left = 1.0 - (time.time() - start_time)
                        if time_left <= 0: break
                        
                        ready, _, _ = select.select([self.sock], [], [], time_left)
                        if not ready: break
                        
                        ack_bytes, _ = self.sock.recvfrom(65535)
                        ack_parsed = parse_packet(ack_bytes)
                        
                        if not ack_parsed or ack_parsed['src_ip'] != client_ip or ack_parsed['sport'] != client_port:
                            continue
                            
                        if ack_parsed['flags'] & FLAG_ACK and ack_parsed['ack'] == server_seq + 1:
                            self.logger.log("RECV", ack_parsed)
                            
                            conn = RawTCPConnection(local_ip, client_ip, client_port, self.src_port)
                            conn.logger = self.logger
                            conn.seq = server_seq + 1
                            conn.ack = ack_parsed['seq']
                            
                            # Catch piggybacked data and ACK it immediately!
                            if ack_parsed['len'] > 0:
                                conn.early_data = ack_parsed['payload']
                                conn.ack += ack_parsed['len']
                                ack_hdr = build_ipv4_header(conn.src_ip, conn.dst_ip, 20, ip_id=202)
                                ack_seg = build_tcp_segment(conn.src_ip, conn.dst_ip, conn.src_port, conn.dst_port, conn.seq, conn.ack, FLAG_ACK)
                                conn.sock.sendto(ack_hdr + ack_seg, (conn.dst_ip, 0))
                                conn.logger.log("SEND", parse_packet(ack_hdr + ack_seg))
                                
                            ack_received = True
                            break
                            
                    if ack_received:
                        print(f"Connection accepted from {client_ip}:{client_port}!")
                        return conn
                        
                    attempts += 1
                
                print("Failed to complete handshake. Listening again...")
                    
if __name__ == "__main__":
    import random
    
    random_src_port = random.randint(61000, 65535)
    
    # NEW API: Pass src_ip, dst_ip, dst_port, and src_port directly into the constructor
    conn = RawTCPConnection("10.10.1.10", "10.10.3.10", 8080, random_src_port)
    
    # NEW API: connect() no longer takes arguments
    if conn.connect():
        # Send an HTTP GET request
        http_request = b"GET / HTTP/1.1\r\nHost: 10.10.3.10\r\nConnection: close\r\n\r\n"
        conn.send_all(http_request)
        
        # Receive the HTML response (using the new recv_until method)
        response = conn.recv_until(b"\r\n\r\n")
        
        # If the server sends a body after the headers, fetch that too
        while True:
            chunk = conn.recv_some(timeout=2.0)
            if not chunk: 
                break
            response += chunk
            
        print("\n--- Server Response ---")
        print(response.decode('utf-8', errors='ignore'))
        
        conn.close()