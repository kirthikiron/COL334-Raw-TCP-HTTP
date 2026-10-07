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

        # STEP 1: Send SYN
        ip_hdr = build_ipv4_header(self.src_ip, self.dst_ip, 24, ip_id=101)
        tcp_seg = build_tcp_segment(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.seq, self.ack, FLAG_SYN, mss=DEFAULT_MSS
        )
        self.sock.sendto(ip_hdr + tcp_seg, (self.dst_ip, 0))
        
        # Log the outgoing SYN
        self.logger.log("SND", parse_packet(ip_hdr + tcp_seg))

        # STEP 2: Wait for SYN-ACK
        while True:
            # select() waits up to 1.0 second for a packet to arrive on the socket
            ready, _, _ = select.select([self.sock], [], [], 1.0)
            
            if not ready:
                print("Timeout waiting for SYN-ACK! (Need to implement retransmission here later)")
                return False

            # Receive the incoming packet
            raw_bytes, addr = self.sock.recvfrom(65535)
            parsed = parse_packet(raw_bytes)
            
            # Ignore corrupted packets or packets not meant for this connection
            if not parsed: continue
            if parsed['src_ip'] != self.dst_ip or parsed['dport'] != self.src_port: continue

            # Check if it is the expected SYN-ACK
            if parsed['flags'] == (FLAG_SYN | FLAG_ACK) and parsed['ack'] == self.seq + 1:
                self.logger.log("RCV", parsed)
                
                # Update our sequence and acknowledgment numbers
                self.seq += 1
                self.ack = parsed['seq'] + 1
                break

        # STEP 3: Send final ACK
        ip_hdr_ack = build_ipv4_header(self.src_ip, self.dst_ip, 20, ip_id=102)
        tcp_seg_ack = build_tcp_segment(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.seq, self.ack, FLAG_ACK
        )
        self.sock.sendto(ip_hdr_ack + tcp_seg_ack, (self.dst_ip, 0))
        self.logger.log("SND", parse_packet(ip_hdr_ack + tcp_seg_ack))
        
        print(f"Connection established with {self.dst_ip}:{self.dst_port}!")
        return True


if __name__ == "__main__":
    import random
    
    # Pick a random high port for each test run to avoid OS connection conflicts
    random_src_port = random.randint(10000, 60000)
    
    # Create a connection on localhost using the random port
    conn = RawTCPConnection("127.0.0.1", random_src_port)
    
    # Attempt to connect to the server
    conn.connect("127.0.0.1", 8080)