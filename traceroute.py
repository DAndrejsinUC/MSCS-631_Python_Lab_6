from socket import *
import os
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2


def checksum(data):
    csum = 0
    countTo = (len(data) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = data[count + 1] * 256 + data[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count += 2

    if countTo < len(data):
        csum = csum + data[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum & 0xffff
    answer = (answer >> 8) | ((answer << 8) & 0xff00)

    return answer


def build_packet():
    myID = os.getpid() & 0xFFFF
    seq = 1
    dummy_checksum = 0

    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, dummy_checksum, myID, seq)
    data = struct.pack("!d", time.time())

    myChecksum = checksum(header + data)

    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, myChecksum, myID, seq)
    packet = header + data
    return packet


def get_route(hostname):
    destAddr = gethostbyname(hostname)
    print(f"Traceroute to {hostname} [{destAddr}]")

    for ttl in range(1, MAX_HOPS + 1):
        reached = False

        for _ in range(TRIES):
            try:
                mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
                mySocket.settimeout(TIMEOUT)

                packet = build_packet()
                send_time = time.time()
                mySocket.sendto(packet, (destAddr, 0))

                ready = select.select([mySocket], [], [], TIMEOUT)
                if not ready[0]:
                    print(f"{ttl}  * * * Request timed out.")
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                recv_time = time.time()

                # IP header is usually first 20 bytes
                ip_header = recvPacket[:20]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                iph_len = (iph[0] & 0x0F) * 4

                icmp_header = recvPacket[iph_len:iph_len + 8]
                icmp_type, code, recv_checksum, packet_id, sequence = struct.unpack("!BBHHH", icmp_header)

                rtt = (recv_time - send_time) * 1000

                if icmp_type == 11:
                    print(f"{ttl}  rtt={rtt:.0f} ms  {addr[0]}")
                    break
                elif icmp_type == 3:
                    print(f"{ttl}  rtt={rtt:.0f} ms  {addr[0]}")
                    break
                elif icmp_type == 0:
                    print(f"{ttl}  rtt={rtt:.0f} ms  {addr[0]}")
                    reached = True
                    break
                else:
                    print(f"{ttl}  ICMP type {icmp_type} from {addr[0]}")
                    break

            except timeout:
                print(f"{ttl}  * * * Request timed out.")
            finally:
                mySocket.close()

        if reached:
            print("Trace complete.")
            return

    print("Maximum hops reached.")


get_route("8.8.8.8")
get_route("google.com")