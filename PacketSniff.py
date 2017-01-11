import socket
import struct
import textwrap


# main function establishes socket connection and gets ethernet frame
#   (including destination/source address, IP header and data)

def main():
    # HOST = socket.gethostbyname(socket.gethostname())
    #  print('IP: {}'.format(HOST))

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # conn.bind((HOST, 0))
    # conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        print("Recieving...")
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        version, header_length, time, ip_proto, ip_source, ip_dest, ip_data = unpack_header(data)
        if eth_proto == 8:
            print("Ethernet Frame: ")
            print("Destination : {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
            print("IP Source : {}, IP Target: {}, Protocol: {}, Header length: {}, Version: {}"
                  .format(ip_source, ip_dest, ip_proto, header_length, version))
            if ip_proto == 1:
                try:
                    code, _type, checksum, data = icmp_packet(ip_data)
                    decoded_data = data.decode('utf-8', 'strict')
                    print("Data:{} ".format(decoded_data))
                  #  x = input("PRESS ANY KEY TO CONTINUE")
                except:
                    continue

            elif ip_proto == 6:
                try:
                    source_port, destination_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, \
                    flag_syn, flag_fin, data = tcp_packet(ip_data)
                    decoded_data = data.decode('utf-8','strict')
                    print("Data:{}".format(decoded_data))
                   # input("PRESS ANY KEY TO CONTINUE")
                except:
                    continue

            elif ip_proto == 17:
                try:
                    source_port, destination_port, size, data = udp_packet(ip_data)
                    decoded_data = data.decode('utf-8','strict')
                    print("Data:{} ".format(decoded_data))
                except:
                    continue
            else:
                print("DATA IS NOT TCP, ICMP OR UDP")
        #x = input("PRESS ANY KEY TO CONTINUE")

# unpack Ethernet Frame ( in to destination MAC, source MAC, protocol and data)

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# formats MAC Address

def get_mac_addr(address):
    bytes_str = map('{:02x}'.format, address)
    return ':'.join(bytes_str).upper()


# unpacks IP Header

def unpack_header(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(source), ipv4(target), data[header_length:]


# formats IPv4 address

def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks ICMP packet

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return code, icmp_type, checksum, data[4:]


# Unpacks TCP Packet


def tcp_packet(data):
    source_port, destination_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H',
                                                                                                   data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return source_port, destination_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, \
        flag_syn, flag_fin, data[offset:]


# Unpacks UDP packet

def udp_packet(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[0:8])
    return source_port, destination_port, size, data[8:]


main()
