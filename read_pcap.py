import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_count = 0

    # khai báo 2 biến ví dụ client và server chứa địa chỉ ip và cổng, bản chất vẫn chỉ là chuỗi string
    client = '192.168.1.137:57080'
    server = '152.19.134.43:80'

    # tách địa chỉ ip và địa chỉ port ngăn cách bởi dấu : bằng hàm split và gắn vào 2 biến _ip và _port
    (clien_ip, client_port) = client.split(':')
    (server_ip, server_port) = server.split(':')

    # truy cập từng gói Ethernet, mỗi lần lặp mang dữ liệu(nội dung gói,...) và siêu dữ liệu(dấu thời gian, số gói,...)
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        
        # bỏ qua những frame LLC(Logical Link Control) vì những frame này không có trường type như các gói thông thường
        if 'type' not in ether_pkt.fields:
            continue

        # kiểm tra xem gói nào không phải IPv4, 0x0800 là mã định danh của giao thức IPv4
        if ether_pkt.type != 0x0800:
            continue

        # giúp truy cập và lưu trữ gói tin IP bên trong gói Ethernet vào một biến mới là ip_pkt
        ip_pkt = ether_pkt[IP]
        # truy cập trường proto trong gói IP, proto == 6 đại diện cho gói tin TCP
        if ip_pkt.proto != 6:
            continue

        

        interesting_count += 1

    print('{} contains {} packets ({} interesting packets)'.format(file_name, count, interesting_count))

if __name__ == '__main__':

    # sử dụng module argparse để lấy tệp pcap từ terminal
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)