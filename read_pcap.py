import argparse
import os
import sys
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

# function chuyển dấu thời gian
def print_timestamp(ts, resol):
    # chuyển thời gian thành đơn vị giây
    ts_sec = ts // resol
    # phần sau dấu phẩy của giây
    ts_sec_resol = ts % resol
    # chuyển thời gian thành đơn vị tự định dạng
    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    # trả về 1 chuỗi string
    return '{}.{}'.format(ts_str, ts_sec_resol)

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_count = 0

    # khai báo 2 biến ví dụ client và server chứa địa chỉ ip và cổng, bản chất vẫn chỉ là chuỗi string
    client = '192.168.1.137:57080'
    server = '152.19.134.43:80'

    # tách địa chỉ ip và địa chỉ port ngăn cách bởi dấu : bằng hàm split và gắn vào 2 biến _ip và _port
    (client_ip, client_port) = client.split(':')
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
        # nếu địa chỉ ip nguồn khác với server và client thì continue
        if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
            continue
        # nếu địa chỉ ip đích khác với server và client thì continue
        if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
            continue

        # giúp truy cập và lưu trữ gói tin TCP bên trong gói IP và lưu vào biến mới là tcp_pkt
        tcp_pkt = ip_pkt[TCP]
        # so sách cổng nguồn tương tự như ip
        if (tcp_pkt.sport != int(server_port)) and (tcp_pkt.sport != int(client_port)): # sử dụng int để chuyển string sang int vì ở trên vừa tách chuỗi string
            continue
        # so sánh cổng đích tương tự như ip
        if (tcp_pkt.dport != int(server_port)) and (tcp_pkt.dport != int(client_port)):
            continue

        interesting_count += 1

        # gói interesting đầu tiên
        if (interesting_count == 1):
            # sử dụng toán tử OR bitwise ( | ) để ghép 32 bit trước và sau thành 64 bit
            # pkt_metadata chứa dấu thời gian 64 bit nhưng chia thành 2 trường 32 bit tshigh và tslow nên cần gộp lại
            first_pkt_timestamp = (pkt_metadata.tshigh << 32 | pkt_metadata.tslow)
            # lưu trữ độ phân giải của dấu thời gian được lấy từ pkt_metadata
            first_pkt_timestamp_resolution = pkt_metadata.tsresol
            # thứ tự
            first_pkt_ordinal = count

        # gói interesting cuối cùng
        last_pkt_timestamp = (pkt_metadata.tshigh << 32 | pkt_metadata.tslow)
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count

    # kiểm tra thử xem phép chuyển đổi thời gian hoạt động như thế nào
    # print(first_pkt_timestamp)
    # print(first_pkt_timestamp_resolution)

    print('{} contains {} packets ({} interesting packets)'.format(file_name, count, interesting_count))

    print('First packet in connection: Packet #{} Time {}'.format(first_pkt_ordinal, print_timestamp(first_pkt_timestamp, first_pkt_timestamp_resolution)))

    print('Last packet in connection: Packet #{} Time {}'.format(last_pkt_ordinal, print_timestamp(last_pkt_timestamp, last_pkt_timestamp_resolution)))

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