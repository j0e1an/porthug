import sys
import re
import logging
import random
import ipaddress
from scapy.all import sr1, IP, ICMP, TCP, sr, UDP

logging.getLogger("scapy").setLevel(logging.CRITICAL)
import argparse

host_list = []
file_host_list = []
port_list = []
port_check_status = False
host_check_status = False
ip_regex = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:$|(\-(2[0-4][0-9]|25[0-5]|1?[0-9]{1,2}))|(\/3[0-2]|\/2[0-9]|\/1[0-9]|\/[0-9])$|(\/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$))'
host_regex = '(^[-a-zA-Z0-9]+)($|(\.[a-zA-Z0-9]+)+)'
parser = argparse.ArgumentParser(add_help=False, prog='porthug',
                                 description='Welcome to Porthug, an advanced port scanner. Please see the usage '
                                             'below. If no command is selected, default TCP scan will be used.')
command_group = parser.add_argument_group('Commands')
other_group = parser.add_argument_group('Others')
command_group.add_argument('-3', '--tcp3way', action='store_true', default='store_false',
                           help='TCP 3way handshake connection scan.')
command_group.add_argument('-x', '--xmas', action='store_true',
                           help='Christmas scan.')
command_group.add_argument('-f', '--fin', action='store_true',
                           help='FIN scan.')
command_group.add_argument('-n', '--null', action='store_true',
                           help='NULL scan.')
command_group.add_argument('-a', '--ack', action='store_true',
                           help='ACK scan.')
command_group.add_argument('-aw', '--window', action='store_true',
                           help='TCP Windows scan.')
command_group.add_argument('-s', '--stealth', action='store_true',
                           help='Stealth scan.')
parser.add_argument('-d', '--hosts', nargs="+",
                    help='Host or hosts to be scanned, accept IP or range of IPs and FQDN. '
                         'Range example: 192.168.1.1-255, 192.168.1.0/24, 192.168.1.0/255.255.0.0 or 192.168.1.50 '
                         '192.168.1.200')
parser.add_argument('-p', '--ports', nargs="+",
                    help='Specify ports for scanning, if all ports use -p-. Port range '
                         'example: 1-100, 200-300, 500')
parser.add_argument('-p-', '--allports', action='store_true',
                    help='Shortcut for all ports, do not use with -p'
                         'example: 1-100, 200-300, 500')
parser.add_argument('-u', '--udp', action='store_true', help='Only compatible with some scans, UDP mode')
parser.add_argument('-i', '--icmp', action='store_true', help='Only compatible with some scans, ICMP-echo mode')
parser.add_argument('-l', '--file', metavar='path_to_txt_file', nargs='?', type=argparse.FileType('r'),
                    help='input a host list using txt file, can be used in addition to -h')
other_group.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
other_group.add_argument('-h', '--help', action='help', help='show this help message and exit')
args = parser.parse_args()


def ippopulator(ip, isipaddr):
    global host_check_status
    global host_list
    singleip = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'
    blockips = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:$|(\/3[0-2]|\/2[0-9]|\/1[0-9]|\/[0-9])$|(\/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$))'
    rangeips = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))((?:\-(2[0-4][0-9]|25[0-5]|1?[0-9]{1,2})))'
    if isipaddr:
        if re.match(singleip, ip):
            host_list.append(ip)
            # print('single IPs: ' + str(host_list))
            host_check_status = True
        elif re.match(blockips, ip):
            try:
                for x in ipaddress.ip_network(ip).hosts():
                    host_list.append(str(x))
                    host_check_status = True
            except ValueError:
                print('Looks like your CIDR block isn\'t correct, try fix it first. IP input: ' + ip)
            # print('block IPs: ' + str(host_list))
        elif re.match(rangeips, ip):
            prefix = re.search('(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3})', ip).group(0)
            suffix = re.search('((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:$|(\-(2[0-4][0-9]|25[0-5]|1?[0-9]{1,2})))',
                               ip).group(0)
            y = re.split('-', suffix)
            g = int(y[0])
            k = eval('int(y[1]) + 1')
            for e in range(g, k):
                j = prefix + str(e)
                host_list.append(j)
            # print('range IPs: ' + str(host_list))
            host_check_status = True
        else:
            print('Something is terribly wrong with your host IP, please check. IP input: ' + ip)
    elif not isipaddr:
        host_list.append(ip)
        host_check_status = True
        # print(host_list)
    else:
        print('something is wrong when trying to populate address for scanning.')


def checkhost(hosts):
    for x in hosts:
        if re.match(ip_regex, x):
            # print('looks like an IP')
            ippopulator(x, True)
        elif re.match(host_regex, x):
            # print('looks like a host: ' + hosts)
            ippopulator(x, False)


def threeway():
    global host_list
    global port_list
    for host in host_list:
        print('Here is the host to be scanned: ' + host)
        for port in port_list:
            print('Here is the port to be scanned: ' + str(port))
            src_port = random.randint(1025, 65534)
            tcp_connect_scan_resp = sr1(IP(dst=host) / TCP(sport=src_port, dport=port, flags='S'), timeout=10,
                                        verbose=0)
            if tcp_connect_scan_resp is None:
                print(f'{host}:{port} might have been filtered.')
            elif tcp_connect_scan_resp.haslayer(TCP):
                if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:
                    sr1(IP(dst=host) / TCP(sport=src_port, dport=port, flags='R'), timeout=10, verbose=0)
                    print(f'{host}:{port} is open!!')
                elif tcp_connect_scan_resp.getlayer(TCP).flags == 0x14:
                    print(f'{host}:{port} is closed!!')


def udpscan():
    global host_list
    global port_list
    for host in host_list:
        print('Here is the host to be scanned: ' + host)
        for port in port_list:
            print('Here is the port to be scanned: ' + str(port))
            src_port = random.randint(1025, 65534)
            udp_scan_resp = sr1(IP(dst=host) / UDP(dport=port), timeout=10, verbose=0)
            if udp_scan_resp is None:
                print(f'{host}:{port} might have been filtered.')
            elif udp_scan_resp.haslayer(UDP):
                print(f'{host}:{port} is open!!')
            else:
                print(f'{host}:{port} is closed!!')


def icmp():
    global host_list
    live_count = 0
    for host in host_list:
        print('Here is the host to be scanned: ' + host)
        resp = sr1(
            IP(dst=str(host)) / ICMP(),
            timeout=2,
            verbose=0,
        )
        if resp is None:
            print(f"{host} is down or not responding.")
        elif (
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
        ):
            print(f"{host} is blocking ICMP.")
        else:
            print(f"{host} is responding.")
            live_count += 1

        print(f"{live_count}/{addresses.num_addresses} hosts are online.")


def checkport(ports):
    global port_check_status
    for x in ports:
        if re.match('\d-\d{1,5}', x):
            y = re.split('-', x)
            k = eval('int(y[1]) + 1')
            y = int(y[0])
            for j in range(y, k):
                port_list.append(j)
        elif 1 <= int(x) <= 65535:
            port_list.append(int(x))
            port_check_status = True
            # print(port_list)
        else:
            print('It doesn\'t look like you have valid port numbers, did you mean to use -p-?')
    # print(port_list)


def start():
    if len(sys.argv) == 1:
        print("Please supply a command name, use --help for more info")
        parser.parse_args(['-h'])
    if args.hosts:
        # print('Here is your host: ' + str(args.hosts))
        checkhost(args.hosts)
    if args.file:
        global file_host_list
        # print('Here is your file: ' + args.file.read())
        file_host_list = args.file.read().splitlines()
        # print(file_host_list)
        checkhost(file_host_list)
    if not args.hosts and not args.file:
        print('You will have to at least supply a host or using a txt file containing a list of hosts.')
        exit()
    if args.ports and args.allports:
        print('You can\'t use -p- with -p, try again.')
    elif args.ports:
        # print('Here is your ports: ' + str(args.ports))
        checkport(args.ports)
    elif args.allports:
        # print('So you wanna get all ports')
        for x in range(1, 65536):
            port_list.append(x)
        # print(port_list)
    if args.tcp3way:
        if host_check_status and port_check_status:
            threeway()


if __name__ == "__main__":
    start()
