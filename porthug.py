import sys
import re
import logging
import random
import ipaddress
import argparse
from scapy.all import *
from scapy.layers.inet import traceroute

logging.getLogger("scapy").setLevel(logging.CRITICAL)

# global system variables, used for all type of scans
host_list = []
file_host_list = []
port_list = []
port_check_status = False
host_check_status = False
# don't break the regex lines below for formatting, will cause regex not to work as expect
ip_regex = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:$|(\-(2[0-4][0-9]|25[0-5]|1?[0-9]{1,2}))|(\/3[0-2]|\/2[0-9]|\/1[0-9]|\/[0-9])$|(\/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$))'
host_regex = '(^[-a-zA-Z0-9]+)($|(\.[a-zA-Z0-9]+)+)'
# start of argparse section
parser = argparse.ArgumentParser(add_help=False, prog='porthug',
                                 description='Welcome to Porthug, an advanced port scanner. Please see the usage '
                                             'below. If no command is selected, default TCP scan will be used.')
command_group = parser.add_argument_group('Commands')
other_group = parser.add_argument_group('Others')
command_group.add_argument('-t', '--tcp3way', action='store_true',
                           help='TCP 3way handshake connection scan.')
command_group.add_argument('-r', '--traceroute',
                           help='traceroute for either DNS, TCP or UDP.', choices=['dns', 'tcp', 'udp'])
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
parser.add_argument('-u', '--udp', action='store_true',
                    help='Only compatible with some scans, UDP mode')
parser.add_argument('-i', '--icmp', action='store_true',
                    help='Only compatible with some scans, ICMP-echo mode')
parser.add_argument('-l', '--file', metavar='path_to_txt_file', nargs='?', type=argparse.FileType('r'),
                    help='input a host list using txt file, can be used in addition to -h')
other_group.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
other_group.add_argument('-h', '--help', action='help', help='show this help message and exit')
args = parser.parse_args()


# end of argparse section


# populate IPs into an array for looping
def ippopulator(ip, isipaddr):
    global host_check_status
    global host_list
    # distinguish all IP input types
    singleip = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'
    blockips = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:$|(\/3[0-2]|\/2[0-9]|\/1[0-9]|\/[0-9])$|(\/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$))'
    rangeips = '(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))((?:\-(2[0-4][0-9]|25[0-5]|1?[0-9]{1,2})))'
    if isipaddr:
        # logics to check if only one single IP was input
        if re.match(singleip, ip):
            # populate the host_list
            host_list.append(ip)
            # print('single IPs: ' + str(host_list))
            host_check_status = True
        # logics to check if CIDR block IP was input
        elif re.match(blockips, ip):
            try:
                for x in ipaddress.ip_network(ip).hosts():
                    host_list.append(str(x))
                    host_check_status = True
            except ValueError:
                print('Looks like your CIDR block isn\'t correct, try fix it first. IP input: ' + ip)
            # print('block IPs: ' + str(host_list))
        # logics to check if a "simple" range of IP was input
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
        # populate the list for when a host name is used
        host_list.append(ip)
        host_check_status = True
        # print(host_list)
    else:
        # for error catching
        print('something is wrong when trying to populate address for scanning.')


# logics to check if the input host is a domain name or IP address
def checkhost(hosts):
    for x in hosts:
        if re.match(ip_regex, x):
            # print('looks like an IP')
            ippopulator(x, True)
        elif re.match(host_regex, x):
            # print('looks like a host: ' + hosts)
            ippopulator(x, False)


# TCP 3way handshake scanner
def threeway():
    global host_list
    global port_list
    for host in host_list:
        open_count = 0
        close_count = 0
        filtered_count = 0
        print('Here is the host to be scanned: ' + host)
        for port in port_list:
            # print('Here is the host to be scanned: ' + str(port))
            # need a random port on local host to send request each time
            src_port = random.randint(1025, 65534)
            ans, unans = sr(IP(dst=host) / TCP(sport=src_port, dport=port, flags='S'), timeout=1, verbose=0)
            if ans is None:
                print(f'{host}:{port} might have been filtered.')
                filtered_count = filtered_count + 1
            else:
                answer = str()
                for s, r in ans:
                    answer = r[TCP].flags
                if answer == 'SA':
                    sr1(IP(dst=host) / TCP(sport=src_port, dport=port, flags='A'), verbose=0)
                    print(f'{host}:{port} is open!!')
                    open_count = open_count + 1
                else:
                    close_count = close_count + 1
        total_count = eval('close_count + open_count + filtered_count')
        print('Total ports scanned: ' + str(total_count))
        print('There are ' + str(close_count) + ' closed ports, ' + str(open_count) + ' opened ports, and '
              + str(filtered_count) + ' filtered ports in host ' + host)
        print('\n')


# UDP scanner
def udpscan():
    global host_list
    global port_list
    for host in host_list:
        close_count = 0
        open_count = 0
        # print('Here is the host to be scanned: ' + host)
        for port in port_list:
            # print('Here is the host to be scanned: ' + str(port))
            ans = sr1(IP(dst=host) / UDP(dport=port), timeout=2, verbose=0)
            if ans is None:
                close_count = close_count + 1
            else:
                if ans.haslayer(UDP):
                    print(f'{host}:{port} is open!!')
                    open_count = open_count + 1
                elif ans.haslayer(ICMP):
                    close_count = close_count + 1
        print('There are ' + str(close_count) + ' closed ports. ' + str(open_count) + ' opened ports.' + host)


# ICMP scanner
def icmp():
    global host_list
    for host in host_list:
        # print('Here is the host to be scanned: ' + host)
        ans, unans = sr(IP(dst=host) / ICMP(), timeout=3, verbose=0)
        if ans is not None:
            ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

# traceroute, allows tcp, udp and dns options
def tracecrt(type):
    global host_list
    if type == 'dns':
        for host in host_list:
            ans, unans = traceroute(host, l4=UDP(sport=random.randint(1025, 65534)) / DNS(qd=DNSQR(qname=host)))
    if type == 'tcp':
        for host in host_list:
            ans, unans = sr(IP(dst=host, ttl=(1, 10)) / TCP(dport=53, flags="S"), verbose=0)
            ans.summary(lambda s, r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))
    if type == 'udp':
        for host in host_list:
            res, unans = sr(IP(dst=host, ttl=(1, 20)) / UDP() / DNS(qd=DNSQR(qname=host)), verbose=0)
            res.make_table(lambda s, r: (s.dst, s.ttl, r.src))


# logics to check if ports input are correct, then put them into a global list
def checkport(ports):
    global port_check_status
    # print('Checking ports')
    check_digits = '(\d{1,5}-\d{1,5})'
    # loop through -p input in case of multiple block of ports are used
    for x in ports:
        # check to see if a port range is used
        if re.match(check_digits, x):
            y = re.split('-', x)
            k = eval('int(y[1]) + 1')
            g = int(y[0])
            if 1 <= g <= 65535 and 1 <= int(y[1]) <= 65535:
                for j in range(g, k):
                    port_list.append(j)
                port_check_status = True
            else:
                print('Your port range is off, please check.')
            # print(port_list)
        # check if single port is used
        elif re.match('(\d{1,5})', x):
            print('single_port')
            if 1 <= int(x) <= 65535:
                port_list.append(int(x))
                port_check_status = True
            else:
                print('Your port range is off, please check.')
        # error catching
        else:
            print('It doesn\'t look like you have valid port numbers, did you mean to use -p-?')
    # print(port_list)


# initiate the program to read command line arguments
def start():
    global port_check_status
    global host_check_status
    # check if no arguments are past
    if len(sys.argv) == 1:
        print("Please supply a command name, use --help for more info")
        parser.parse_args(['-h'])
        exit()
    # send input host destination to test
    if args.hosts:
        # print('Here is your host: ' + str(args.hosts))
        checkhost(args.hosts)
    # send input host file to test
    if args.file:
        global file_host_list
        # print('Here is your file: ' + args.file.read())
        file_host_list = args.file.read().splitlines()
        # print(file_host_list)
        checkhost(file_host_list)
    # check if either host IP/Name or host file is used. -d or -i
    if not args.hosts and not args.file:
        print('You will have to at least supply a host or using a txt file containing a list of hosts.')
        exit()
    # check if either port or all ports format is past, similar to NMAP
    if args.ports and args.allports:
        print('You can\'t use -p- with -p, try again.')
        exit()
    elif args.ports:
        # print('Here is your ports: ' + str(args.ports))
        checkport(args.ports)
    elif args.allports:
        # print('So you wanna get all ports')
        for x in range(1, 65536):
            port_list.append(x)
            port_check_status = True
        # print(port_list)
    # check if TCP 3way scan is being called
    if args.tcp3way:
        print('TCP called')
        if host_check_status and port_check_status:
            threeway()
        else:
            print('Something is wrong, please check.')
    # check if ICMP scan is being called
    if args.icmp:
        print('ICMP called')
        if host_check_status:
            icmp()
        else:
            print('Something is wrong, please check.')
    # check if UDP scan is being called
    if args.udp:
        print('UDP called')
        if host_check_status and port_check_status:
            udpscan()
        else:
            print('Something is wrong, please check.')
    if args.traceroute:
        print('traceroute called')
        if host_check_status and args.traceroute == 'dns':
            tracecrt('dns')
        elif host_check_status and args.traceroute == 'tcp':
            tracecrt('tcp')
        elif host_check_status and args.traceroute == 'udp':
            tracecrt('udp')
        else:
            print('Something is wrong, please check.')


# initiate the program
if __name__ == "__main__":
    start()
