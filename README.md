# porthug
usage: porthug [-t] [-r {dns,tcp,udp}] [-f] [-n] [-a] [-aw] [-s] [-d HOSTS [HOSTS ...]] [-p PORTS [PORTS ...]] [-p-]
               [-u] [-i] [-l [path_to_txt_file]] [-v] [-h]

Welcome to Porthug, an advanced port scanner. Please see the usage below. If no command is selected, default TCP scan
will be used.

optional arguments:
  -d HOSTS [HOSTS ...], --hosts HOSTS [HOSTS ...]
                        Host or hosts to be scanned, accept IP or range of IPs and FQDN. Range example:
                        192.168.1.1-255, 192.168.1.0/24, 192.168.1.0/255.255.0.0 or 192.168.1.50 192.168.1.200
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        Specify ports for scanning, if all ports use -p-. Port range example: 1-100, 200-300, 500
  -p-, --allports       Shortcut for all ports, do not use with -pexample: 1-100, 200-300, 500
  -u, --udp             Only compatible with some scans, UDP mode
  -i, --icmp            Only compatible with some scans, ICMP-echo mode
  -l [path_to_txt_file], --file [path_to_txt_file]
                        input a host list using txt file, can be used in addition to -h

Commands:
  -t, --tcp3way         TCP 3way handshake connection scan.
  -r {dns,tcp,udp}, --traceroute {dns,tcp,udp}
                        traceroute for either DNS, TCP or UDP.
  -f, --fin             FIN scan.
  -n, --null            NULL scan.
  -a, --ack             ACK scan.
  -aw, --window         TCP Windows scan.
  -s, --stealth         Stealth scan.

Others:
  -v, --version         show program's version number and exit
  -h, --help            show this help message and exit
