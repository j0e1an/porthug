# Porthug - multi-feaure port scanner

## Introduction

This is a project I did for my class. Feel free to use it or fork it to make it better. Scapy is used so make sure you have imported that in your python environment. 

## Code Samples

# porthug
usage: </p>porthug [-t] [-r {dns,tcp,udp}] [-f] [-n] [-a] [-aw] [-s] [-d HOSTS [HOSTS ...]] [-p PORTS [PORTS ...]] [-p-]
               [-u] [-i] [-l [path_to_txt_file]] [-v] [-h]
</p>
optional arguments:</p>
  -d HOSTS [HOSTS ...], --hosts HOSTS [HOSTS ...]</p>
                        Host or hosts to be scanned, accept IP or range of IPs and FQDN. </p>Range example:
                        192.168.1.1-255, 192.168.1.0/24, 192.168.1.0/255.255.0.0 or 192.168.1.50 192.168.1.200</p>
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]</p>
                        Specify ports for scanning, if all ports use -p-. Port range example: 1-100, 200-300, 500</p>
  -p-, --allports       Shortcut for all ports, do not use with -pexample: 1-100, 200-300, 500</p>
  -u, --udp             Only compatible with some scans, UDP mode</p>
  -i, --icmp            Only compatible with some scans, ICMP-echo mode</p>
  -l [path_to_txt_file], --file [path_to_txt_file]</p>
                        input a host list using txt file, can be used in addition to -h</p>

Commands:</p>
  -t, --tcp3way         TCP 3way handshake connection scan.</p>
  -r {dns,tcp,udp}, --traceroute {dns,tcp,udp}</p>
                        traceroute for either DNS, TCP or UDP.</p>
  -f, --fin             FIN scan.</p>
  -n, --null            NULL scan.</p>
  -a, --ack             ACK scan.</p>
  -aw, --window         TCP Windows scan.</p>
  -s, --stealth         Stealth scan.</p>

Others:</p>
  -v, --version         show program's version number and exit</p>
  -h, --help            show this help message and exit</p>


## Installation

Just download and run it on python. Needs administrator right. Windows user please download latest dev version of scapy and follow the instruction from https://scapy.readthedocs.io/en/latest/installation.html#windows
