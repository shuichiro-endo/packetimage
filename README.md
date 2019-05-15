# PacketImage

Packet Flow Graph Image


## Summary

I made this tool because I want to comprehend network instantly from a lot of packet data.

For example, start and end node, protocol, port number, and so on.

This tool can do the following.

- Output packet flow graph image (PNG) from pcap file
    - L2 type
        - Private and Multicast Address
        - Type
            - IPv4:red, ARP:greenyellow, IPv6:cyan, ...
        - Vlan ID
    - IPv4 type
        - Private, Multicast, and Global Address
        - Protocol
            - ICMP:black, TCP:green, UDP:orange
        - Source and Destination Port Number
    - IPv6 type
        - Link Local, Unique Local, Multicast and Global Address
        - Protocol
            - ICMP6:black, TCP:green, UDP:orange
        - Source and Destination Port Number


## Installation

This tool can run Linux Operationg System(e.g. Debian).

Also, You need to install the following packages.

- python 2.7.16
- python-dpkt 1.9.2-1
- graphviz 0.10.1
    - ````pip install graphviz````


## Example

1. Run
    ````
    $ python packetimage.py -h
    usage: python packetimage.py parsetype inputfile outputfile [--help]

    positional arguments:
      parsetype   l2 or ipv4 or ipv6
      inputfile   input pcap file name
      outputfile  output file name (The file extension does not include.)

    optional arguments:
      -h, --help  show this help message and exit

    $ python packetimage.py ipv4 test.pcap testimage
    ````


## Sample
- L2 type
    - ![l2-001.png](./image/l2-001.png)

    - ![l2-002.png](./image/l2-002.png)

- IPv4 type
    - ![ipv4-001.png](./image/ipv4-001.png)

    - ![ipv4-002.png](./image/ipv4-002.png)

- IPv6 type
    - ![ipv6-001.png](./image/ipv6-001.png)
