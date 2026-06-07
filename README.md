# dhcp-parser-zig

A DHCP packet parser written in Zig, takes stdin for input, can read from binary packets and from pcaps.

## Binary Packet
```bash
echo discover.bin | dhcp-parser-zig
```

## PCAP Capture
```bash
sudo tcpdump -U -i eth0 -w - udp port 67 or port 68 | ./dhcp_parser_zig --pcap_input
```

Example output:
```
op: BOOTREQUEST
htype: 1
hlen: 6
xid: 920527217
secs: 53377
flags: NOT BROADCAST
ciaddr: 0.0.0.0
yiaddr: 0.0.0.0
siaddr: 0.0.0.0
giaddr: 0.0.0.0
chaddr: XX:XX:XX:XX:XX:XX
sname:
file:
Option: DHCP Message Type: { X }
Option: Client Identifier: { X, XX, XX, XX, XXX, XX, X }
Option: Parameter Request List: { X, X, X, XX, XX, XX, XX, XX, XX, XXX, XXX, XXX }
Option: Vendor Class Identifier: { XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX }
Option: Max Message Size: { X, XX }
Option: Host Name: { XX, XX, XX, XX, XX, XX, XX }
```
