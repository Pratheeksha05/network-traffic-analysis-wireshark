# Network Traffic Analysis and Suspicious Activity Investigation Using Wireshark

## Project Overview

This project demonstrates practical network traffic analysis and introductory security investigation using **Wireshark 4.6.9** on Windows 11.

The objective was to capture and inspect network packets, understand commonly used network protocols, investigate communication patterns, and identify potentially unusual network behavior through packet-level analysis.

The investigation covered TCP, UDP, DNS, HTTP, HTTPS/TLS, ARP, DHCP, ICMPv6, and multicast DNS (mDNS).

## Objectives

- Capture and inspect network traffic using Wireshark.
- Understand packet structure and TCP/IP communication.
- Analyze TCP three-way handshakes.
- Investigate TCP retransmissions, duplicate acknowledgments, and connection resets.
- Examine DNS queries and responses.
- Inspect HTTP requests and response status codes.
- Understand TLS handshakes and encrypted application data.
- Analyze ARP requests and replies.
- Examine DHCP message types.
- Investigate ICMPv6 Neighbor Discovery.
- Analyze mDNS service-discovery traffic.
- Apply Wireshark display filters and document findings.

## Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| Windows 11 | Operating system |
| Wireshark 4.6.9 | Packet capture and analysis |
| TCP/IP | Network communication |
| DNS | Domain name resolution |
| HTTP/HTTPS | Web communication |
| ARP | IPv4-to-MAC address resolution |
| DHCP | Dynamic IP configuration |
| ICMPv6 | IPv6 Neighbor Discovery |
| mDNS | Local network service discovery |

## Protocols Investigated

### 1. TCP Analysis

- Examined TCP connection establishment using SYN, SYN-ACK, and ACK packets.
- Investigated retransmissions, fast retransmissions, duplicate acknowledgments, and out-of-order packets.
- Examined TCP FIN and RST flags.
- Inspected connection behavior using TCP stream filtering.

### 2. UDP Analysis

- Examined UDP headers, source and destination ports, packet lengths, and payload data.
- Investigated a UDP packet sent to a local network broadcast address.
- Learned that a port number alone is insufficient to conclusively identify an application protocol.

### 3. DNS Analysis

- Inspected DNS queries and responses.
- Examined A, AAAA, and HTTPS DNS record types.
- Reviewed query names and returned address information.
- Investigated multicast DNS traffic and local service discovery.

### 4. HTTP Analysis

- Inspected HTTP GET requests and response messages.
- Examined request URI paths and HTTP response status codes.
- Observed an HTTP 301 Moved Permanently response.
- Applied filters for HTTP methods and error responses.

### 5. HTTPS/TLS Analysis

Investigated a TCP-based TLS connection with the SNI hostname `edge.microsoft.com`.

Observed handshake progression:

- Client Hello
- Server Hello and certificate-related messages
- Client Key Exchange
- Change Cipher Spec
- Encrypted Handshake Messages
- Encrypted Application Data in both directions

A later TCP RST packet was also observed. No matching TLS Alert or TCP FIN packets were identified in that stream.

The encrypted application content was not decrypted.

### 6. ARP Analysis

- Examined ARP requests and replies.
- Investigated IP-to-MAC address resolution.
- Observed repeated requests and consistent reply mappings in the examined sample.
- Checked for gratuitous ARP and duplicate-address-detection indicators.

### 7. DHCP Analysis

- Examined DHCP Request and Inform messages.
- Inspected transaction IDs, requested IP information, and client identifiers.
- Checked for Discover, Offer, ACK, NAK, Decline, and Release messages.
- Documented that a complete DHCP address-assignment exchange could not be established from the captured packets.

### 8. ICMPv6 Neighbor Discovery

- Examined Neighbor Solicitation (Type 135).
- Examined Neighbor Advertisement (Type 136).
- Inspected target IPv6 addresses and link-layer address information.
- Investigated the significance of the IPv6 Hop Limit.

### 9. mDNS Analysis

- Examined multicast DNS queries and responses.
- Investigated local service-discovery records.
- Reviewed WPAD-related hostname queries.
- Examined a Nearby Presence service-discovery response.
- Distinguished local service discovery from confirmed malicious activity.

## Selected Wireshark Display Filters

| Investigation | Display Filter |
|---|---|
| TCP traffic | `tcp` |
| UDP traffic | `udp` |
| DNS traffic | `dns` |
| HTTP traffic | `http` |
| TLS traffic | `tls` |
| ARP traffic | `arp` |
| DHCP traffic | `dhcp` |
| ICMPv6 traffic | `icmpv6` |
| mDNS traffic | `mdns` |
| TCP initial SYN | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| TCP SYN-ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| TCP retransmissions | `tcp.analysis.retransmission` |
| TCP duplicate ACK | `tcp.analysis.duplicate_ack` |
| TCP reset | `tcp.flags.reset == 1` |
| TCP FIN | `tcp.flags.fin == 1` |
| DNS queries | `dns.flags.response == 0` |
| DNS responses | `dns.flags.response == 1` |
| HTTP requests | `http.request` |
| TLS Client Hello | `tls.handshake.type == 1` |
| TLS Server Hello | `tls.handshake.type == 2` |
| ARP requests | `arp.opcode == 1` |
| ARP replies | `arp.opcode == 2` |
| ICMPv6 Neighbor Solicitation | `icmpv6.type == 135` |
| ICMPv6 Neighbor Advertisement | `icmpv6.type == 136` |

## Key Findings

- Identified TCP connection-establishment sequences.
- Observed TCP retransmission and duplicate-acknowledgment indicators.
- Examined DNS queries and responses across different record types.
- Identified an HTTP GET request and a 301 redirect response.
- Observed a TLS handshake followed by encrypted application-data exchange in both directions.
- Identified a later TCP reset in the investigated TLS connection.
- Examined ARP request/reply behavior and consistent address mappings in the selected sample.
- Identified DHCP Request and Inform messages without a complete address-assignment exchange in the capture.
- Investigated IPv6 Neighbor Discovery and multicast service-discovery traffic.

**Security conclusion:** No confirmed malicious activity was established during this investigation. Observed packet indicators were interpreted in context rather than automatically classified as attacks.

## Skills Demonstrated

- Network traffic capture and packet inspection
- Wireshark display-filter usage
- TCP/IP fundamentals
- DNS and HTTP analysis
- TLS handshake investigation
- ARP and DHCP analysis
- IPv6 Neighbor Discovery
- mDNS service discovery
- Basic network troubleshooting
- Evidence-based security investigation
- Technical documentation and reporting

## Repository Contents

```text
network-traffic-analysis-wireshark/
│
├── README.md
└── Network_Traffic_Investigation_Report.txt
```

The original `.pcapng` capture is retained locally and is not included in this public repository to avoid exposing potentially sensitive network information.

## Limitations

- The investigation was performed on a single Windows 11 Wi-Fi environment.
- Findings represent only the traffic visible during the capture period.
- HTTPS/TLS application payloads remained encrypted.
- Port numbers alone were not treated as proof of application identity.
- Wireshark analysis indicators require context and do not independently prove an attack or network fault.
- The absence of a packet type does not prove that the corresponding activity never occurred.
- No confirmed cyberattack was established.

## Conclusion

This project provided practical experience in network packet capture, protocol analysis, TCP connection investigation, DNS and HTTP inspection, TLS handshake analysis, and local network traffic investigation.

It strengthened my understanding of networking fundamentals and introductory security monitoring techniques using Wireshark.

**Project Type:** Educational Cybersecurity / Network Traffic Analysis  
**Operating System:** Windows 11  
**Packet Analysis Tool:** Wireshark 4.6.9  
**Capture Format:** PCAPNG
