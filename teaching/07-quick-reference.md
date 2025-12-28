# Networking Foundations Quick Reference

## Your Existing Knowledge Summary ✅

Based on what you shared, you already understand these core concepts:

### Number Systems
| System | Base | Characters | Example |
|--------|------|------------|---------|
| Binary | 2 | 0,1 | 11000110 = 198 |
| Decimal | 10 | 0-9 | 198 |
| Octal | 8 | 0-7 | 306 |
| Hexadecimal | 16 | 0-F | C6 |

### Binary Conversion (Your Method)
```
To convert 198 to binary:
128 + 64 + 4 + 2 = 198

| 1   | 1  | 0  | 0  | 0 | 1 | 1 | 0 |
|-----|----|----|----|----|---|---|---|
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
| 2⁷  | 2⁶ | 2⁵ | 2⁴ | 2³| 2²| 2¹| 2⁰|

Result: 11000110
```

### IPv4 Addressing
```
IPv4 = 32 bits = 4 octets
Format: 0-255 . 0-255 . 0-255 . 0-255
Example: 192.168.1.10
```

### Subnet Masks
- **1s** = Network bits
- **0s** = Host bits

| CIDR | Mask | Network Bits | Host Bits | Usable Hosts |
|------|------|--------------|-----------|--------------|
| /8 | 255.0.0.0 | 8 | 24 | 16,777,214 |
| /16 | 255.255.0.0 | 16 | 16 | 65,534 |
| /24 | 255.255.255.0 | 24 | 8 | 254 |
| /25 | 255.255.255.128 | 25 | 7 | 126 |
| /26 | 255.255.255.192 | 26 | 6 | 62 |
| /30 | 255.255.255.252 | 30 | 2 | 2 |

**Formula:** Usable Hosts = 2^(host bits) - 2

### Subnetting Example
```
/24 → borrow 1 bit → /25 → 2 subnets, 126 hosts each
192.168.1.0/25   → hosts 1-126
192.168.1.128/25 → hosts 129-254

/24 → borrow 2 bits → /26 → 4 subnets, 62 hosts each
192.168.1.0/26   → hosts 1-62
192.168.1.64/26  → hosts 65-126
192.168.1.128/26 → hosts 129-190
192.168.1.192/26 → hosts 193-254
```

### Internet Governance
```
IANA (Internet Assigned Numbers Authority)
  └── RIRs (Regional Internet Registries)
       ├── APNIC (Asia-Pacific)
       ├── ARIN (North America)
       ├── RIPE NCC (Europe)
       ├── LACNIC (Latin America)
       └── AFRINIC (Africa)
           └── NIRs (National)
               └── ISPs
                   └── End Users
```

### MAC Addresses
```
48 bits = 6 octets (hexadecimal)
Format: XX:XX:XX:XX:XX:XX
Example: 00:1A:2B:3C:4D:5E

First 3 octets: OUI (Manufacturer)
Last 3 octets: Device ID
```

### Key Commands You Know
```bash
# DNS lookup
nslookup google.com

# Trace route
traceroute 8.8.8.8

# AS (Autonomous System) lookup
whois AS15169
```

### BGP & DNS
- **BGP** = Border Gateway Protocol (routes between ASes)
- **DNS** = 13 root servers (A through M)
- **Internet Exchange** = Where networks peer

---

## Communication Types

| Type | Description | Example |
|------|-------------|---------|
| **Unicast** | One-to-one | Web request to server |
| **Multicast** | One-to-many (group) | Video streaming to subscribers |
| **Broadcast** | One-to-all | DHCP discovery |

---

## What You Need to Learn Next

Based on this foundation, here's what to focus on:

### 1. OSI Layers 3-4 (Depth)
- [x] IP addressing basics ✓
- [ ] IP header structure
- [ ] TCP 3-way handshake
- [ ] TCP state machine
- [ ] UDP characteristics

### 2. NAT & Routing
- [ ] SNAT vs DNAT
- [ ] Masquerading
- [ ] Routing tables
- [ ] Policy routing
- [ ] Multiple routing tables

### 3. Connection Tracking
- [ ] conntrack basics
- [ ] CONNMARK
- [ ] State persistence

### 4. iptables
- [ ] Tables and chains
- [ ] Packet marking
- [ ] NAT rules

### 5. Go Networking
- [ ] net package
- [ ] TCP/UDP sockets
- [ ] Interface binding
- [ ] ICMP (ping)

---

## Resources Mapped to Your Level

### Books (Start with)
1. **"TCP/IP Illustrated, Vol 1"** - W. Richard Stevens
   - Best for deep protocol understanding
   
2. **"Computer Networking: A Top-Down Approach"**
   - Start from Chapter 3 (Transport Layer)

### Hands-On Tools
```bash
# Already know nslookup, traceroute
# Add these:
ip route show           # Routing tables
ip rule list           # Policy routing
conntrack -L           # Connection tracking
iptables -L -v -n      # Firewall rules
tcpdump -i any         # Packet capture
```

### Online Deep-Dives
- Linux Advanced Routing (lartc.org)
- Netfilter/iptables docs
- bgp.he.net (BGP exploration)

---

## Quick Reference Cards

### IP Header (Key Fields)
```
| Version | IHL | TOS | Total Length |
| ID | Flags | Fragment Offset |
| TTL | Protocol | Checksum |
| Source IP |
| Destination IP |
```

### TCP Header (Key Fields)
```
| Source Port | Dest Port |
| Sequence Number |
| Acknowledgment Number |
| Flags (SYN,ACK,FIN,RST) | Window |
```

### 5-Tuple (Connection ID)
```
Src IP + Src Port + Dst IP + Dst Port + Protocol
Example: 10.0.0.50:49152 → 8.8.8.8:443 (TCP)
```

### iptables Tables
```
raw     → Skip conntrack
mangle  → Modify packets (MARK) ⭐
nat     → Address translation ⭐
filter  → Accept/drop (firewall)
```

---

This reference card summarizes your existing knowledge and points to where you need to go next. Use it as a foundation as you work through the teaching modules!
