# Network Systems Developer Roadmap - Complete Guide

**Target:** Frontend developers (JS/TS/React/Next.js) with Go knowledge wanting to build network systems tools

**Timeline:** 4-6 months (10-15 hours/week)

**Goal:** Build production-ready multi-WAN load balancer

---

## PART I: LEARNING ROADMAP

### Phase 1: Network Fundamentals (2-3 weeks)

**Objectives:**
- OSI model layers 3-4 (IP, TCP/UDP)
- Routing tables, NAT, packet flow
- Connection tracking (conntrack)
- Policy routing

**Key Concepts:**
- IP addressing, subnetting, CIDR
- TCP: 3-way handshake, state machine, connection tracking
- UDP: connectionless, use cases
- NAT: SNAT, DNAT, masquerading
- Routing: tables, metrics, default gateway

**Exercises:**
1. Use Wireshark to capture HTTP traffic, identify TCP handshake
2. Examine home router routing table
3. Practice: `ip route show`, `ip addr show`, `conntrack -L`
4. Trace connections with `traceroute` and `mtr`

**Resources:**
- "Computer Networking: A Top-Down Approach" (Chapters 3-4)
- "TCP/IP Illustrated, Vol 1" by Stevens
- Wireshark tutorials
- Linux man pages: `man ip`, `man iptables`

---

### Phase 2: Go Network Programming (2-3 weeks)

**Objectives:**
- Master `net` package
- TCP/UDP socket programming
- Connection management, timeouts
- HTTP internals

**Projects:**
1. Port scanner (scan ports 1-1024)
2. TCP echo server (concurrent connections)
3. UDP chat app (peer-to-peer)
4. HTTP proxy (forward + modify headers)
5. Connection pool implementation

**Code Example - TCP Server:**
```go
listener, _ := net.Listen("tcp", ":8080")
for {
    conn, _ := listener.Accept()
    go handleConnection(conn)
}
```

**Key Packages:**
- `net` - networking
- `net/http` - HTTP
- `context` - cancellation/timeouts
- `io` - I/O operations

---

### Phase 3: Raw Sockets & Packet Manipulation (3-4 weeks)

**Objectives:**
- Raw socket programming
- Parse/construct packets
- iptables mastery
- Multi-table routing

**Projects:**
1. Packet sniffer (display src/dst IPs, ports)
2. TCP proxy with packet modification
3. Basic NAT implementation
4. Rule-based packet router

**Linux Commands to Master:**
```bash
# Routing
ip route show table all
ip route add default via 192.168.1.1 table 100
ip rule add fwmark 1 table 100

# iptables
iptables -t mangle -L -v -n
iptables -t mangle -A PREROUTING -s 10.0.0.50 -j MARK --set-mark 1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Connection tracking
conntrack -L
conntrack -L -p tcp
```

**Go Packages:**
- `github.com/google/gopacket` - packet manipulation
- `golang.org/x/net/ipv4` - IPv4 operations
- `github.com/vishvananda/netlink` - netlink API
- `github.com/coreos/go-iptables` - iptables control

---

### Phase 4: Multi-WAN Architecture (4-5 weeks)

**Load Balancing Strategies:**

1. **Failover** - Primary + backup (simplest)
2. **Round-robin** - Alternate between ISPs
3. **Weighted** - Distribute by bandwidth ratio (70/30)
4. **Least connections** - Route to ISP with fewer connections
5. **Latency-based** - Choose ISP with lower RTT
6. **Application-aware** - Route by domain/port/protocol

**Critical: Per-Connection Persistence**
- Once assigned, connection MUST stay on same ISP
- Prevents breaking TCP, SSL, auth sessions

**Implementation Versions:**

**V1: Basic Failover (Week 1-2)**
- Health monitoring (ping ISPs every 5s)
- Detect failure (3 consecutive fails)
- Switch default route
- Restore when recovered

**V2: Connection Tracking (Week 2-3)**
- Track connections in memory
- Assign ISP on first packet
- Persist throughout lifetime
- Use iptables MARK + conntrack

**V3: Weighted Distribution (Week 3-4)**
- Configure weight ratios (e.g., 0.7, 0.3)
- Count connections per ISP
- Route to ISP with lowest (connections/weight)

**V4: Application-Aware (Week 4-5)**
- Policy configuration (YAML)
- Match by domain, port, source IP
- Priority system for conflicts
- DNS integration

---

### Phase 5: Advanced Features (3-4 weeks)

**Features:**
1. **Connection Persistence** - Track in memory + disk
2. **Intelligent Routing** - Measure RTT, choose best path
3. **Bandwidth Monitoring** - Track usage per ISP, quotas
4. **Quality Metrics** - Packet loss, jitter, latency
5. **DNS-aware** - Route based on resolved domain

**Optimizations:**
- Minimize routing table lookups
- Efficient connection state management
- Lock-free data structures
- Goroutine pooling for health checks

---

### Phase 6: Production & UI (3-4 weeks)

**Management Interface:**
- REST API (status, config, control)
- React dashboard (real-time WebSocket updates)
- CLI tool (command-line management)
- YAML configuration files

**Observability:**
- Structured logging (zerolog/zap)
- Prometheus metrics export
- Health check endpoints
- Historical data storage

**Deployment:**
- Systemd service
- Docker container
- Installation script
- Backup/restore functionality

---

## PART II: TECHNICAL ARCHITECTURE

### System Topology

```
Internet ISP1 (192.168.1.1) ──┐
                               ├─→ [Linux Gateway] ──→ Home Network (10.0.0.0/24)
Internet ISP2 (192.168.2.1) ──┘    (Go Load Balancer)
```

### Hardware Requirements

**Minimum:**
- Dual-core 1GHz CPU
- 512MB RAM
- 3× Ethernet ports
- 4GB storage

**Recommended:**
- Quad-core 1.5GHz+ CPU
- 1GB+ RAM
- 3× Gigabit Ethernet
- 16GB+ storage
- Raspberry Pi 4 (4GB) perfect for home use (~$100)

### Core Components

1. **Health Monitor** - Ping ISPs, measure latency/loss
2. **Connection Tracker** - Maintain connection-to-ISP mapping
3. **Routing Engine** - Make routing decisions
4. **Route Manager** - Update iptables + routing tables
5. **Policy Manager** - Apply user-defined rules
6. **Metrics Collector** - Bandwidth, latency, connections
7. **API Server** - REST API for management
8. **Web Dashboard** - React UI

---

## PART III: IMPLEMENTATION GUIDE

### Project Structure

```
multiwan-loadbalancer/
├── cmd/
│   ├── daemon/          # Main daemon
│   └── cli/             # CLI tool
├── internal/
│   ├── health/          # Health monitoring
│   ├── conntrack/       # Connection tracking
│   ├── routing/         # Routing engine
│   ├── policy/          # Policy management
│   └── netlink/         # Linux netlink interface
├── pkg/
│   ├── config/          # Configuration
│   └── api/             # REST API
├── web/                 # React dashboard
├── configs/
│   └── config.yaml      # Configuration
└── scripts/
    └── install.sh       # Installation
```

### Health Monitor Implementation

```go
package health

type Monitor struct {
    isps    []ISP
    states  map[string]*ISPHealth
    updates chan HealthUpdate
}

type ISPHealth struct {
    IsUp          bool
    PacketLoss    float64
    AvgLatency    time.Duration
    LastCheck     time.Time
}

func (m *Monitor) monitorISP(ctx context.Context, isp ISP) {
    ticker := time.NewTicker(5 * time.Second)
    for {
        select {
        case <-ticker.C:
            health := m.checkHealth(isp)
            m.updateState(isp.Name, health)
        case <-ctx.Done():
            return
        }
    }
}

func (m *Monitor) checkHealth(isp ISP) *ISPHealth {
    var totalLatency time.Duration
    var successCount int
    
    for _, target := range isp.Targets {
        start := time.Now()
        err := m.ping(target, isp.Interface)
        latency := time.Since(start)
        
        if err == nil {
            successCount++
            totalLatency += latency
        }
    }
    
    packetLoss := float64(len(isp.Targets)-successCount) / 
                  float64(len(isp.Targets)) * 100
    
    return &ISPHealth{
        IsUp:       successCount > 0,
        PacketLoss: packetLoss,
        AvgLatency: totalLatency / time.Duration(successCount),
        LastCheck:  time.Now(),
    }
}
```

### Routing Engine Implementation

```go
package routing

type Engine struct {
    cfg         *config.Config
    connections *ConnectionTable
}

func (e *Engine) RouteConnection(conn Connection) RoutingDecision {
    // Check policy first
    if policy := e.cfg.Policies.Match(conn); policy != nil {
        return RoutingDecision{
            Connection: conn,
            ISP:        policy.RouteVia,
            Reason:     "Policy: " + policy.Name,
        }
    }
    
    // Use algorithm
    switch e.cfg.Algorithm {
    case "weighted":
        return e.weightedRouting(conn)
    case "least-connections":
        return e.leastConnectionsRouting(conn)
    default:
        return e.roundRobinRouting(conn)
    }
}

func (e *Engine) weightedRouting(conn Connection) RoutingDecision {
    weights := e.cfg.ISPWeights
    connCounts := e.connections.CountPerISP()
    
    var selectedISP string
    minRatio := float64(99999)
    
    for isp, weight := range weights {
        ratio := float64(connCounts[isp]) / weight
        if ratio < minRatio {
            minRatio = ratio
            selectedISP = isp
        }
    }
    
    return RoutingDecision{
        Connection: conn,
        ISP:        selectedISP,
        Reason:     "Weighted distribution",
    }
}
```

### Linux Network Setup

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Setup routing tables
# /etc/iproute2/rt_tables
100 isp1_table
200 isp2_table

# Configure ISP1 table
ip route add default via 192.168.1.1 dev eth0 table isp1_table
ip route add 192.168.1.0/24 dev eth0 table isp1_table

# Configure ISP2 table
ip route add default via 192.168.2.1 dev eth1 table isp2_table
ip route add 192.168.2.0/24 dev eth1 table isp2_table

# Policy routing rules
ip rule add fwmark 1 table isp1_table priority 100
ip rule add fwmark 2 table isp2_table priority 100

# NAT masquerading
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

# Connection tracking
iptables -t mangle -A PREROUTING -m conntrack --ctstate NEW \
    -m statistic --mode random --probability 0.7 \
    -j MARK --set-mark 1

iptables -t mangle -A PREROUTING -j CONNMARK --save-mark

iptables -t mangle -A PREROUTING \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j CONNMARK --restore-mark
```

### Configuration File (config.yaml)

```yaml
isps:
  - name: isp1
    interface: eth0
    gateway: 192.168.1.1
    weight: 0.7
    health_check:
      targets: [8.8.8.8, 1.1.1.1]
      interval: 5s
      timeout: 2s
      
  - name: isp2
    interface: eth1
    gateway: 192.168.2.1
    weight: 0.3
    health_check:
      targets: [8.8.8.8, 1.1.1.1]
      interval: 5s
      timeout: 2s

lan:
  interface: eth2
  network: 10.0.0.0/24

routing:
  algorithm: weighted
  failover_enabled: true
  failover_threshold: 50

policies:
  - name: Gaming Traffic
    priority: 100
    match:
      source_ips: [10.0.0.25]
      dest_ports: [3074, 27015]
    route_via: isp1
    
  - name: Video Streaming
    priority: 90
    match:
      domains: [netflix.com, youtube.com]
    route_via: isp2

api:
  enabled: true
  port: 8080

metrics:
  enabled: true
  prometheus_port: 9090
```

---

## PART IV: MILESTONE PROJECTS

### Month 1: Foundation & Simple Failover

**Goal:** Health monitoring with automatic failover

**Deliverables:**
- Ping both ISPs every 5 seconds
- Detect failure (3 consecutive fails)
- Switch default route to secondary
- Restore primary when recovered
- Log all state changes

**Testing:**
- Disconnect primary ISP, verify failover
- Reconnect, verify restoration

---

### Month 2: Connection Tracking

**Goal:** Per-connection ISP assignment

**Deliverables:**
- Connection tracking table in memory
- Detect new connections via netfilter
- Assign and persist ISP per connection
- Prevent mid-connection switches
- Connection timeout and cleanup

**Testing:**
- Long download stays on same ISP
- Multiple connections distributed
- Test TCP, UDP, ICMP

---

### Month 3: Weighted Load Balancing

**Goal:** Distribute by bandwidth ratio

**Deliverables:**
- Weighted round-robin algorithm
- Configurable weights (70/30)
- Real-time connection counting
- Dynamic adjustment on failure
- Metrics dashboard

**Testing:**
- 100 connections = ~70/30 split
- Measure actual bandwidth per ISP
- Verify adjustment when ISP fails

---

### Month 4: Application-Aware Routing

**Goal:** Route by app/domain/port

**Deliverables:**
- YAML policy configuration
- Domain-based routing (DNS)
- Port-based rules
- Source IP routing
- Priority system

**Testing:**
- Netflix → ISP2 (verify with Wireshark)
- Gaming → ISP1 (measure latency)
- Test policy priorities

---

### Month 5: Web Dashboard

**Goal:** React management interface

**Deliverables:**
- REST API (status, config, control)
- React dashboard (WebSocket real-time)
- Bandwidth/latency graphs
- Connection distribution chart
- Policy editor UI
- System logs viewer

**Features:**
- ISP status cards (up/down, latency, loss)
- Active connections table
- Historical bandwidth graphs
- Live policy editor

---

### Month 6: Production Ready

**Goal:** Deploy and optimize

**Deliverables:**
- Systemd service
- Graceful shutdown
- SQLite metrics storage
- Installation script
- Docker container
- Documentation

**Advanced Features:**
- Bandwidth quotas per ISP
- Time-based policies
- Email/Slack notifications
- Backup/restore config
- Performance optimization

---

## PART V: RESOURCES

### Essential Go Packages

```bash
go get github.com/vishvananda/netlink
go get github.com/google/gopacket
go get github.com/coreos/go-iptables
go get golang.org/x/net/ipv4
go get github.com/gorilla/mux
go get github.com/gorilla/websocket
go get gopkg.in/yaml.v3
go get github.com/rs/zerolog
go get github.com/prometheus/client_golang
```

### Books

- "TCP/IP Illustrated, Volume 1" - W. Richard Stevens
- "The Linux Programming Interface" - Michael Kerrisk
- "Computer Networks" - Andrew Tanenbaum
- "Network Programming with Go" - Jan Newmarch

### Online Resources

- Linux Advanced Routing: https://lartc.org
- Netfilter documentation: https://netfilter.org
- Go networking: https://blog.golang.org
- iptables tutorial: netfilter.org/documentation

### Tools to Master

- Wireshark - Packet analysis
- tcpdump - Command-line capture
- iperf3 - Bandwidth testing
- mtr - Network diagnostics
- conntrack - Connection inspection

### Similar Projects to Study

- mwan3 (OpenWrt) - Multi-WAN package
- pfSense - Open source firewall
- Traefik - Cloud-native proxy
- Cilium - eBPF networking

---

## PART VI: TROUBLESHOOTING

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No internet | IP forwarding disabled | `echo 1 > /proc/sys/net/ipv4/ip_forward` |
| Not distributed | iptables marks missing | `iptables -t mangle -L -v` |
| Connections break | ISP switching | Check conntrack MARK persistence |
| High latency | Wrong gateway | Verify gateway IPs |
| Policies fail | Priority issues | `ip rule list` |

### Debug Commands

```bash
# Check routing
ip route show table all

# Inspect iptables
iptables -t mangle -L -v -n
iptables -t nat -L -v -n

# View connections
conntrack -L | grep ASSURED

# Monitor packets
tcpdump -i any -nn 'not port 22'

# Test routing
ip route get 8.8.8.8
traceroute -n 8.8.8.8
```

---

## TIMELINE SUMMARY

**Total: 4-6 months** (10-15 hours/week)

- **Month 1:** Network fundamentals + Go basics
- **Month 2:** Raw sockets + packet manipulation
- **Month 3:** Core load balancer (failover + tracking)
- **Month 4:** Weighted distribution + policies
- **Month 5:** Web dashboard + API
- **Month 6:** Production features + optimization

---

## NEXT STEPS

1. Start Phase 1 this week
2. Install Wireshark and capture traffic
3. Set up Linux VM for experiments
4. Join Go and networking communities
5. Build incrementally, test frequently

**Your Advantage:** Frontend expertise means you can build:
- Polished web dashboard
- Excellent API design
- User-friendly CLI
- Complete full-stack solution

This combination of low-level networking + frontend polish is rare and valuable!

---

## CAREER OPPORTUNITIES

After completing this project:

- Network Infrastructure Engineer
- DevOps/SRE Engineer (network automation)
- Systems Programmer (networking)
- Open Source Contributor
- Freelance/Consulting (deploy for clients)

**Further Learning:**
- eBPF programming
- Service mesh (Istio, Linkerd)
- SDN (Software Defined Networking)
- High-performance networking (DPDK, XDP)
- Network security (firewalls, IDS/IPS)

---

**Good luck on your journey from frontend developer to network systems engineer!**