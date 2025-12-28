# Module 6: Building the Multi-WAN Load Balancer

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MULTI-WAN LOAD BALANCER                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │   Config    │  │    Health    │  │   Routing   │  │   Metrics    │  │
│  │   Manager   │  │   Monitor    │  │   Engine    │  │  Collector   │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘  │
│         │                │                 │                 │         │
│         └────────────────┴────────┬────────┴─────────────────┘         │
│                                   │                                     │
│                          ┌────────▼────────┐                           │
│                          │   Core Engine   │                           │
│                          └────────┬────────┘                           │
│                                   │                                     │
│              ┌────────────────────┼────────────────────┐               │
│              │                    │                    │               │
│    ┌─────────▼─────────┐ ┌───────▼───────┐ ┌─────────▼─────────┐     │
│    │   iptables Mgr    │ │  conntrack    │ │    Route Mgr      │     │
│    │  (go-iptables)    │ │ (go-conntrack)│ │   (netlink)       │     │
│    └───────────────────┘ └───────────────┘ └───────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │   Linux Kernel    │
                          │ (netfilter/routing)│
                          └───────────────────┘
```

---

## Project Structure

```
multiwan-loadbalancer/
├── cmd/
│   ├── daemon/
│   │   └── main.go          # Main daemon entry
│   └── cli/
│       └── main.go          # CLI tool
├── internal/
│   ├── config/
│   │   └── config.go        # Configuration loading
│   ├── health/
│   │   ├── monitor.go       # Health monitoring
│   │   └── ping.go          # ICMP/HTTP checks
│   ├── routing/
│   │   ├── engine.go        # Routing decisions
│   │   ├── table.go         # Route table management
│   │   └── policy.go        # Policy routing
│   ├── netlink/
│   │   ├── route.go         # Route manipulation
│   │   └── rule.go          # IP rules
│   ├── iptables/
│   │   ├── manager.go       # iptables control
│   │   └── rules.go         # Rule definitions
│   ├── conntrack/
│   │   └── tracker.go       # Connection tracking
│   └── metrics/
│       └── collector.go     # Metrics collection
├── pkg/
│   └── api/
│       ├── server.go        # REST API
│       └── handlers.go      # API handlers
├── web/                     # React dashboard
├── configs/
│   └── config.yaml          # Configuration
└── go.mod
```

---

## Core Components Implementation

### 1. Configuration

```go
// internal/config/config.go
package config

import (
    "os"
    "time"
    
    "gopkg.in/yaml.v3"
)

type Config struct {
    ISPs      []ISPConfig     `yaml:"isps"`
    LAN       LANConfig       `yaml:"lan"`
    Routing   RoutingConfig   `yaml:"routing"`
    Policies  []PolicyConfig  `yaml:"policies"`
    API       APIConfig       `yaml:"api"`
    Metrics   MetricsConfig   `yaml:"metrics"`
}

type ISPConfig struct {
    Name        string          `yaml:"name"`
    Interface   string          `yaml:"interface"`
    Gateway     string          `yaml:"gateway"`
    Weight      float64         `yaml:"weight"`
    TableID     int             `yaml:"table_id"`
    Mark        int             `yaml:"mark"`
    HealthCheck HealthCheckConfig `yaml:"health_check"`
}

type HealthCheckConfig struct {
    Targets   []string      `yaml:"targets"`
    Interval  time.Duration `yaml:"interval"`
    Timeout   time.Duration `yaml:"timeout"`
    Threshold int           `yaml:"threshold"`
}

type RoutingConfig struct {
    Algorithm        string  `yaml:"algorithm"` // weighted, round-robin, least-conn
    FailoverEnabled  bool    `yaml:"failover_enabled"`
    FailoverThreshold float64 `yaml:"failover_threshold"`
}

type PolicyConfig struct {
    Name      string     `yaml:"name"`
    Priority  int        `yaml:"priority"`
    Match     MatchConfig `yaml:"match"`
    RouteVia  string     `yaml:"route_via"`
}

type MatchConfig struct {
    SourceIPs   []string `yaml:"source_ips"`
    DestPorts   []int    `yaml:"dest_ports"`
    Domains     []string `yaml:"domains"`
    Protocols   []string `yaml:"protocols"`
}

func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    
    return &cfg, nil
}
```

### 2. Health Monitor

```go
// internal/health/monitor.go
package health

import (
    "context"
    "sync"
    "time"
    
    "multiwan/internal/config"
)

type ISPHealth struct {
    Name       string
    IsUp       bool
    Latency    time.Duration
    PacketLoss float64
    LastCheck  time.Time
}

type Monitor struct {
    cfg         *config.Config
    states      map[string]*ISPHealth
    mu          sync.RWMutex
    updates     chan ISPHealth
    consecutiveFails map[string]int
}

func NewMonitor(cfg *config.Config) *Monitor {
    m := &Monitor{
        cfg:              cfg,
        states:           make(map[string]*ISPHealth),
        updates:          make(chan ISPHealth, 10),
        consecutiveFails: make(map[string]int),
    }
    
    // Initialize states
    for _, isp := range cfg.ISPs {
        m.states[isp.Name] = &ISPHealth{
            Name: isp.Name,
            IsUp: true, // Assume up initially
        }
    }
    
    return m
}

func (m *Monitor) Start(ctx context.Context) {
    for _, isp := range m.cfg.ISPs {
        go m.monitorISP(ctx, isp)
    }
}

func (m *Monitor) monitorISP(ctx context.Context, isp config.ISPConfig) {
    ticker := time.NewTicker(isp.HealthCheck.Interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            health := m.checkHealth(isp)
            m.updateState(isp.Name, health)
            m.updates <- *health
        }
    }
}

func (m *Monitor) checkHealth(isp config.ISPConfig) *ISPHealth {
    var totalLatency time.Duration
    var successCount int
    
    for _, target := range isp.HealthCheck.Targets {
        latency, err := PingViaInterface(target, isp.Interface, isp.HealthCheck.Timeout)
        if err == nil {
            successCount++
            totalLatency += latency
        }
    }
    
    totalTargets := len(isp.HealthCheck.Targets)
    packetLoss := float64(totalTargets-successCount) / float64(totalTargets) * 100
    
    var avgLatency time.Duration
    if successCount > 0 {
        avgLatency = totalLatency / time.Duration(successCount)
    }
    
    // Determine if ISP is up based on threshold
    isUp := successCount > 0
    
    return &ISPHealth{
        Name:       isp.Name,
        IsUp:       isUp,
        Latency:    avgLatency,
        PacketLoss: packetLoss,
        LastCheck:  time.Now(),
    }
}

func (m *Monitor) updateState(name string, health *ISPHealth) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    oldState := m.states[name]
    m.states[name] = health
    
    // Track consecutive failures
    if !health.IsUp {
        m.consecutiveFails[name]++
    } else {
        m.consecutiveFails[name] = 0
    }
    
    // Log state changes
    if oldState.IsUp != health.IsUp {
        if health.IsUp {
            log.Info().Str("isp", name).Msg("ISP recovered")
        } else {
            log.Warn().Str("isp", name).Msg("ISP failed")
        }
    }
}

func (m *Monitor) GetState(name string) *ISPHealth {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.states[name]
}

func (m *Monitor) GetAllStates() map[string]*ISPHealth {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    result := make(map[string]*ISPHealth)
    for k, v := range m.states {
        result[k] = v
    }
    return result
}

func (m *Monitor) Updates() <-chan ISPHealth {
    return m.updates
}
```

### 3. Routing Engine

```go
// internal/routing/engine.go
package routing

import (
    "sync"
    "sync/atomic"
    
    "multiwan/internal/config"
    "multiwan/internal/health"
)

type Engine struct {
    cfg           *config.Config
    healthMonitor *health.Monitor
    connections   *ConnectionTable
    roundRobinIdx uint64
    mu            sync.RWMutex
}

type Connection struct {
    SrcIP    string
    SrcPort  uint16
    DstIP    string
    DstPort  uint16
    Protocol string
}

type RoutingDecision struct {
    Connection Connection
    ISP        string
    Mark       int
    Reason     string
}

func NewEngine(cfg *config.Config, hm *health.Monitor) *Engine {
    return &Engine{
        cfg:           cfg,
        healthMonitor: hm,
        connections:   NewConnectionTable(),
    }
}

func (e *Engine) Route(conn Connection) RoutingDecision {
    // 1. Check if connection already tracked
    if isp, exists := e.connections.Get(conn); exists {
        return RoutingDecision{
            Connection: conn,
            ISP:        isp,
            Mark:       e.getMarkForISP(isp),
            Reason:     "Existing connection",
        }
    }
    
    // 2. Check policies
    for _, policy := range e.cfg.Policies {
        if e.matchPolicy(conn, policy) {
            e.connections.Set(conn, policy.RouteVia)
            return RoutingDecision{
                Connection: conn,
                ISP:        policy.RouteVia,
                Mark:       e.getMarkForISP(policy.RouteVia),
                Reason:     "Policy: " + policy.Name,
            }
        }
    }
    
    // 3. Use configured algorithm
    var decision RoutingDecision
    
    switch e.cfg.Routing.Algorithm {
    case "weighted":
        decision = e.weightedRouting(conn)
    case "round-robin":
        decision = e.roundRobinRouting(conn)
    case "least-connections":
        decision = e.leastConnectionsRouting(conn)
    case "latency":
        decision = e.latencyBasedRouting(conn)
    default:
        decision = e.weightedRouting(conn)
    }
    
    // Store decision
    e.connections.Set(conn, decision.ISP)
    
    return decision
}

func (e *Engine) weightedRouting(conn Connection) RoutingDecision {
    connCounts := e.connections.CountPerISP()
    
    var selectedISP string
    minRatio := float64(999999)
    
    for _, isp := range e.cfg.ISPs {
        // Skip unhealthy ISPs
        state := e.healthMonitor.GetState(isp.Name)
        if !state.IsUp {
            continue
        }
        
        count := connCounts[isp.Name]
        ratio := float64(count) / isp.Weight
        
        if ratio < minRatio {
            minRatio = ratio
            selectedISP = isp.Name
        }
    }
    
    // Fallback if all ISPs down
    if selectedISP == "" {
        selectedISP = e.cfg.ISPs[0].Name
    }
    
    return RoutingDecision{
        Connection: conn,
        ISP:        selectedISP,
        Mark:       e.getMarkForISP(selectedISP),
        Reason:     "Weighted distribution",
    }
}

func (e *Engine) roundRobinRouting(conn Connection) RoutingDecision {
    healthyISPs := e.getHealthyISPs()
    if len(healthyISPs) == 0 {
        healthyISPs = e.cfg.ISPs // Fallback to all
    }
    
    idx := atomic.AddUint64(&e.roundRobinIdx, 1)
    selected := healthyISPs[int(idx)%len(healthyISPs)]
    
    return RoutingDecision{
        Connection: conn,
        ISP:        selected.Name,
        Mark:       selected.Mark,
        Reason:     "Round-robin",
    }
}

func (e *Engine) latencyBasedRouting(conn Connection) RoutingDecision {
    var bestISP string
    var bestLatency = time.Hour
    
    for _, isp := range e.cfg.ISPs {
        state := e.healthMonitor.GetState(isp.Name)
        if state.IsUp && state.Latency < bestLatency {
            bestLatency = state.Latency
            bestISP = isp.Name
        }
    }
    
    return RoutingDecision{
        Connection: conn,
        ISP:        bestISP,
        Mark:       e.getMarkForISP(bestISP),
        Reason:     fmt.Sprintf("Lowest latency (%v)", bestLatency),
    }
}

func (e *Engine) getHealthyISPs() []config.ISPConfig {
    var healthy []config.ISPConfig
    for _, isp := range e.cfg.ISPs {
        state := e.healthMonitor.GetState(isp.Name)
        if state.IsUp {
            healthy = append(healthy, isp)
        }
    }
    return healthy
}

func (e *Engine) getMarkForISP(name string) int {
    for _, isp := range e.cfg.ISPs {
        if isp.Name == name {
            return isp.Mark
        }
    }
    return 0
}
```

### 4. Connection Table

```go
// internal/routing/table.go
package routing

import (
    "sync"
    "time"
)

type connectionEntry struct {
    ISP       string
    CreatedAt time.Time
    LastSeen  time.Time
}

type ConnectionTable struct {
    entries map[string]*connectionEntry
    mu      sync.RWMutex
}

func NewConnectionTable() *ConnectionTable {
    ct := &ConnectionTable{
        entries: make(map[string]*connectionEntry),
    }
    
    // Start cleanup goroutine
    go ct.cleanup()
    
    return ct
}

func (ct *ConnectionTable) key(conn Connection) string {
    return fmt.Sprintf("%s:%d-%s:%d-%s",
        conn.SrcIP, conn.SrcPort,
        conn.DstIP, conn.DstPort,
        conn.Protocol)
}

func (ct *ConnectionTable) Set(conn Connection, isp string) {
    ct.mu.Lock()
    defer ct.mu.Unlock()
    
    k := ct.key(conn)
    if entry, exists := ct.entries[k]; exists {
        entry.LastSeen = time.Now()
    } else {
        ct.entries[k] = &connectionEntry{
            ISP:       isp,
            CreatedAt: time.Now(),
            LastSeen:  time.Now(),
        }
    }
}

func (ct *ConnectionTable) Get(conn Connection) (string, bool) {
    ct.mu.RLock()
    defer ct.mu.RUnlock()
    
    if entry, exists := ct.entries[ct.key(conn)]; exists {
        return entry.ISP, true
    }
    return "", false
}

func (ct *ConnectionTable) CountPerISP() map[string]int {
    ct.mu.RLock()
    defer ct.mu.RUnlock()
    
    counts := make(map[string]int)
    for _, entry := range ct.entries {
        counts[entry.ISP]++
    }
    return counts
}

func (ct *ConnectionTable) cleanup() {
    ticker := time.NewTicker(1 * time.Minute)
    for range ticker.C {
        ct.mu.Lock()
        
        threshold := time.Now().Add(-30 * time.Minute)
        for k, entry := range ct.entries {
            if entry.LastSeen.Before(threshold) {
                delete(ct.entries, k)
            }
        }
        
        ct.mu.Unlock()
    }
}
```

---

## Main Daemon

```go
// cmd/daemon/main.go
package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"
    
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
    
    "multiwan/internal/config"
    "multiwan/internal/health"
    "multiwan/internal/routing"
    "multiwan/internal/iptables"
    "multiwan/pkg/api"
)

func main() {
    // Setup logging
    log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
        With().Timestamp().Logger()
    
    // Load config
    cfg, err := config.Load("/etc/multiwan/config.yaml")
    if err != nil {
        log.Fatal().Err(err).Msg("Failed to load config")
    }
    
    log.Info().Msg("Starting Multi-WAN Load Balancer")
    
    // Create context for graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Initialize components
    healthMonitor := health.NewMonitor(cfg)
    routingEngine := routing.NewEngine(cfg, healthMonitor)
    iptablesMgr := iptables.NewManager(cfg)
    
    // Setup initial routing
    if err := iptablesMgr.Setup(); err != nil {
        log.Fatal().Err(err).Msg("Failed to setup iptables")
    }
    
    // Start health monitoring
    healthMonitor.Start(ctx)
    
    // Handle health updates
    go func() {
        for update := range healthMonitor.Updates() {
            log.Info().
                Str("isp", update.Name).
                Bool("up", update.IsUp).
                Dur("latency", update.Latency).
                Float64("loss", update.PacketLoss).
                Msg("Health update")
            
            // Handle failover if needed
            if !update.IsUp && cfg.Routing.FailoverEnabled {
                iptablesMgr.HandleFailover(update.Name)
            }
        }
    }()
    
    // Start API server
    if cfg.API.Enabled {
        go api.StartServer(cfg, healthMonitor, routingEngine)
    }
    
    log.Info().Msg("Load balancer running")
    
    // Wait for shutdown signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    
    log.Info().Msg("Shutting down...")
    cancel()
    
    // Cleanup
    iptablesMgr.Cleanup()
    
    log.Info().Msg("Shutdown complete")
}
```

---

## Next Steps After This Module

1. **Setup Lab Environment**
   - Linux VM with 2+ network interfaces
   - Or Raspberry Pi as gateway

2. **Implement Phase by Phase**
   - Start with health monitoring only
   - Add failover
   - Add weighted distribution
   - Add policies

3. **Test Thoroughly**
   - Disconnect cables to test failover
   - Run bandwidth tests per ISP
   - Verify connection persistence

4. **Build Dashboard**
   - Use your React skills
   - WebSocket for real-time updates
   - Visualize bandwidth and latency

---

## Key Takeaways

1. **Modular architecture** makes testing easier
2. **Health monitoring** is the foundation
3. **Connection persistence** is critical for TCP
4. **iptables MARK + CONNMARK** bridge Go logic to kernel routing
5. **Start simple**, iterate to complex

Good luck building your load balancer! 🚀
