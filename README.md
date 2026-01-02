# Cloud-Native Network Programming

[![Learning Path](https://img.shields.io/badge/Timeline-6--8%20months-blue)]()
[![Core Tech](https://img.shields.io/badge/Core-eBPF%20%7C%20XDP%20%7C%20Go-green)]()
[![Level](https://img.shields.io/badge/Level-Intermediate%20to%20Advanced-orange)]()

A comprehensive learning path for mastering cloud-native networking with **eBPF, XDP, and Kubernetes networking**.

## 📊 Concept Overview

![Network Concepts Overview](./teaching/images/network_concepts_overview.png)

## 🎯 Goal

Build production-ready cloud networking tools like **Cilium**, **Traefik**, or **CoreDNS**.

## 📚 Primary Resource

> **"Learning eBPF" by Liz Rice** → `Learning eBPF New Version.pdf`

## 📖 Learning Modules

### Core Networking (Modules 0-7)

| # | Module | Description |
|---|--------|-------------|
| 0 | [Roadmap Validation](./teaching/00-roadmap-validation.md) | Assessment & learning path |
| 1 | [OSI Model Deep Dive](./teaching/01-osi-model-deep-dive.md) | Layers 3-4, TCP/UDP, 5-tuple |
| 2 | [NAT & Routing](./teaching/02-nat-and-routing.md) | SNAT, DNAT, policy routing |
| 3 | [Connection Tracking](./teaching/03-connection-tracking.md) | conntrack, CONNMARK |
| 4 | [iptables Mastery](./teaching/04-iptables-mastery.md) | Tables, chains, packet marking |
| 5 | [Go Networking](./teaching/05-go-networking.md) | TCP/UDP, ICMP, health checks |
| 6 | [eBPF Fundamentals](./teaching/06-ebpf-fundamentals.md) | XDP, TC, maps, verifier |
| 7 | [Quick Reference](./teaching/07-quick-reference.md) | Commands & code snippets |

### Advanced eBPF (Modules 8-14) 🆕

| # | Module | Description |
|---|--------|-------------|
| 8 | [eBPF VM Deep Dive](./teaching/08-ebpf-vm-deep-dive.md) | Registers, instructions, JIT, verifier |
| 9 | [eBPF Maps Mastery](./teaching/09-ebpf-maps-mastery.md) | All map types, ring buffer, rate limiter |
| 10 | [CO-RE & BTF](./teaching/10-core-btf-portability.md) | Portable programs, vmlinux.h, BPF_CORE_READ |
| 11 | [eBPF Networking Guide](./teaching/11-ebpf-networking-guide.md) | Complete packet flow, XDP vs TC, load balancer |
| 12 | [eBPF Security](./teaching/12-ebpf-security.md) | LSM BPF, seccomp, observability, Tetragon |
| 13 | [Socket Programming](./teaching/13-socket-programming.md) | Socket filters, sockops, sk_msg, SOCKMAP, cgroup BPF |
| 14 | [Go Development](./teaching/14-go-development.md) | cilium/ebpf, bpf2go, debugging, testing, IDE setup |

## 🗺️ Complete Roadmap

See [network-roadmap.md](./network-roadmap.md) for the full 6-8 month learning roadmap.

## 🚀 Quick Start

1. Start with **Module 0** to assess your current knowledge
2. Work through modules **1-5** for Linux networking fundamentals
3. Read the **Learning eBPF** book alongside **Module 6**
4. Use **Module 7** as a reference while practicing

## 💼 Career Outcomes

- Cloud Network Engineer
- eBPF Engineer ($150K-$300K+)
- Kubernetes Networking Specialist
- Open Source Contributor (Cilium, Calico, Falco)

---

*Happy learning! 🎓*
