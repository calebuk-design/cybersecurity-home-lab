
# Lab Setup Guide

## Overview
This document describes the virtual lab environment used for cybersecurity practice exercises.

## Virtual Machines

### Host Machine
- OS: Windows / macOS / Linux
- Hypervisor: VirtualBox or VMware Workstation
- RAM allocated to VMs: 8GB+

### VM 1 — Windows Server (Target)
- OS: Windows Server 2019/2022 (Evaluation)
- Role: Active Directory, file server, log source
- IP: 192.168.56.10 (host-only network)
- Tools installed: Splunk Universal Forwarder

### VM 2 — Kali Linux (Analysis/Attacker)
- OS: Kali Linux (latest)
- Role: Network scanning, traffic analysis
- IP: 192.168.56.20 (host-only network)
- Tools: Nmap, Wireshark, Metasploit

## Network Configuration

```
Host-Only Network: 192.168.56.0/24
Gateway: 192.168.56.1

VM1 - Windows Server: 192.168.56.10
VM2 - Kali Linux:     192.168.56.20
```

## Splunk Setup
1. Download Splunk Free from https://www.splunk.com
2. Install on Windows Server VM
3. Configure data inputs: Windows Event Logs (Security, System, Application)
4. Access Splunk Web UI at http://192.168.56.10:8000

## Wireshark Setup
1. Install Wireshark on Kali VM
2. Select the host-only network adapter for captures
3. Apply capture filters as needed (see `/network-analysis/wireshark-notes.md`)
