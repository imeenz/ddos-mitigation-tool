# DDoS Mitigation Tool

A Rust-based defensive DDoS mitigation tool for monitoring network traffic, detecting anomalies, and automatically blocking suspicious source IP addresses.

The project combines packet capture, statistical anomaly detection, eBPF/XDP, nftables, and a React dashboard.

---

## Contents

- [About](#about)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Technologies](#technologies)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Project](#running-the-project)
- [How Detection Works](#how-detection-works)
- [How Mitigation Works](#how-mitigation-works)
- [eBPF/XDP](#ebpfxdp)
- [Firewall Enforcement](#firewall-enforcement)
- [Dashboard](#dashboard)
- [Testing](#testing)
- [Useful Commands](#useful-commands)
- [Security Notes](#security-notes)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Project Status](#project-status)

---

## About

This project is a defensive network security tool written in Rust.

It captures network traffic, extracts traffic statistics, detects abnormal behavior, generates security alerts, and can automatically mitigate suspicious source IP addresses.

The mitigation layer uses two mechanisms:

- eBPF/XDP for early packet filtering
- nftables for firewall enforcement

A React dashboard provides a live view of traffic, detection events, alerts, and mitigation activity.

The project was developed and tested in a controlled Kali Linux and Metasploitable lab environment.

---

## Features

### Traffic monitoring

- Real-time packet capture
- Packet and byte statistics
- Packets-per-second monitoring
- Bytes-per-second monitoring
- TCP, UDP and ICMP parsing
- Source IP tracking
- Destination port tracking
- Traffic history

### Detection

- Statistical anomaly detection
- Z-score based analysis
- Source IP concentration analysis
- Destination port concentration analysis
- Combined anomaly score
- Security alert generation
- Severity levels

### Mitigation

- Automatic IP blocking
- Configurable mitigation threshold
- Configurable block duration
- Protected IP support
- Automatic block expiration
- Mitigation history

### Enforcement

- eBPF/XDP packet filtering
- nftables firewall enforcement
- Active block tracking
- Automatic recovery after block expiration

---

## Architecture

The main flow of the application is:

```text
                    Network Traffic
                          |
                          v
                +-------------------+
                |   Packet Capture  |
                |   pcap / parser   |
                +---------+---------+
                          |
                          v
                +-------------------+
                |   Traffic Stats   |
                | packets / bytes   |
                | IPs / protocols   |
                +---------+---------+
                          |
                          v
                +-------------------+
                |  Detection Engine |
                |                   |
                | Z-score           |
                | Source conc.      |
                | Port conc.        |
                | Anomaly score     |
                +---------+---------+
                          |
                    anomaly detected
                          |
                          v
                +-------------------+
                | Mitigation Manager|
                +---------+---------+
                          |
                 +--------+--------+
                 |                 |
                 v                 v
          +-------------+   +-------------+
          |  eBPF/XDP   |   |  nftables   |
          | packet drop |   |  firewall   |
          +-------------+   +-------------+
                 |                 |
                 +--------+--------+
                          |
                          v
                    +-----------+
                    |  Axum API |
                    +-----+-----+
                          |
                          v
                   React Dashboard

Main flow
1.Packets are captured from the network interface.
2.The parser extracts information such as source IP, destination IP, protocol and destination port.
3.Traffic statistics are updated.
4.The detection engine analyzes the current traffic window.
5.An anomaly score is calculated.
6.If the score reaches the mitigation threshold, the source IP is checked against the protected IP list.
7.If the IP is not protected, mitigation can be applied.
8.The IP is added to the XDP blocked-IP map and nftables.
9.The block remains active for the configured duration.
10.After expiration, the active block is removed.
11.The API exposes the current state to the dashboard.

Project Structure
ddos-mitigation-tool/
|
├── ebpf/
|   └── xdp_test.c
|
├── frontend/
|   ├── src/
|   |   ├── components/
|   |   ├── pages/
|   |   ├── services/
|   |   └── types/
|   ├── package.json
|   └── vite.config.ts
|
├── src/
|   ├── alerts/
|   ├── analysis/
|   ├── api/
|   ├── capture/
|   ├── config/
|   ├── detection/
|   ├── metrics/
|   ├── mitigation/
|   └── main.rs
|
├── .env.example
├── Cargo.toml
├── Cargo.lock
└── README.md

Important directories
src/capture/ — packet capture and parsing
src/detection/ — anomaly detection
src/mitigation/ — mitigation and enforcement
src/alerts/ — alert management
src/analysis/ — security analysis
src/metrics/ — runtime and persistent metrics
src/api/ — Axum API and live state
src/config/ — application configuration
ebpf/ — XDP/eBPF program
frontend/ — React dashboard

Technologies
| Part              | Technology   |
| ----------------- | ------------ |
| Main language     | Rust         |
| Async runtime     | Tokio        |
| Packet capture    | pcap         |
| Packet parsing    | etherparse   |
| API               | Axum         |
| Serialization     | Serde / JSON |
| Logging           | tracing      |
| eBPF framework    | Aya          |
| Packet filtering  | eBPF / XDP   |
| Firewall          | nftables     |
| Frontend          | React        |
| Frontend language | TypeScript   |
| Frontend tooling  | Vite         |
| Routing           | React Router |
| Charts            | Recharts     |
| HTTP client       | Axios        |

Requirements

The project is mainly intended for Linux because the mitigation layer uses XDP and nftables.

Required
Linux
Rust and Cargo
Clang / LLVM
libpcap
nftables
Node.js
Yarn

Root privileges are required for packet capture and operations involving XDP and nftables.

The project was developed and tested on Kali Linux.

Installation

Clone the repository:

git clone https://github.com/imeenz/ddos-mitigation-tool.git
cd ddos-mitigation-tool

Build the Rust application:

cargo build

Install the frontend dependencies:

cd frontend
yarn install
cd ..

Create the local environment file:

cp .env.example .env

The .env file contains local configuration and should not be committed.

Configuration

The main configuration is stored in .env.

Example:

APP_NAME=ddos-mitigation-tool
APP_ENV=development
LOG_LEVEL=info

MITIGATION_SCORE_THRESHOLD=0.40
MITIGATION_BLOCK_DURATION_SECS=60
MITIGATION_ENFORCEMENT_ENABLED=true
MITIGATION_PROTECTED_IPS=192.168.13.128

Main variables
| Variable                         | Description                                  |
| -------------------------------- | -------------------------------------------- |
| `APP_NAME`                       | Application name                             |
| `APP_ENV`                        | Current environment                          |
| `LOG_LEVEL`                      | Logging level                                |
| `MITIGATION_SCORE_THRESHOLD`     | Score required to trigger mitigation         |
| `MITIGATION_BLOCK_DURATION_SECS` | How long an IP remains blocked               |
| `MITIGATION_ENFORCEMENT_ENABLED` | Enables mitigation enforcement               |
| `MITIGATION_PROTECTED_IPS`       | IPs that should not be automatically blocked |


Protected IPs are checked before mitigation is applied.

Running the Project

Start the Rust engine

From the project directory:
sudo ./target/debug/ddos-mitigation-tool

The API runs on:
http://127.0.0.1:3000

Check the live state:
curl -s http://127.0.0.1:3000/api/state

Start the dashboard

In another terminal:

cd frontend
yarn dev --host 0.0.0.0 --port 5173

Open:
http://localhost:5173/


How Detection Works

The detection engine works on traffic windows and looks at several characteristics of the traffic.

The main signals are:

Packets per second
Z-score
Source IP concentration
Destination port concentration

These values are combined into an anomaly score.

Packet rate
     |
     +------------------+
                        |
Z-score ---------------+
                        |
Source concentration --+--> Anomaly Score
                        |
Port concentration ----+
                        |
                        v
                Mitigation threshold

A high anomaly score does not automatically mean that an IP will be blocked.

The mitigation logic also checks the protected IP list and whether enforcement is enabled.

How Mitigation Works

When an anomaly reaches the configured mitigation threshold, the mitigation manager handles the response.

Anomaly detected
       |
       v
Check protected IP
       |
   +---+---+
   |       |
Protected  Not protected
   |       |
   v       v
 Skip    Mitigation
           |
      +----+----+
      |         |
      v         v
     XDP     nftables
      |         |
      +----+----+
           |
           v
      IP is blocked
           |
           v
     Block expires
           |
           v
      IP is removed

Active blocks and mitigation history are tracked separately.

After a block expires, the IP is removed from the active block list while the mitigation event remains available in the history.

eBPF/XDP

XDP is used to block traffic early in the Linux networking path.

The XDP program checks the source IPv4 address against the blocked-IP map.

Incoming packet
      |
      v
Read source IP
      |
      v
Is IP in blocked map?
      |
   +--+--+
   |     |
  Yes    No
   |     |
   v     v
 DROP   PASS

The Rust application uses Aya to interact with the eBPF program.

Compile the XDP program
clang -O2 -g -target bpf \
  -I/usr/include/x86_64-linux-gnu \
  -c ebpf/xdp_test.c \
  -o ebpf/xdp_test.o

Attach XDP
sudo ip link set dev eth0 xdp obj ebpf/xdp_test.o sec xdp

Detach XDP
sudo ip link set dev eth0 xdp off

The interface name may be different on another system.

The blocked-IP map is pinned under:
/sys/fs/bpf/ddos-mitigation/blocked_ips

Check it with:
sudo bpftool map dump name blocked_ips

Firewall Enforcement

The project also uses nftables as a second enforcement layer.

The application manages the:

inet ddos_mitigation

table and its:

blocked_ips

set.

During mitigation, the source IP can be added to the set with a timeout.

Check the current set:

sudo nft list set inet ddos_mitigation blocked_ips

This gives the project two enforcement layers:

Detected IP
    |
    +------> eBPF/XDP
    |
    +------> nftables

Dashboard

The project includes a React dashboard connected to the Rust API.

The dashboard provides a live view of the current state of the engine.

It includes:

Engine status
Capture interface
XDP status
Firewall status
Packets per second
Bytes per second
Current anomaly score
Active blocked IPs
Protocol statistics
Top source IPs
Destination ports
Recent alerts
Mitigation history

The dashboard is divided into views for traffic, detection, mitigation and security events.

Testing

Testing was performed in a controlled lab using Kali Linux and Metasploitable.

Lab setup
Metasploitable
192.168.13.128
       |
       | Test traffic
       v
Kali Linux
192.168.13.130
       |
       +-- Rust DDoS engine
       +-- XDP
       +-- nftables
       +-- React dashboard
Test results
Test	Result
Engine / API	PASS
Normal traffic	PASS
ICMP traffic	PASS
UDP traffic	PASS
Anomaly detection	PASS
Protected IP handling	PASS
XDP enforcement	PASS
nftables enforcement	PASS
Automatic mitigation	PASS
Block expiration	PASS
Firewall recovery	PASS
Dashboard state	PASS
Rust test suite	PASS
Protected IP test

A protected IP was used during testing to verify that detection does not automatically lead to blocking.

The engine detected the traffic but skipped mitigation:

ANOMALY DETECTED

MITIGATION: skipped — protected local IP 192.168.13.128
Blocked IPs: 0
Automatic mitigation test

For the controlled mitigation test, the protected-IP exception was temporarily removed.

The engine then produced:

XDP: blocked IP 192.168.13.128 added to eBPF map
MITIGATION: Block applied to source IP 192.168.13.128
Currently blocked IPs: 1
ENFORCEMENT: firewall block applied to 192.168.13.128

The test traffic was then blocked.

Block expiration test

The configured block duration was 60 seconds.

After the block expired:

Blocked IPs: 0

The nftables set was also checked and confirmed to be empty.

This verified the full cycle:

Detection
   ↓
Mitigation
   ↓
XDP + nftables block
   ↓
Block timeout
   ↓
Automatic recovery
Rust tests

The Rust test suite was executed with:

cargo test
Useful Commands
Build
cargo build
Run tests
cargo test
Run the engine
sudo ./target/debug/ddos-mitigation-tool
Start the frontend
cd frontend
yarn dev --host 0.0.0.0 --port 5173
Check API state
curl -s http://127.0.0.1:3000/api/state | python3 -m json.tool
Check nftables
sudo nft list set inet ddos_mitigation blocked_ips
Check XDP map
sudo bpftool map dump name blocked_ips
Check Git status
git status
Security Notes

This project is intended for defensive security research, education and authorized testing.

Only test against systems and networks you own or are authorized to test.
XDP and nftables operations require elevated privileges.
An aggressive detection threshold can result in legitimate traffic being blocked.
Protected IPs should be configured carefully.
The dashboard/API should not be exposed publicly without appropriate access controls.
XDP support depends on the Linux kernel, network interface and driver.
Detection thresholds should be tuned for the environment where the system is deployed.
Limitations

The current version is a functional prototype and was validated in a controlled lab environment.

Some current limitations are:

Linux is required for the XDP and nftables enforcement layer.
Detection is currently based on statistical analysis rather than machine learning.
Detection thresholds need to be tuned for different network environments.
XDP support depends on the available kernel and network interface.
Testing was performed in a controlled laboratory setup.
The current system is designed as a local mitigation engine rather than a distributed DDoS protection system.
Future Improvements

Possible future work includes:

Machine-learning-based traffic classification
Distributed detection sensors
Centralized SIEM integration
Threat intelligence integration
More advanced rate limiting
Improved TCP traffic analysis
Centralized event storage
High-availability deployment
Containerized deployment
Cloud-based monitoring
Project Status

The current version is a functional prototype.

The following parts have been implemented and tested:

Real-time packet capture
Traffic statistics
Protocol detection
Statistical anomaly detection
Security alerts
Automatic IP mitigation
eBPF/XDP enforcement
nftables enforcement
Protected IP handling
Timed block expiration
Metrics and persistence
Axum API
React dashboard

The system has been tested in a controlled Kali Linux and Metasploitable environment.
