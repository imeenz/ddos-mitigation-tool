# DDoS Mitigation Tool

A DDoS detection and mitigation tool built with Rust.

The project captures network traffic, analyzes traffic behavior, detects anomalies, and can automatically block suspicious source IPs using eBPF/XDP and nftables.

A React dashboard is included to monitor traffic, alerts, anomaly scores, active blocks, and mitigation events in real time.

The project was developed and tested in a controlled Linux lab environment using Kali Linux and Metasploitable.

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

## About

The main goal of this project is to build a system that can detect abnormal network traffic and react to it automatically.

The Rust engine is responsible for capturing packets, collecting traffic statistics, detecting anomalies, generating alerts, and handling mitigation.

When mitigation is triggered, the source IP can be blocked through both eBPF/XDP and nftables. Blocks are temporary and expire after the configured duration.

The project also includes a web dashboard that provides a live view of the engine and keeps security events available for later review.

The project was built as a hands-on cybersecurity project with a focus on networking, Linux, Rust, eBPF/XDP, firewall enforcement, and real-time monitoring.

## Features

### Traffic monitoring

- Real-time packet capture
- IPv4 packet parsing
- TCP, UDP and ICMP detection
- Packet and byte statistics
- Packets-per-second calculation
- Source IP tracking
- Destination port tracking

### Detection

- Traffic anomaly detection
- Z-score based analysis
- Source IP concentration
- Destination port concentration
- Combined anomaly score
- Security alert generation
- Alert severity levels

### Mitigation

- Automatic source IP blocking
- Configurable mitigation threshold
- Configurable block duration
- Protected IP support
- Active blocked IP tracking
- Mitigation history
- Automatic block expiration

### Enforcement

- eBPF/XDP packet dropping
- nftables firewall enforcement
- Temporary firewall blocks
- Automatic recovery after expiration


- Live engine status
- Traffic statistics
- Anomaly score
- Security alerts
- Active blocked IPs
- XDP and firewall status
- Traffic history
- Mitigation history

## Architecture

The project is split into a Rust backend, an eBPF/XDP component, a firewall layer, and a React dashboard.

```text
                    Network Traffic
                          |
                          v
                +-------------------+
                |   Packet Capture  |
                |   pcap / parsing  |
                +---------+---------+
                          |
                          v
                +-------------------+
                |  Traffic Stats    |
                | packets / bytes   |
                | IPs / protocols   |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Detection Engine  |
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
          |  packet drop|   |  firewall   |
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

### Main flow

1. Packets are captured from the network interface.
2. The parser extracts information such as source IP, destination IP, protocol and destination port.
3. Traffic statistics are updated.
4. The detection engine analyzes the current traffic window.
5. An anomaly score is calculated.
6. If the score reaches the mitigation threshold, the source IP is checked against the protected IP list.
7. If the IP is not protected, mitigation can be applied.
8. The IP is added to the XDP blocked-IP map and nftables.
9. The block stays active for the configured duration.
10. After expiration, the active block is removed.
11. The API exposes the current state to the dashboard.


---

# 6. Project Structure

```markdown
## Project Structure

```text
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
├── data/
|
├── .env.example
├── Cargo.toml
├── Cargo.lock
└── README.md


---

# 7. Technologies

```markdown
## Technologies

| Part | Technology |
|---|---|
| Main language | Rust 2024 |
| Async runtime | Tokio |
| Packet capture | pcap |
| Packet parsing | etherparse |
| API | Axum |
| Serialization | Serde / JSON |
| Logging | tracing |
| eBPF framework | Aya |
| Packet filtering | eBPF / XDP |
| Firewall | nftables |
| Frontend | React |
| Frontend language | TypeScript |
| Frontend tooling | Vite |
| Routing | React Router |
| Charts | Recharts |
| HTTP client | Axios |

## Requirements

The project is mainly intended for Linux because the mitigation layer uses XDP and nftables.

### Required

- Linux
- Rust and Cargo
- Clang / LLVM
- libpcap
- nftables
- Node.js
- Yarn

Root privileges are required for packet capture and for operations involving XDP and nftables.

The project was developed and tested on Kali Linux.

## Installation

Clone the repository:

```bash
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


---

# 10. Configuration

```markdown
## Configuration

The main configuration is stored in `.env`.

Example:

```env
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

Protected IPs are checked before mitigation is applied. This allows local or important systems to be excluded from automatic blocking.


---

# 11. Running the Project

```markdown
## Running the Project

### Start the Rust engine

From the project directory:

```bash
sudo ./target/debug/ddos-mitigation-tool

The API runs on:

http://127.0.0.1:3000

The live state can be checked with:

curl -s http://127.0.0.1:3000/api/state
Start the dashboard

In another terminal:

cd frontend
yarn dev --host 0.0.0.0 --port 5173

Open:

http://localhost:5173/


---

# 12. How Detection Works

```markdown
## How Detection Works

The detection engine works on traffic windows and looks at several characteristics of the traffic.

The main signals used are:

- Packets per second
- Z-score
- Source IP concentration
- Destination port concentration

These values are combined into an anomaly score.

```text
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

A high anomaly score does not automatically mean that an IP will be blocked. The mitigation logic also checks whether the source IP is protected and whether enforcement is enabled.

This separates detection from the actual mitigation decision.


---

# 13. How Mitigation Works

```markdown
## How Mitigation Works

When an anomaly reaches the configured mitigation threshold, the mitigation manager handles the response.

```text
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

The system keeps track of active blocks separately from mitigation history.

For example, after a 60-second block expires:

Active blocked IPs: 0

while the previous mitigation event can still remain in the history.


---

# 14. eBPF/XDP

```markdown
## eBPF/XDP

XDP is used to block traffic as early as possible in the Linux networking path.

The XDP program checks the source IPv4 address against the blocked-IP map.

```text
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

The blocked-IP map is pinned under:

/sys/fs/bpf/ddos-mitigation/blocked_ips

It can be inspected with:

sudo bpftool map dump name blocked_ips


---

# 15. Firewall Enforcement

```markdown
## Firewall Enforcement

The project also uses nftables as a second enforcement layer.

The application manages:

```text
inet ddos_mitigation

and its:

blocked_ips

set.

During mitigation, the source IP can be added to the set with a timeout.

Check the current set with:

sudo nft list set inet ddos_mitigation blocked_ips

After the configured block duration expires, the active firewall entry is removed.

This gives the project two enforcement layers:

Detected IP
    |
    +------> eBPF/XDP
    |
    +------> nftables


---

# 16. Dashboard

```markdown
## Dashboard

The project includes a React dashboard connected to the Rust API.

The dashboard provides a live view of the current state of the engine.

It includes:

- Engine status
- Capture interface
- XDP status
- Firewall status
- Packets per second
- Bytes per second
- Current anomaly score
- Active blocked IPs
- Protocol statistics
- Top source IPs
- Destination ports
- Recent alerts
- Mitigation history

The dashboard is divided into several views for traffic, detection, mitigation and security events.




## Testing

Testing was performed in a controlled lab using Kali Linux and Metasploitable.

### Lab setup

```text
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
| Test                  | Result |
| --------------------- | ------ |
| Engine / API          | PASS   |
| Normal traffic        | PASS   |
| ICMP traffic          | PASS   |
| UDP traffic           | PASS   |
| Anomaly detection     | PASS   |
| Protected IP handling | PASS   |
| XDP enforcement       | PASS   |
| nftables enforcement  | PASS   |
| Automatic mitigation  | PASS   |
| Block expiration      | PASS   |
| Firewall recovery     | PASS   |
| Dashboard state       | PASS   |
| Rust test suite       | PASS   |

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
60 second timeout
   ↓
Automatic recovery

Rust tests

The complete Rust test suite was also executed:

cargo test

The test suite completed successfully.


---

# 18. Useful Commands

```markdown
## Useful Commands

### Build

```bash
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


---

# 19. Security Notes

```markdown
## Security Notes

This project is intended for defensive security research, education and authorized testing.

- Only test against systems and networks you own or are authorized to test.
- XDP and nftables operations require elevated privileges.
- An aggressive detection threshold can result in legitimate traffic being blocked.
- Protected IPs should be configured carefully.
- The dashboard/API should not be exposed publicly without appropriate access controls.
- XDP support depends on the Linux kernel, network interface and driver.
- Detection thresholds should be tuned for the environment where the system is deployed.

## Limitations

The current version is a functional prototype and was validated in a controlled lab environment.

Some current limitations are:

- Linux is required for the XDP and nftables enforcement layer.
- Detection is currently based on statistical analysis rather than machine learning.
- Detection thresholds need to be tuned for different network environments.
- XDP support depends on the available kernel and network interface.
- Testing was performed in a controlled laboratory setup.
- The current system is designed as a local mitigation engine rather than a distributed DDoS protection system.

## Future Improvements

Possible future work includes:

- Machine-learning-based traffic classification
- Distributed detection sensors
- Centralized SIEM integration
- Threat intelligence integration
- More advanced rate limiting
- Improved TCP traffic analysis
- Centralized event storage
- High-availability deployment
- Containerized deployment
- Cloud-based monitoring

## Project Status

The current version is a functional prototype.

The following parts have been implemented and tested:

- Real-time packet capture
- Traffic statistics
- Protocol detection
- Statistical anomaly detection
- Security alerts
- Automatic IP mitigation
- eBPF/XDP enforcement
- nftables enforcement
- Protected IP handling
- Timed block expiration
- Metrics and persistence
- Axum API
- React dashboard

The system has been tested in a controlled Kali Linux and Metasploitable environment.



