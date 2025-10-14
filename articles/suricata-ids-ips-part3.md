# Suricata IDS/IPS - Part 3: Kiến trúc lõi (Core Architecture)

*"Phần 3 đi sâu vào kiến trúc bên trong của Suricata, bao gồm mô hình đa luồng (multi-threaded packet pipeline), các capture engines (AF-Packet, PF_RING, NFQUEUE, PCAP), Flow Manager, Stream engine, Detection engine, Output modules và Lua scripting subsystem."*

---

## 3. Kiến trúc lõi (Core Architecture)

### 3.1. Tổng quan kiến trúc Suricata

**High-level architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                    PACKET CAPTURE LAYER                     │
│  (AF_PACKET, PF_RING, DPDK, Netmap, NFQUEUE, PCAP...)     │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                  PACKET ACQUISITION (DAQ)                   │
│              - Receive packets from NIC/file                │
│              - Load balancing across threads                │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                  MULTI-THREADED PIPELINE                    │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │Thread 1 │  │Thread 2 │  │Thread N │  │Manager  │       │
│  │         │  │         │  │         │  │Threads  │       │
│  │ Decode  │  │ Decode  │  │ Decode  │  │         │       │
│  │ Stream  │  │ Stream  │  │ Stream  │  │ - Flow  │       │
│  │ Detect  │  │ Detect  │  │ Detect  │  │ - Stats │       │
│  │ Respond │  │ Respond │  │ Respond │  │         │       │
│  └────┬────┘  └────┬────┘  └────┬────┘  └─────────┘       │
│       │            │            │                           │
└───────┼────────────┼────────────┼───────────────────────────┘
        │            │            │
        └────────────┴────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    OUTPUT MODULES                           │
│  - EVE JSON (logs)                                          │
│  - Fast Alert log                                           │
│  - PCAP (packet capture)                                    │
│  - Unix Socket                                              │
│  - Syslog, File logging                                     │
└─────────────────────────────────────────────────────────────┘
```

**Key components:**
1. **Capture Layer:** Nhận packets từ network interface
2. **Threading Model:** Xử lý packets song song trên nhiều CPU cores
3. **Flow Manager:** Quản lý kết nối/flows
4. **Stream Engine:** Reassemble TCP streams
5. **Detection Engine:** Pattern matching, rule evaluation
6. **Output Modules:** Ghi logs, alerts, captured packets

---

### 3.2. Threading Model (Multi-threaded Packet Pipeline)

#### **3.2.1. Runmodes (Thread Architecture Modes)**

Suricata hỗ trợ nhiều threading models phù hợp với các môi trường khác nhau:

**1. Workers Runmode (Mặc định, Khuyến nghị):**

```
┌──────────────────────────────────────────────────────────────┐
│                    Packet Capture                            │
│         (AF_PACKET with cluster_flow/cluster_qm)             │
└─────────────────┬────────────────┬───────────────┬───────────┘
                  │                │               │
         ┌────────▼──────┐  ┌──────▼─────┐  ┌─────▼──────┐
         │  Worker 1     │  │  Worker 2  │  │  Worker N  │
         │               │  │            │  │            │
         │  - Decode     │  │  - Decode  │  │  - Decode  │
         │  - Stream     │  │  - Stream  │  │  - Stream  │
         │  - Detect     │  │  - Detect  │  │  - Detect  │
         │  - Output     │  │  - Output  │  │  - Output  │
         └───────────────┘  └────────────┘  └────────────┘
              Full pipeline per worker thread
```

**Đặc điểm:**
- **Mỗi worker thread xử lý hoàn chỉnh một packet** (decode → detect → output)
- Packets được **load-balanced** giữa workers dựa trên flow hash (5-tuple)
- **Tất cả packets của cùng flow đi qua cùng worker** → Stream reassembly chính xác
- **Scalability tốt:** Tăng workers = tăng throughput (linear scaling)
- **Không có shared state** giữa workers → ít contention

**Configuration (`suricata.yaml`):**
```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ 1-15 ]  # Workers on cores 1-15
        mode: "exclusive"
        prio:
          default: "high"

af-packet:
  - interface: eth0
    threads: 16  # 16 worker threads
    cluster-type: cluster_flow  # Flow-based load balancing
    defrag: no
    use-mmap: yes
```

**Khi nào dùng Workers mode:**
- ✅ Multi-core CPUs (4+ cores)
- ✅ High-speed networks (1Gbps+)
- ✅ Production deployments
- ✅ Inline IPS mode

---

**2. Autofp Runmode (Auto Flow Pinned):**

```
┌──────────────────────────────────────────────────────────────┐
│                    Packet Capture                            │
└─────────────────┬────────────────────────────────────────────┘
                  │
         ┌────────▼──────────┐
         │  Capture Thread   │
         │  - Receive pkts   │
         │  - Decode         │
         │  - Flow lookup    │
         └────────┬──────────┘
                  │ Assign to worker based on flow
         ┌────────┼────────┬─────────┐
         │        │        │         │
    ┌────▼───┐ ┌─▼────┐ ┌─▼────┐ ┌──▼────┐
    │Detect 1│ │Det. 2│ │Det. 3│ │Det. N │
    │        │ │      │ │      │ │       │
    │Stream  │ │Stream│ │Stream│ │Stream │
    │Output  │ │Output│ │Output│ │Output │
    └────────┘ └──────┘ └──────┘ └───────┘
```

**Đặc điểm:**
- **Capture thread** nhận và decode packets
- **Detection threads** xử lý detection và stream reassembly
- Flows được "pin" (gán cố định) cho detection threads
- **Ít scalable hơn Workers mode** (capture thread có thể bottleneck)

**Configuration:**
```yaml
threading:
  set-cpu-affinity: yes
  detect-thread-ratio: 1.5  # 1.5x detection threads per core

runmode: autofp
```

**Khi nào dùng Autofp:**
- ⚠️ Legacy systems
- ⚠️ Khi Workers mode gặp vấn đề
- ⚠️ Debugging (dễ trace packets qua pipeline)

---

**3. Single Mode (Single-threaded):**

```
┌────────────────────────────────────────┐
│      Single Thread                     │
│  Capture → Decode → Stream → Detect   │
│         → Output                       │
└────────────────────────────────────────┘
```

**Khi nào dùng Single mode:**
- ❌ KHÔNG dùng trong production
- ✅ Development & debugging
- ✅ PCAP analysis (offline)
- ✅ Low-traffic environments (<100Mbps)

**Configuration:**
```yaml
runmode: single
```

---

#### **3.2.2. Thread Types**

**1. Worker Threads:**
- Xử lý packets từ capture đến output
- Mỗi worker độc lập, không share state
- Số lượng: Thường = số CPU cores - 2 (để lại cho management)

**2. Management Threads:**
- **Flow Manager Thread:** Cleanup expired flows, timeouts
- **Flow Recycler Thread:** Recycle flow memory
- **Stats Thread:** Thu thập và báo cáo thống kê
- **Unix Socket Thread:** API cho external management

**3. Output Threads:**
- Ghi logs, alerts ra disk/network
- Có thể tách riêng để không block workers

---

#### **3.2.3. CPU Affinity (Pinning Threads to Cores)**

**Tại sao cần CPU affinity:**
- **Tránh context switching:** Thread luôn chạy trên cùng core
- **L1/L2 cache locality:** Data ở cache của core đó
- **NUMA awareness:** Thread chạy trên core gần memory node

**Configuration:**
```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]  # Core 0 for management
    - receive-cpu-set:
        cpu: [ 0 ]  # Core 0 for packet capture
    - worker-cpu-set:
        cpu: [ 1-15 ]  # Cores 1-15 for workers
        mode: "exclusive"
        prio:
          default: "high"
```

**Best practices:**
- Core 0: Management + Capture (nếu không phải high-speed)
- Core 1-N: Workers
- Tránh Hyperthreading siblings (ví dụ: 0,16 là siblings trên CPU 16-core)

**Check CPU topology:**
```bash
lscpu -e
# hoặc
cat /proc/cpuinfo | grep -E '(processor|physical id|core id)'
```

---

#### **3.2.4. Load Balancing Strategies**

**1. cluster_flow (Khuyến nghị):**
```yaml
af-packet:
  - interface: eth0
    cluster-type: cluster_flow
```
- Load balance dựa trên **5-tuple hash** (src IP, dst IP, src port, dst port, protocol)
- Tất cả packets của **cùng flow → cùng worker**
- ✅ Stream reassembly chính xác
- ✅ Stateful detection works correctly

**2. cluster_qm (Queue Mapping):**
```yaml
af-packet:
  - interface: eth0
    cluster-type: cluster_qm
```
- Dựa vào **RSS (Receive Side Scaling)** của NIC
- NIC hardware phân phối packets vào queues
- ✅ Offload load balancing sang hardware
- ⚠️ Cần NIC hỗ trợ RSS

**3. cluster_cpu:**
```yaml
af-packet:
  - interface: eth0
    cluster-type: cluster_cpu
```
- Round-robin packets giữa CPUs
- ❌ **KHÔNG khuyến nghị:** Packets của cùng flow có thể đến khác workers → stream reassembly sai

---

#### **3.2.5. Thread Performance Tuning**

**Monitoring threads:**
```bash
# Check thread count
ps -eLf | grep suricata | wc -l

# Check CPU usage per thread
top -H -p $(pidof suricata)

# Suricata stats
suricatasc -c "dump-counters"
```

**Key metrics:**
```
capture.kernel_packets     # Packets received from kernel
capture.kernel_drops       # Drops at kernel level
decoder.pkts               # Packets decoded
flow.memuse               # Flow table memory usage
detect.alert              # Alerts generated
```

**Tuning guidelines:**

| Symptom | Solution |
|---------|----------|
| High `kernel_drops` | Increase workers, ring buffer size |
| Workers idle (low CPU) | Decrease workers, traffic too low |
| Workers 100% CPU | Increase workers, reduce rules |
| High `flow.memuse` | Increase `memcap`, reduce `flow.timeout` |
| Uneven CPU usage | Check load balancing, CPU affinity |

---

### 3.3. Capture Engines

Suricata hỗ trợ nhiều packet capture methods, mỗi loại phù hợp với use cases khác nhau.

#### **3.3.1. AF_PACKET (Linux, Khuyến nghị)**

**Giới thiệu:**
- Native Linux packet capture socket
- Zero-copy mode với MMAP (memory-mapped buffers)
- Built-in load balancing (PACKET_FANOUT)
- **Best choice cho Linux production systems**

**Architecture:**
```
┌──────────────────────────────────────────────┐
│           Network Interface (eth0)           │
└────────────────┬─────────────────────────────┘
                 │
         ┌───────▼────────┐
         │  Kernel Space  │
         │  Ring Buffer   │  (MMAP shared memory)
         └───────┬────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼───┐   ┌───▼───┐   ┌───▼───┐
│Worker1│   │Worker2│   │WorkerN│  (User space)
└───────┘   └───────┘   └───────┘
```

**Configuration (`suricata.yaml`):**
```yaml
af-packet:
  - interface: eth0
    # Number of receive threads
    threads: 16

    # Cluster type for load balancing
    cluster-type: cluster_flow  # or cluster_qm, cluster_cpu
    cluster-id: 99

    # Disable in-kernel IP defragmentation (Suricata does it)
    defrag: no

    # Use memory-mapped ring buffer (zero-copy)
    use-mmap: yes

    # Ring buffer size (in MB per thread)
    ring-size: 2048

    # Block size (must be power of 2)
    block-size: 32768

    # Checksum validation (offload to NIC if possible)
    checksum-checks: no

    # Copy entire packet (not just headers)
    copy-mode: ifs
    copy-iface: eth1  # for IPS mode
```

**Performance tuning:**

**1. Ring buffer sizing:**
```yaml
ring-size: 2048  # 2GB per thread
```
- Larger = fewer drops during traffic spikes
- Too large = memory waste
- Recommended: 1024-4096 MB per thread

**2. Block size:**
```yaml
block-size: 32768  # 32KB
```
- Smaller = lower latency
- Larger = better efficiency
- Recommended: 16384 or 32768

**3. Disable kernel features Suricata handles:**
```bash
# Disable offloading (Suricata needs to see original packets)
ethtool -K eth0 gro off
ethtool -K eth0 lro off
ethtool -K eth0 tso off
ethtool -K eth0 gso off

# Increase ring buffer
ethtool -G eth0 rx 4096 tx 4096
```

**Advantages:**
- ✅ High performance (10-40 Gbps)
- ✅ Zero-copy với MMAP
- ✅ Built-in load balancing
- ✅ Native Linux, no external libraries
- ✅ Hỗ trợ IPS mode (copy-mode: ips)

**Disadvantages:**
- ❌ Linux only
- ❌ Kernel drops vẫn có thể xảy ra nếu không tune đúng

---

#### **3.3.2. PF_RING (Linux, High-Performance)**

**Giới thiệu:**
- Packet capture framework từ ntop
- Kernel module + user-space library
- Zero-copy, DNA (Direct NIC Access) mode
- **Best cho very high-speed networks (40Gbps+)**

**Architecture:**
```
┌─────────────────────────────────────────┐
│      Network Interface (eth0)           │
└──────────────┬──────────────────────────┘
               │
       ┌───────▼────────┐
       │  PF_RING       │  (Kernel module)
       │  Kernel Module │
       └───────┬────────┘
               │ Zero-copy DMA
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│Worker1│ │Worker2│ │WorkerN│
└───────┘ └───────┘ └───────┘
```

**Installation:**
```bash
# Install PF_RING library
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel
make && sudo make install

cd ../userland/lib
./configure && make && sudo make install

# Load kernel module
sudo modprobe pf_ring
```

**Configuration (`suricata.yaml`):**
```yaml
pfring:
  - interface: eth0
    threads: 16
    cluster-id: 99
    cluster-type: cluster_flow
```

**Advantages:**
- ✅ Very high performance (40-100 Gbps)
- ✅ Zero-copy DMA (DNA mode với NICs hỗ trợ)
- ✅ Hardware timestamping
- ✅ Kernel-level filtering (BPF offload)

**Disadvantages:**
- ❌ Cần cài kernel module (phức tạp)
- ❌ DNA mode cần NICs đặc biệt (Intel, Broadcom...)
- ❌ License: Free version có giới hạn, DNA cần license thương mại

---

#### **3.3.3. DPDK (Data Plane Development Kit)**

**Giới thiệu:**
- Framework từ Intel cho packet processing
- **Bypass kernel hoàn toàn** (kernel-bypass)
- Poll-mode drivers (PMD) → zero-copy, no interrupts
- **Extreme performance** (100 Gbps+)

**Architecture:**
```
┌─────────────────────────────────────────┐
│      Network Interface (eth0)           │
└──────────────┬──────────────────────────┘
               │ Direct hardware access
       ┌───────▼────────┐
       │  DPDK PMD      │  (User space driver)
       │  (Bypass kernel)│
       └───────┬────────┘
               │ Huge pages memory
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│Worker1│ │Worker2│ │WorkerN│
└───────┘ └───────┘ └───────┘
```

**Setup:**
```bash
# Install DPDK
apt-get install dpdk dpdk-dev

# Setup huge pages (required for DPDK)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Bind NIC to DPDK driver
dpdk-devbind.py --bind=uio_pci_generic 0000:03:00.0
```

**Configuration (`suricata.yaml`):**
```yaml
dpdk:
  eal-params:
    proc-type: primary
  interfaces:
    - interface: 0000:03:00.0  # PCI address
      threads: 16
      promisc: yes
```

**Advantages:**
- ✅ **Highest performance** (100+ Gbps)
- ✅ Kernel-bypass → no context switches
- ✅ Zero-copy, poll-mode → ultra-low latency
- ✅ Hỗ trợ nhiều NICs (Intel, Mellanox, Broadcom...)

**Disadvantages:**
- ❌ **Phức tạp nhất** trong setup
- ❌ NIC bị DPDK chiếm → kernel không thấy
- ❌ Cần huge pages memory
- ❌ CPU 100% do poll-mode (không sleep)

---

#### **3.3.4. Netmap (BSD/Linux)**

**Giới thiệu:**
- Fast packet I/O framework
- Kernel-bypass, zero-copy
- Hỗ trợ FreeBSD, Linux
- Giữa AF_PACKET và DPDK về performance

**Configuration (`suricata.yaml`):**
```yaml
netmap:
  - interface: netmap:eth0
    threads: 8
    copy-mode: ips
    copy-iface: netmap:eth1
```

**Advantages:**
- ✅ High performance (10-40 Gbps)
- ✅ Đơn giản hơn DPDK
- ✅ Zero-copy, kernel-bypass

**Disadvantages:**
- ❌ Cần compile custom kernel module
- ❌ Ít phổ biến hơn AF_PACKET/DPDK

---

#### **3.3.5. NFQUEUE (Inline IPS Mode)**

**Giới thiệu:**
- Linux Netfilter framework
- **Inline mode:** Packets đi qua Suricata trước khi forwarding
- Suricata có thể **DROP/ACCEPT/REJECT** packets
- **True IPS mode** (không chỉ monitor)

**Architecture:**
```
Internet
   │
   ▼
Firewall (iptables)
   │
   ├─ NFQUEUE rule: QUEUE traffic to Suricata
   │
   ▼
┌─────────────────┐
│   Suricata IPS  │ → Analysis
│   (NFQUEUE)     │ → Decision: ACCEPT/DROP
└────────┬────────┘
         │
         ▼ Verdict back to kernel
   Forward to destination
```

**Setup:**
```bash
# iptables rule to send traffic to NFQUEUE
iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
```

**Configuration (`suricata.yaml`):**
```yaml
nfqueue:
  mode: accept  # accept or repeat
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  batchcount: 20
  fail-open: yes  # Let traffic pass if Suricata crashes
```

**Action modes:**
```yaml
# In rules, specify action
drop tcp any any -> any 80 (msg:"Block malicious traffic"; ...)
```

**Advantages:**
- ✅ **True inline IPS:** Can block attacks in real-time
- ✅ Tích hợp với iptables/nftables
- ✅ Fail-open support (let traffic pass nếu Suricata fail)

**Disadvantages:**
- ❌ Lower throughput (packets đi qua kernel nhiều lần)
- ❌ Latency cao hơn monitor mode
- ❌ Risk: Misconfiguration có thể block legitimate traffic

---

#### **3.3.6. PCAP (Legacy, Offline Analysis)**

**Giới thiệu:**
- libpcap-based capture
- **Offline analysis:** Đọc PCAP files
- **Live capture:** Fallback nếu AF_PACKET không dùng được

**Configuration (`suricata.yaml`):**
```yaml
pcap:
  - interface: eth0
    buffer-size: 32768
    checksum-checks: no
```

**Offline PCAP analysis:**
```bash
suricata -r capture.pcap -l /var/log/suricata/
```

**Advantages:**
- ✅ Portable (Windows, macOS, Linux, BSD)
- ✅ Offline analysis
- ✅ No special setup

**Disadvantages:**
- ❌ **Lowest performance** (~1-2 Gbps)
- ❌ No zero-copy
- ❌ Single-threaded capture
- ❌ Không khuyến nghị cho production

---

#### **3.3.7. Capture Engine Comparison**

| Capture Method | Performance | Complexity | Platform | Use Case |
|----------------|-------------|------------|----------|----------|
| **AF_PACKET** | ⭐⭐⭐⭐ (10-40G) | ⭐⭐ Easy | Linux | **Production (recommended)** |
| **PF_RING** | ⭐⭐⭐⭐⭐ (40-100G) | ⭐⭐⭐⭐ Hard | Linux | Very high-speed networks |
| **DPDK** | ⭐⭐⭐⭐⭐ (100G+) | ⭐⭐⭐⭐⭐ Very hard | Linux | Extreme performance |
| **Netmap** | ⭐⭐⭐⭐ (10-40G) | ⭐⭐⭐ Medium | BSD/Linux | BSD systems |
| **NFQUEUE** | ⭐⭐ (1-5G) | ⭐⭐ Easy | Linux | **Inline IPS** |
| **PCAP** | ⭐ (1-2G) | ⭐ Very easy | All | Offline analysis, testing |

**Decision tree:**

```
Need inline blocking (IPS)?
  Yes → NFQUEUE
  No  → Monitor mode
        │
        ├─ Linux?
        │   Yes → Throughput?
        │         ├─ <10 Gbps → AF_PACKET
        │         ├─ 10-40 Gbps → AF_PACKET or PF_RING
        │         └─ >40 Gbps → DPDK
        │
        ├─ BSD?
        │   Yes → Netmap or PCAP
        │
        └─ Windows/macOS?
            Yes → PCAP (or use Linux VM)
```

---

### 3.4. Flow Manager

#### **3.4.1. Flow Concepts**

**Flow definition:**
Flow là một chuỗi packets có cùng 5-tuple trong một khoảng thời gian:
- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol (TCP/UDP/ICMP)

**Flow table:**
```
┌─────────────────────────────────────────────────────────────┐
│                      Flow Hash Table                        │
├─────────────────────────────────────────────────────────────┤
│ Hash(5-tuple) → Flow Entry                                  │
│                                                              │
│ Example flow:                                               │
│   Key: 192.168.1.10:54321 → 93.184.216.34:443 (TCP)        │
│   Value:                                                     │
│     - State: ESTABLISHED                                    │
│     - Packets: 245                                          │
│     - Bytes: 128KB                                          │
│     - Start time: 2024-01-15 10:30:00                       │
│     - Last seen: 2024-01-15 10:32:15                        │
│     - Timeout: 3600s                                        │
│     - Alerts: [alert1, alert2]                              │
│     - Stream: [TCP reassembly data]                         │
└─────────────────────────────────────────────────────────────┘
```

---

#### **3.4.2. Flow Lifecycle**

**Flow states:**

```
NEW → ESTABLISHED → CLOSED
 │         │            │
 └─────────┴────────────┴→ TIMEOUT / EMERGENCY CLEANUP
```

**1. NEW:**
- Flow mới được tạo khi packet đầu tiên xuất hiện
- Allocate memory cho flow entry
- TCP: SYN packet → NEW state

**2. ESTABLISHED:**
- Flow đã hoàn thành handshake (TCP) hoặc có bidirectional traffic
- TCP: SYN → SYN-ACK → ACK → ESTABLISHED
- UDP: Packet theo cả 2 chiều → ESTABLISHED

**3. CLOSED:**
- TCP: FIN → FIN-ACK → CLOSED
- TCP: RST → CLOSED immediately
- UDP/ICMP: Timeout (không có close signal)

**4. TIMEOUT:**
- Flow không thấy packets trong `timeout` seconds
- Flow Manager cleanup flow entry

**5. EMERGENCY CLEANUP:**
- Flow table đầy (達到 `memcap`)
- Cleanup oldest flows để giải phóng memory

---

#### **3.4.3. Flow Timeouts**

**Configuration (`suricata.yaml`):**
```yaml
flow:
  # Flow timeouts (in seconds)
  timeouts:
    default:
      new: 30          # New flow, no established state
      established: 300 # Established flow
      closed: 0        # Immediately after close
      bypassed: 100
      emergency-new: 10
      emergency-established: 100
      emergency-closed: 0

    tcp:
      new: 60
      established: 3600  # 1 hour for established TCP
      closed: 120
      emergency-new: 10
      emergency-established: 300
      emergency-closed: 20

    udp:
      new: 30
      established: 300
      bypassed: 100
      emergency-new: 10
      emergency-established: 100

    icmp:
      new: 30
      established: 300
      emergency-new: 10
      emergency-established: 100
```

**Tuning guidelines:**

| Timeout | Impact | Recommended Value |
|---------|--------|-------------------|
| `tcp.established` | High = more memory, low = miss long connections | 3600s (1 hour) |
| `udp.established` | UDP stateless, timeout faster | 60-300s |
| `icmp.established` | ICMP request-reply, short timeout | 30s |
| `emergency-*` | Under memory pressure, cleanup faster | 10-100s |

---

#### **3.4.4. Flow Memory Management**

**Configuration:**
```yaml
flow:
  # Maximum memory for flows (in bytes)
  memcap: 128mb

  # Flow hash table size (must be power of 2)
  hash-size: 65536

  # Preallocation (faster, but uses memory upfront)
  prealloc: 10000

  # Emergency recovery
  emergency-recovery: 30  # Cleanup 30% when memcap reached
```

**Memory calculation:**
```
Flow entry size ≈ 1-2 KB (depends on features enabled)

Example:
- memcap: 128 MB
- Flow entry: 1.5 KB
- Max flows: 128 MB / 1.5 KB ≈ 87,000 flows

For 10 Gbps network with average flow duration 60s:
  Flows per second ≈ 50,000 (估算)
  Concurrent flows ≈ 50,000 * 60 = 3,000,000
  Memory needed ≈ 3,000,000 * 1.5 KB ≈ 4.5 GB
```

**Monitoring flow memory:**
```bash
suricatasc -c "dump-counters" | grep flow

# Key metrics:
flow.memuse           # Current memory usage
flow.spare            # Flows in spare queue
flow.emerg_mode_entered  # Times emergency mode triggered
flow.emerg_mode_over  # Times exited emergency mode
```

---

#### **3.4.5. Flow Manager Thread**

**Responsibilities:**
1. **Timeout expired flows:** Check flow timeout, cleanup
2. **Memory management:** Monitor memcap, trigger emergency cleanup
3. **Statistics:** Report flow counters
4. **Flow recycling:** Reuse flow memory (không free/malloc mỗi lần)

**Configuration:**
```yaml
flow-timeouts:
  managers: 1  # Number of flow manager threads (usually 1)
  recyclers: 1 # Number of flow recycler threads
```

**Flow Manager workflow:**
```
Every 1 second:
  1. Scan flow hash table
  2. For each flow:
     - Check last_seen timestamp
     - If (now - last_seen) > timeout:
         Mark flow for cleanup
  3. Cleanup marked flows:
     - Free stream reassembly data
     - Free alerts data
     - Return flow entry to spare pool
  4. If memuse > memcap:
     - Enter emergency mode
     - Sort flows by last_seen (oldest first)
     - Cleanup emergency-recovery% of flows
```

---

### 3.5. Stream Engine (TCP Reassembly)

#### **3.5.1. Why Stream Reassembly?**

**Problem:**
TCP packets có thể:
- **Out-of-order:** Packets đến không theo thứ tự
- **Fragmented:** Dữ liệu bị chia nhỏ
- **Retransmitted:** Packets bị mất, gửi lại

**Example:**
```
Application data: "GET /malicious_payload HTTP/1.1"

Packets seen by Suricata:
  Packet 1: SEQ=1000, Data="GET "
  Packet 3: SEQ=1010, Data="ious_payload"  (out-of-order!)
  Packet 2: SEQ=1004, Data="/malic"
  Packet 4: SEQ=1024, Data=" HTTP/1.1"

Without reassembly:
  Rule: content:"GET /malicious_payload"
  → MISS (không match bất kỳ packet nào)

With reassembly:
  Reassembled: "GET /malicious_payload HTTP/1.1"
  → MATCH!
```

---

#### **3.5.2. Stream Engine Architecture**

**Components:**
```
┌─────────────────────────────────────────────────────────┐
│                    TCP Packet                           │
└──────────────────┬──────────────────────────────────────┘
                   │
         ┌─────────▼────────┐
         │  Stream Tracker  │
         │  - Sequence nums │
         │  - State (SYN, EST, FIN) │
         │  - Window tracking │
         └─────────┬────────┘
                   │
         ┌─────────▼────────┐
         │ Reassembly Engine│
         │  - Segment queue │
         │  - Overlap handling │
         │  - Gap detection │
         └─────────┬────────┘
                   │
         ┌─────────▼────────┐
         │ Reassembled Stream│ → Detection Engine
         │  "Complete data" │
         └──────────────────┘
```

---

#### **3.5.3. Configuration**

**Basic settings (`suricata.yaml`):**
```yaml
stream:
  # Memcap for stream reassembly
  memcap: 64mb

  # Inline mode (IPS)
  inline: no

  # Checksum validation
  checksum-validation: yes

  # Reassembly depth (per direction)
  reassembly:
    memcap: 64mb
    depth: 1mb  # Inspect first 1MB per stream direction
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes
```

**Reassembly depth:**
- `depth: 1mb` → Inspect first 1MB, ignore rest
- **Trade-off:**
  - High depth = catch attacks later in stream, more memory
  - Low depth = miss attacks after Nth byte, less memory
- **Recommendation:**
  - HTTP/TLS: 1-4 MB
  - File transfer: 0 (disable, too large)
  - Unknown: 512 KB - 1 MB

---

#### **3.5.4. TCP State Tracking**

**TCP states in Suricata:**
```
CLOSED → SYN_SENT → SYN_RECV → ESTABLISHED → FIN_WAIT1
  → FIN_WAIT2 → TIME_WAIT → CLOSED

Or:
CLOSED → SYN_SENT → SYN_RECV → ESTABLISHED → CLOSE_WAIT
  → LAST_ACK → CLOSED
```

**State machine:**
```yaml
stream:
  midstream: false  # Allow pickup mid-stream (no SYN seen)
  async-oneside: false  # Allow one-sided flows (only see client or server)
```

**midstream: true (useful for):**
- Suricata starts after connections already established
- Long-lived connections (SSH, database)
- ⚠️ Risk: Miss attack in handshake phase

**async-oneside: true (useful for):**
- Asymmetric routing (see only one direction)
- TAP on one side of connection
- ⚠️ Risk: Cannot reassemble bidirectional protocols properly

---

#### **3.5.5. Overlap Handling**

**Problem:**
Attacker gửi overlapping segments để evade detection:

```
Segment 1: SEQ=1000, Len=10, Data="GET /norm"
Segment 2: SEQ=1005, Len=10, Data="malicious"  (Overlap!)

Byte position:
 1000    1005    1010    1015
  |-------|-------|-------|
  [GET /norm]
        [malicious]
        ^^^^^^^
        Overlap area
```

**Different OS handle overlaps differently:**
- **Windows:** Keep **old** data (Segment 1 wins)
  → Reassembled: "GET /normous"
- **Linux:** Keep **new** data (Segment 2 wins)
  → Reassembled: "GET /malicious"

**Suricata configuration:**
```yaml
stream:
  reassembly:
    # Target OS (how to handle overlaps)
    # Options: bsd, linux, old-linux, windows, macos
    toserver-policy: linux
    toclient-policy: windows
```

**Evasion example:**
```
Attacker knows target is Linux (new data wins)
Attacker knows IDS configured as Windows (old data wins)

Send:
  Segment 1: "GET /normal HTTP/1.1"
  Segment 2: "malicious" (overlap position)

IDS (Windows policy) sees: "GET /normal HTTP/1.1" → No alert
Target (Linux) sees: "GET /malicious HTTP/1.1" → Attacked!
```

**Best practice:**
- Configure `toserver-policy` to **match target server OS**
- Configure `toclient-policy` to **match client OS** (usually Windows)
- If mixed environment: Use `linux` (more common in servers)

---

#### **3.5.6. Handling Gaps & Missing Segments**

**Gap scenario:**
```
Segment 1: SEQ=1000, Len=100
Segment 2: SEQ=1200, Len=100  (GAP! Missing SEQ 1100-1199)
```

**Options:**
```yaml
stream:
  reassembly:
    # What to do with gaps?
    # Options: yes, no, both
    check-overlap-different-data: yes
```

**Behavior:**
- **Generate alert:** `STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA`
- **Pass to detection anyway** (with gap marked)

**Detection with gaps:**
```
Rule: content:"malicious";
Stream: "benign_[GAP]_malicious_payload"
         ^^^^^^^^
         Gap here

→ Match depends on rule settings:
  - content:"malicious"; → MATCH (found after gap)
  - content:"benign_malicious"; → MISS (gap breaks pattern)
```

---

#### **3.5.7. Performance Tuning**

**Monitoring:**
```bash
suricatasc -c "dump-counters" | grep stream

# Key metrics:
tcp.reassembly_memuse  # Memory used for reassembly
tcp.reassembly_gap     # Gaps detected
tcp.rst                # RST packets
tcp.sessions           # Active TCP sessions
tcp.ssn_memcap_drop    # Dropped due to memcap
```

**Tuning:**

| Symptom | Solution |
|---------|----------|
| High `reassembly_memuse` | Decrease `depth`, `memcap` |
| Many `ssn_memcap_drop` | Increase `memcap`, decrease `depth` |
| High CPU in stream engine | Decrease `depth`, disable for non-critical protocols |
| Missing attacks | Increase `depth`, enable `midstream` |

**Selective depth per protocol:**
```yaml
app-layer:
  protocols:
    http:
      request-body-limit: 100kb
      response-body-limit: 100kb
    tls:
      detection-ports:
        dp: 443
```

---

### 3.6. Detection Engine

#### **3.6.1. Detection Pipeline**

**Flow:**
```
┌────────────────────────────────────────────────────────────┐
│ 1. Packet arrives                                          │
└───────────────────┬────────────────────────────────────────┘
                    │
         ┌──────────▼──────────┐
         │ 2. Prefilter        │
         │  - Fast pattern match │
         │  - Port groups       │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │ 3. Rule Evaluation  │
         │  - Match all keywords│
         │  - Stream inspection│
         │  - Protocol parsing │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │ 4. Verdict          │
         │  - PASS / ALERT     │
         │  - DROP / REJECT    │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │ 5. Output           │
         │  - Log alerts       │
         │  - PCAP logging     │
         └─────────────────────┘
```

---

#### **3.6.2. Pattern Matching Engines**

Suricata hỗ trợ nhiều pattern matching algorithms:

**1. Hyperscan (Intel, Default & Recommended):**
```yaml
detect:
  pattern-matcher: hs  # Hyperscan
```
- **Regex engine** từ Intel
- **Hardware-accelerated** (SIMD instructions: SSE, AVX2, AVX512)
- **Multiple patterns simultaneously** (scan once, match many)
- ✅ Fastest for large rulesets (10,000+ rules)
- ❌ Intel/AMD x86 only (no ARM)

**2. Aho-Corasick (AC):**
```yaml
detect:
  pattern-matcher: ac  # Aho-Corasick
```
- Classic multi-pattern matching algorithm
- ✅ Portable (works on ARM, MIPS...)
- ❌ Slower than Hyperscan

**3. AC-BS (Aho-Corasick Boyer-Moore-Single):**
```yaml
detect:
  pattern-matcher: ac-bs
```
- Hybrid algorithm
- ⚠️ Legacy, not recommended

**Benchmark (10,000 rules):**
```
Hyperscan: 10 Gbps, 50% CPU
AC:         5 Gbps, 80% CPU
AC-BS:      6 Gbps, 75% CPU
```

---

#### **3.6.3. Multi-Pattern Matcher (MPM)**

**Concept:**
Thay vì scan từng rule một, MPM scan **tất cả patterns cùng lúc**.

**Example:**
```
Rules:
  Rule 1: content:"malware";
  Rule 2: content:"exploit";
  Rule 3: content:"shellcode";

Without MPM (slow):
  Packet data: "This is exploit payload"
  - Scan for "malware" → Not found
  - Scan for "exploit" → Found! → Evaluate Rule 2
  - Scan for "shellcode" → Not found

With MPM (fast):
  Packet data: "This is exploit payload"
  - Scan for all patterns simultaneously
  - Found: "exploit" → Evaluate Rule 2 only
  - Other rules skipped
```

**Configuration:**
```yaml
detect:
  profile: high  # Optimize for speed
  # Options: low, medium, high, custom

  sgh-mpm-context: auto  # Signature group MPM context
  # Options: auto, full, single
```

---

#### **3.6.4. Rule Grouping & Optimization**

**Port Groups:**
Suricata groups rules by ports để giảm số rules cần evaluate.

```
Rules:
  Rule 1: alert tcp any any -> any 80 (content:"http_attack"; ...)
  Rule 2: alert tcp any any -> any 443 (content:"https_attack"; ...)
  Rule 3: alert tcp any any -> any 22 (content:"ssh_attack"; ...)

Packet: dst_port=80
→ Only evaluate Rule 1 (port group 80)
→ Skip Rule 2, 3
```

**Signature Group Heads (SGH):**
Further optimize by grouping rules với similar characteristics:
- Same protocol
- Same direction (to_server / to_client)
- Same port ranges

**Rule ordering:**
Suricata automatically reorders rules for efficiency:
1. **Fast pattern rules first** (có content keywords)
2. **Specific rules before generic** (nhiều keywords = specific)
3. **High-priority rules first**

**Manual optimization:**
```
# Use "priority" keyword to force order
alert tcp any any -> any 80 (
  content:"critical_attack";
  priority: 1;  # High priority, evaluate first
  ...
)
```

---

#### **3.6.5. Protocol Parsers**

Suricata có built-in parsers cho nhiều protocols:

**Supported protocols:**
- **HTTP:** Request/response parsing, URI normalization
- **TLS/SSL:** Handshake parsing, certificate extraction
- **DNS:** Query/response parsing
- **SMB:** File sharing protocol
- **SSH:** Version detection, key exchange
- **FTP:** Command/response parsing
- **SMTP:** Email metadata
- **NFS, RDP, TFTP, DHCP, SNMP...**

**Enable/disable:**
```yaml
app-layer:
  protocols:
    http:
      enabled: yes
      memcap: 64mb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    smb:
      enabled: yes
      detection-ports:
        dp: 139,445
    ssh:
      enabled: yes
```

**Protocol-specific keywords:**
```
# HTTP
http.method; content:"POST";
http.uri; content:"/admin";
http.user_agent; content:"BadBot";

# TLS
tls.sni; content:"malicious.com";
tls.cert_subject; content:"CN=Evil";

# DNS
dns.query; content:"evil.com";
```

---

#### **3.6.6. Detection Performance Tuning**

**Configuration:**
```yaml
detect:
  # Detection profile (memory vs speed tradeoff)
  profile: high
  # low: Low memory, slow
  # medium: Balanced
  # high: High memory, fast
  # custom: Manual tuning

  # Payload inspection limits
  inspection-recursion-limit: 3000

  # Rule reload without restart
  reload: true
```

**Profiling rules:**
```yaml
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    limit: 100  # Top 100 slowest rules
```

**Analyze:**
```bash
suricatasc -c "dump-counters" | grep detect

# Check slow rules
cat /var/log/suricata/rule_perf.log | sort -k3 -rn | head -20
```

**Optimization strategies:**
1. **Disable unused protocols:**
   ```yaml
   app-layer:
     protocols:
       ftp: { enabled: no }
       tftp: { enabled: no }
   ```

2. **Reduce inspection depth:**
   ```yaml
   stream:
     reassembly:
       depth: 512kb  # Instead of 1mb
   ```

3. **Use fast_pattern:**
   ```
   alert http any any -> any any (
     content:"rare_string"; fast_pattern;
     content:"common_word";
     ...
   )
   ```

4. **Optimize PCRE:**
   ```
   # Bad (slow):
   pcre:"/.*malicious.*/";

   # Good (fast):
   content:"malicious"; pcre:"/\bmalicious\b/";
   ```

---

### 3.7. Output Modules

#### **3.7.1. EVE JSON (Recommended)**

**Extensible Event Format** - Structured logging in JSON.

**Configuration:**
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular  # or unix_stream, unix_dgram
      filename: eve.json

      # File rotation
      rotate-interval: 1h  # or: day, hour

      # Types of events to log
      types:
        - alert:
            payload: yes             # Include packet payload
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes

        - http:
            extended: yes

        - dns:
            query: yes
            answer: yes

        - tls:
            extended: yes

        - files:
            force-magic: yes
            force-hash: [md5, sha256]

        - smtp
        - ssh
        - flow
        - netflow
```

**Example alert:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123456+0000",
  "flow_id": 123456789,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "10.0.0.5",
  "src_port": 54321,
  "dest_ip": "93.184.216.34",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2029336,
    "rev": 2,
    "signature": "ET MALWARE Possible Cobalt Strike Beacon",
    "category": "A Network Trojan was Detected",
    "severity": 1,
    "metadata": {
      "attack_target": ["Client_Endpoint"],
      "deployment": ["Perimeter"],
      "malware_family": ["CobaltStrike"]
    }
  },
  "http": {
    "hostname": "malicious.com",
    "url": "/beacon",
    "http_method": "GET",
    "http_user_agent": "Mozilla/5.0 ...",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 1024
  },
  "payload": "R0VUIC9iZWFjb24gSFRUUC8xLjENCkhvc3Q6IG1hbGljaW91cy5jb20=",
  "payload_printable": "GET /beacon HTTP/1.1\r\nHost: malicious.com",
  "stream": 0
}
```

**Advantages:**
- ✅ Easy integration with SIEM (ELK, Splunk, Graylog)
- ✅ Structured data (easy to parse, query)
- ✅ Rich metadata (protocol details, payloads)
- ✅ Single file for all event types

---

#### **3.7.2. Fast Alert Log**

**Format:**
```
[Timestamp] [**] [GID:SID:Rev] Message [**] [Classification] [Priority] {Protocol} SrcIP:SrcPort -> DstIP:DstPort
```

**Example:**
```
01/15/2024-10:30:45.123456  [**] [1:2029336:2] ET MALWARE Possible Cobalt Strike Beacon [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 10.0.0.5:54321 -> 93.184.216.34:443
```

**Configuration:**
```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
```

**Use case:**
- Quick grep/search
- Legacy systems expecting this format
- ⚠️ Less info than EVE JSON

---

#### **3.7.3. Unified2 (Legacy)**

**Binary format** compatible with Barnyard2 (for Snort compatibility).

**Configuration:**
```yaml
outputs:
  - unified2-alert:
      enabled: yes
      filename: unified2.alert
```

**Processing:**
```bash
# Use Barnyard2 to process
barnyard2 -c /etc/barnyard2.conf -d /var/log/suricata -f unified2.alert
```

**Use case:**
- Snort-to-Suricata migration
- Tools expecting unified2 format
- ⚠️ Legacy, use EVE JSON instead

---

#### **3.7.4. PCAP Logging**

**Save packets to PCAP files.**

**Configuration:**
```yaml
outputs:
  - pcap-log:
      enabled: yes
      filename: log.pcap

      # Limit PCAP size
      limit: 1000mb
      max-files: 100

      # Conditional logging (save only alerts)
      conditional: alerts  # or: all

      # One PCAP per flow
      mode: multi  # or: single
      dir: /var/log/suricata/pcaps/
```

**Use case:**
- Forensics (inspect packets later)
- Evidence collection
- False positive analysis

---

#### **3.7.5. Syslog Output**

**Configuration:**
```yaml
outputs:
  - syslog:
      enabled: yes
      facility: local5
      level: Info
```

**Use case:**
- Centralized logging (rsyslog, syslog-ng)
- Legacy SIEM integration

---

#### **3.7.6. Stats Output**

**Configuration:**
```yaml
outputs:
  - stats:
      enabled: yes
      filename: stats.log
      interval: 30  # seconds
```

**Example stats:**
```
Date: 1/15/2024 -- 10:30:00
--------------------------------------------------------------
Counter                         | TM Name                | Value
--------------------------------------------------------------
capture.kernel_packets          | RxPCAP0                | 1000000
capture.kernel_drops            | RxPCAP0                | 150
decoder.pkts                    | RxPCAP0                | 999850
detect.alert                    | W#01-eth0              | 523
tcp.sessions                    | W#01-eth0              | 12034
flow.memuse                     | FlowManagerThread      | 128000000
```

---

### 3.8. Lua Scripting Subsystem

#### **3.8.1. Why Lua in Suricata?**

**Use cases:**
- **Custom detection logic** phức tạp hơn rules bình thường
- **Dynamic thresholds** dựa trên context
- **Protocol parsing** cho protocols Suricata chưa hỗ trợ
- **Output filtering** (chỉ log certain conditions)

---

#### **3.8.2. Lua Keywords in Rules**

**1. `luajit` (inline script):**
```
alert http any any -> any any (
  msg:"Custom Lua detection";
  luajit:luascript.lua;
  sid:1000001;
)
```

**2. `lua` (precompiled):**
```
alert http any any -> any any (
  lua:myscript.lua;
  sid:1000002;
)
```

---

#### **3.8.3. Example: HTTP User-Agent Entropy Detection**

**Problem:** Detect DGA (Domain Generation Algorithm) or obfuscated User-Agents.

**Lua script (`ua_entropy.lua`):**
```lua
function init(args)
    local needs = {}
    needs["http.user_agent"] = tostring(true)
    return needs
end

function match(args)
    local ua = HttpGetRequestHeader("User-Agent")
    if ua == nil then
        return 0
    end

    -- Calculate Shannon entropy
    local entropy = calculate_entropy(ua)

    -- Alert if entropy > 4.5 (suspicious)
    if entropy > 4.5 then
        return 1
    else
        return 0
    end
end

function calculate_entropy(str)
    local freq = {}
    local len = string.len(str)

    -- Count character frequencies
    for i = 1, len do
        local c = string.sub(str, i, i)
        freq[c] = (freq[c] or 0) + 1
    end

    -- Calculate entropy
    local entropy = 0
    for c, count in pairs(freq) do
        local p = count / len
        entropy = entropy - (p * math.log(p) / math.log(2))
    end

    return entropy
end
```

**Rule:**
```
alert http any any -> any any (
  msg:"High Entropy User-Agent (Possible Malware)";
  luajit:ua_entropy.lua;
  classtype:trojan-activity;
  sid:1000001;
)
```

---

#### **3.8.4. Example: DNS Query Length Anomaly**

**Detect DNS tunneling via long queries.**

**Lua script (`dns_long_query.lua`):**
```lua
function init(args)
    local needs = {}
    needs["dns.query"] = tostring(true)
    return needs
end

function match(args)
    local query = DnsGetDnsQuery()
    if query == nil then
        return 0
    end

    -- Alert if query > 50 characters
    if string.len(query) > 50 then
        return 1
    else
        return 0
    end
end
```

**Rule:**
```
alert dns any any -> any any (
  msg:"Long DNS Query (Possible Tunneling)";
  lua:dns_long_query.lua;
  classtype:policy-violation;
  sid:1000002;
)
```

---

#### **3.8.5. Available Lua Functions**

**HTTP:**
```lua
HttpGetRequestHeader(name)     -- Get request header
HttpGetResponseHeader(name)    -- Get response header
HttpGetRequestLine()           -- GET /path HTTP/1.1
HttpGetResponseLine()          -- HTTP/1.1 200 OK
HttpGetHost()
HttpGetRequestUriRaw()
HttpGetRequestUriNormalized()
```

**DNS:**
```lua
DnsGetDnsQuery()               -- Query domain
DnsGetAnswers()                -- DNS answers
DnsGetRcode()                  -- Response code
```

**TLS:**
```lua
TlsGetVersion()
TlsGetSNI()                    -- Server Name Indication
TlsGetCertSubject()
TlsGetCertIssuer()
```

**Packet:**
```lua
PacketTimeSince()              -- Time since first packet
PacketTimeString()
FlowGetSourceIp()
FlowGetDestinationIp()
```

---

#### **3.8.6. Performance Considerations**

**Lua scripts có overhead:**
- Slower than native C code
- Each match() call costs CPU cycles

**Best practices:**
1. **Use Lua sparingly:** Chỉ khi rules thông thường không đủ
2. **Optimize scripts:** Avoid expensive operations (regex, I/O)
3. **Cache results:** Store calculations in global variables
4. **Profile:** Use `suricatasc` to measure rule performance

**Example optimization:**
```lua
-- Bad (recalculate every time)
function match(args)
    local ua = HttpGetRequestHeader("User-Agent")
    for i = 1, 1000000 do  -- Expensive loop
        ...
    end
end

-- Good (cache precomputed values)
local blacklist = {["BadBot"]=true, ["Malware"]=true}

function match(args)
    local ua = HttpGetRequestHeader("User-Agent")
    if blacklist[ua] then
        return 1
    end
end
```

---

## 🎯 Tổng kết Part 3

Sau khi hoàn thành Part 3, bạn đã hiểu sâu về kiến trúc của Suricata:

✅ **Threading Model:**
- Workers runmode (khuyến nghị) - mỗi worker xử lý full pipeline
- Autofp, Single mode
- CPU affinity, load balancing strategies

✅ **Capture Engines:**
- AF_PACKET (Linux, production)
- PF_RING (very high-speed)
- DPDK (extreme performance, kernel-bypass)
- NFQUEUE (inline IPS)
- PCAP (offline analysis)

✅ **Flow Manager:**
- Flow lifecycle (NEW → ESTABLISHED → CLOSED)
- Timeout management
- Memory management (memcap, emergency cleanup)

✅ **Stream Engine:**
- TCP reassembly
- Overlap handling
- Gap detection
- OS-specific policies

✅ **Detection Engine:**
- Pattern matching (Hyperscan, Aho-Corasick)
- Multi-pattern matcher (MPM)
- Rule grouping & optimization
- Protocol parsers

✅ **Output Modules:**
- EVE JSON (structured logging, SIEM integration)
- Fast alert log
- PCAP logging
- Syslog, Stats

✅ **Lua Scripting:**
- Custom detection logic
- HTTP, DNS, TLS functions
- Performance considerations

→ **Bạn đã hiểu cách Suricata xử lý packets từ capture đến output, và có thể tuning để đạt hiệu năng tối ưu!**

---

**Tiếp theo: Part 4 sẽ hướng dẫn cài đặt, cấu hình, và vận hành Suricata trong môi trường thực tế.**
