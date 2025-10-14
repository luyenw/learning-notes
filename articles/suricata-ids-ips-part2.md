# Suricata IDS/IPS - Part 2: Tổng quan về IDS/IPS

*"Phần 2 giới thiệu tổng quan về hệ thống phát hiện và phòng chống xâm nhập mạng (IDS/IPS), phân loại các loại hệ thống, so sánh các công cụ phổ biến như Suricata, Snort, Zeek/Bro, và đánh giá ưu nhược điểm về hiệu năng, khả năng mở rộng, độ chính xác và tích hợp."*

---

## 2. Tổng quan IDS/IPS

### 2.1. Khái niệm cơ bản

#### **2.1.1. IDS (Intrusion Detection System)**

**Định nghĩa:**
IDS là hệ thống giám sát và phân tích traffic mạng hoặc hoạt động hệ thống để phát hiện các hành vi đáng ngờ, tấn công, hoặc vi phạm chính sách bảo mật.

**Chức năng chính:**
- **Monitor:** Giám sát traffic/logs liên tục
- **Analyze:** Phân tích dựa trên signatures hoặc anomalies
- **Alert:** Cảnh báo khi phát hiện mối đe dọa
- **Log:** Ghi lại các sự kiện để phân tích sau

**Đặc điểm:**
- **Passive mode:** Chỉ quan sát, KHÔNG can thiệp vào traffic
- **Out-of-band deployment:** Nhận copy của traffic (port mirroring/TAP)
- **False positives:** Có thể cảnh báo nhầm (benign traffic được xem là malicious)
- **False negatives:** Có thể bỏ sót tấn công thực sự

**Ví dụ:**
```
[IDS] ──┐
        ├─ Monitor ─→ Traffic ─→ Destination
        │
        └─ Alert: "SQL Injection detected from 10.0.0.5"
           (Traffic vẫn đến đích bình thường)
```

---

#### **2.1.2. IPS (Intrusion Prevention System)**

**Định nghĩa:**
IPS là phiên bản nâng cao của IDS, có khả năng không chỉ phát hiện mà còn **chủ động ngăn chặn** các tấn công.

**Chức năng:**
- Tất cả chức năng của IDS
- **Block:** Chặn traffic độc hại
- **Drop:** Loại bỏ packets/sessions nguy hiểm
- **Reset:** Ngắt kết nối TCP
- **Modify:** Chỉnh sửa hoặc sanitize packets

**Đặc điểm:**
- **Active/Inline mode:** Đứng giữa luồng traffic
- **In-line deployment:** Tất cả traffic phải đi qua IPS
- **Latency:** Có thể gây delay do phải phân tích trước khi forward
- **False positives impact:** Có thể block nhầm traffic hợp lệ → DoS

**Ví dụ:**
```
Source ─→ [IPS - Inline] ─→ Destination
              │
              ├─ Malicious traffic → BLOCKED ❌
              └─ Legitimate traffic → ALLOWED ✓
```

**So sánh IDS vs IPS:**

| Tiêu chí | IDS | IPS |
|----------|-----|-----|
| **Chế độ** | Passive (Out-of-band) | Active (Inline) |
| **Hành động** | Chỉ cảnh báo | Cảnh báo + Chặn |
| **Deployment** | Port mirror / TAP | Giữa firewall và switch |
| **Latency** | Không ảnh hưởng | Có thể tăng latency |
| **False positive** | Chỉ gây nhiễu | Có thể chặn nhầm traffic |
| **Rủi ro** | Thấp (chỉ monitor) | Cao (có thể gây gián đoạn) |

---

#### **2.1.3. NIDS (Network-based IDS)**

**Định nghĩa:**
NIDS giám sát toàn bộ traffic mạng trên một hoặc nhiều segments.

**Vị trí triển khai:**
```
Internet
   │
   ├─ Firewall
   │
   ├─ [NIDS Sensor] ← Port mirror from switch
   │
   ├─ Internal Switch
   │     │
   │     ├─ Server 1
   │     ├─ Server 2
   │     └─ Server 3
```

**Đặc điểm:**
- Phân tích packets, flows, sessions
- Có thể reassemble TCP streams
- Hỗ trợ nhiều protocols (HTTP, DNS, TLS, SMB...)
- Khả năng phát hiện network-level attacks

**Ưu điểm:**
- ✅ Giám sát toàn bộ mạng với một sensor
- ✅ Phát hiện attacks giữa các hosts
- ✅ Không cần cài agent trên từng host
- ✅ Khó bị attacker phát hiện và vô hiệu hóa

**Nhược điểm:**
- ❌ Khó phân tích encrypted traffic (TLS/VPN)
- ❌ Performance bottleneck ở high-speed networks (>10Gbps)
- ❌ Không thấy được hoạt động local trên host
- ❌ Bị ảnh hưởng bởi network topology

**Ví dụ NIDS:** Suricata, Snort, Zeek/Bro

---

#### **2.1.4. HIDS (Host-based IDS)**

**Định nghĩa:**
HIDS chạy trực tiếp trên từng host (server, workstation) để giám sát hoạt động của chính hệ thống đó.

**Giám sát:**
- System logs (syslog, Windows Event Logs)
- File integrity (checksums của system files)
- Process activity (process start/stop, parent-child relationships)
- Registry changes (Windows)
- User activity (login/logout, privilege escalation)
- System calls (syscalls monitoring)

**Kiến trúc:**
```
Host (Server/Workstation)
  │
  ├─ [HIDS Agent]
  │     │
  │     ├─ Log Monitor
  │     ├─ File Integrity Checker
  │     ├─ Process Monitor
  │     └─ Network Monitor (local)
  │
  └─ Send alerts to Central Management Server
```

**Ưu điểm:**
- ✅ Phát hiện attacks sau khi bypass network security
- ✅ Thấy được encrypted traffic (sau khi decrypt)
- ✅ Detect insider threats, privilege escalation
- ✅ File integrity monitoring (rootkit detection)
- ✅ Context-aware (biết user nào, process nào)

**Nhược điểm:**
- ❌ Cần cài agent trên MỌI host (quản lý phức tạp)
- ❌ Tốn tài nguyên host (CPU, RAM, disk)
- ❌ Có thể bị attacker vô hiệu hóa nếu chiếm quyền root
- ❌ Không thấy được network-wide attacks

**Ví dụ HIDS:** OSSEC, Wazuh, Tripwire, AIDE

---

**So sánh NIDS vs HIDS:**

| Tiêu chí | NIDS | HIDS |
|----------|------|------|
| **Vị trí** | Network segment | Trên từng host |
| **Giám sát** | Network traffic | System logs, files, processes |
| **Encrypted traffic** | Không thấy được | Thấy được (sau decrypt) |
| **Deployment** | Dễ (1-n sensors) | Khó (agent trên mọi host) |
| **Resource usage** | Không ảnh hưởng hosts | Tốn tài nguyên host |
| **Visibility** | Network-wide | Per-host |
| **Evasion** | Fragmentation, encryption | Disable agent (nếu có root) |

**Xu hướng:** Sử dụng kết hợp NIDS + HIDS để bảo vệ toàn diện:
- NIDS: Phát hiện network attacks, scanning, lateral movement
- HIDS: Phát hiện malware execution, privilege escalation, data exfiltration

---

### 2.2. Phân loại IDS/IPS theo phương pháp phát hiện

#### **2.2.1. Signature-based Detection (Phát hiện dựa trên chữ ký)**

**Nguyên lý:**
So sánh traffic/activity với database các **signatures** (patterns) của attacks đã biết.

**Signature format (Suricata example):**
```
alert http any any -> any any (
  msg:"SQL Injection - UNION SELECT";
  flow:established,to_server;
  content:"union"; nocase; http_uri;
  content:"select"; nocase; http_uri;
  distance:0; within:100;
  classtype:web-application-attack;
  sid:1000001; rev:1;
)
```

**Cách hoạt động:**
```
Incoming packet:
  GET /search?q=test' UNION SELECT password FROM users-- HTTP/1.1

↓ Pattern matching engine

Signature database:
  ✓ Contains "union" + "select" in URI
  ✓ HTTP traffic
  ✓ Match!

→ Alert: "SQL Injection - UNION SELECT"
```

**Ưu điểm:**
- ✅ **Độ chính xác cao:** Ít false positives với signatures chất lượng
- ✅ **Dễ hiểu:** Security analysts dễ đọc và tuning rules
- ✅ **Fast processing:** Pattern matching nhanh (especially với hardware acceleration)
- ✅ **Detailed context:** Rules mô tả rõ attack type, severity, references

**Nhược điểm:**
- ❌ **Chỉ phát hiện known attacks:** Không detect được zero-day, variants
- ❌ **Signature maintenance:** Cần update rules liên tục (emerging threats)
- ❌ **Evasion techniques:** Attackers có thể obfuscate để bypass
  ```
  Original:  ' UNION SELECT
  Obfuscated: ' /*!50000UniOn*/ /*!50000SeLeCt*/
  ```
- ❌ **High volume signatures:** Hàng chục nghìn rules → performance impact

**Ví dụ công cụ:** Suricata, Snort

---

#### **2.2.2. Anomaly-based Detection (Phát hiện dựa trên bất thường)**

**Nguyên lý:**
Xây dựng **baseline** (hành vi bình thường) của mạng/hệ thống, sau đó phát hiện các **deviations** (sai lệch) khỏi baseline.

**Quy trình:**
```
1. Training phase (1-4 weeks):
   Học behavioral patterns:
   - User A thường truy cập: web, email, file server
   - Traffic pattern: 80% HTTP, 15% DNS, 5% SSH
   - Peak hours: 9AM-5PM
   - Average bandwidth: 10Mbps

2. Detection phase:
   Monitor real-time traffic

   Normal: User A → Web server (HTTP) at 10AM
           ✓ Within baseline

   Anomaly: User A → External IP (SSH) at 3AM
            ✓ Unusual time + protocol
            → Alert!
```

**Kỹ thuật Anomaly Detection:**

**1. Statistical Analysis:**
```
Metric: DNS queries per hour
Baseline: Mean = 1000, StdDev = 200

Current: 5000 queries/hour
→ Z-score = (5000 - 1000) / 200 = 20
→ Highly anomalous!
→ Possible DNS tunneling or DDoS
```

**2. Protocol Analysis:**
```
HTTP Request:
  Baseline: Average request size = 500 bytes

  Current request: 10KB in URI
  → Anomaly!
  → Possible SQL injection or buffer overflow
```

**3. Behavioral Analysis:**
```
User behavior:
  Baseline: User accesses 5-10 files/day

  Current: User downloaded 1000 files in 1 hour
  → Anomaly!
  → Possible data exfiltration
```

**4. Machine Learning:**
```
Training data:
  - Normal traffic features: packet sizes, inter-arrival times, protocols...

Algorithm: Random Forest, Neural Networks, SVM

Detection:
  New traffic → Feature extraction → Model prediction
  → Probability of being malicious: 95%
  → Alert!
```

**Ưu điểm:**
- ✅ **Phát hiện unknown attacks:** Zero-days, polymorphic malware, new variants
- ✅ **Adaptive:** Tự điều chỉnh baseline theo thay đổi môi trường
- ✅ **Detect insider threats:** Unusual behavior của legitimate users
- ✅ **Comprehensive:** Không cần biết trước attack signatures

**Nhược điểm:**
- ❌ **High false positive rate:** Hành vi mới (legitimate) cũng bị coi là anomaly
  ```
  Example: Công ty triển khai service mới
  → Traffic pattern thay đổi
  → IDS alert (false positive)
  ```
- ❌ **Training period:** Cần thời gian dài để học baseline chính xác
- ❌ **Baseline poisoning:** Nếu attacker hoạt động trong training phase
  ```
  Attacker âm thầm exfiltrate data trong 2 weeks training
  → Behavior này trở thành "normal"
  → Sau đó không bị phát hiện
  ```
- ❌ **Resource intensive:** ML models tốn CPU/RAM/storage
- ❌ **Difficult to tune:** Cần expertise để điều chỉnh thresholds

**Ví dụ công cụ:** Zeek/Bro (behavior analysis), Darktrace (ML-based), Cisco Stealthwatch

---

#### **2.2.3. Hybrid Detection (Kết hợp)**

**Nguyên lý:**
Sử dụng **cả signature-based VÀ anomaly-based** để tận dụng ưu điểm của cả hai.

**Kiến trúc:**
```
Incoming Traffic
      │
      ├─→ [Signature Engine]
      │        │
      │        ├─ Known attack patterns
      │        └─ → High confidence alerts
      │
      └─→ [Anomaly Engine]
               │
               ├─ Statistical analysis
               ├─ Behavioral baseline
               ├─ ML models
               └─ → Medium confidence alerts

      ↓
[Correlation Engine]
      │
      ├─ Combine alerts from both engines
      ├─ Reduce false positives
      └─ → Final alerts with context
```

**Ví dụ scenario:**

**Scenario 1: Known attack**
```
Traffic: HTTP request with "union select" in URL

Signature Engine: ✓ Match rule #1000001 "SQL Injection"
                  → Alert with high confidence

Anomaly Engine:   ✓ Unusual characters in URL
                  → Alert with medium confidence

Correlation:      Both engines agree
                  → Final alert: HIGH priority
```

**Scenario 2: Zero-day attack**
```
Traffic: Unknown exploit targeting new vulnerability

Signature Engine: ✗ No matching signature
                  → No alert

Anomaly Engine:   ✓ Unusual payload size + rare protocol sequence
                  → Alert with medium confidence

Correlation:      Only anomaly detected
                  → Final alert: MEDIUM priority (investigate)
```

**Scenario 3: False positive reduction**
```
Traffic: Legitimate software update (large download)

Signature Engine: ✗ No match
                  → No alert

Anomaly Engine:   ✓ High bandwidth usage (deviation from baseline)
                  → Alert with low confidence

Correlation:      - Check whitelist (update server)
                  - Check time window (maintenance window)
                  → Suppress alert (known benign)
```

**Ưu điểm:**
- ✅ Detect cả known và unknown attacks
- ✅ Giảm false positives qua correlation
- ✅ Context-aware decisions
- ✅ Flexibility trong tuning

**Nhược điểm:**
- ❌ Phức tạp hơn trong deployment và tuning
- ❌ Tốn tài nguyên hơn (chạy cả 2 engines)
- ❌ Cần expertise cao để vận hành

**Ví dụ:** Suricata (có cả signature rules và anomaly detection features), modern SIEM platforms

---

### 2.3. So sánh các công cụ IDS/IPS phổ biến

#### **2.3.1. Suricata**

**Giới thiệu:**
- Phát triển bởi OISF (Open Information Security Foundation) từ 2009
- Open-source IDS/IPS/NSM engine
- Được thiết kế để thay thế Snort với hiệu năng cao hơn

**Kiến trúc:**
```
┌─────────────────────────────────────────────┐
│            Packet Acquisition               │
│  (AF_PACKET, PF_RING, DPDK, Netmap...)     │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│          Multi-threaded Processing          │
│  ┌────────┐ ┌────────┐ ┌────────┐          │
│  │Thread 1│ │Thread 2│ │Thread N│          │
│  │Decode  │ │Decode  │ │Decode  │          │
│  │Detect  │ │Detect  │ │Detect  │          │
│  │Output  │ │Output  │ │Output  │          │
│  └────────┘ └────────┘ └────────┘          │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│          Protocol Parsers                   │
│  HTTP, TLS, DNS, SMB, SSH, FTP, SMTP...    │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         Detection Engines                   │
│  - Pattern matching (Hyperscan/AC)         │
│  - Protocol anomaly detection              │
│  - File extraction & inspection            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│            Outputs                          │
│  EVE JSON, Syslog, PCAP, Lua scripts...    │
└─────────────────────────────────────────────┘
```

**Tính năng chính:**
- ✅ **Multi-threading:** Tận dụng multi-core CPUs
- ✅ **GPU acceleration:** Hỗ trợ CUDA cho pattern matching
- ✅ **Protocol parsers:** HTTP, TLS, DNS, SMB, SSH, FTP, SMTP, NFS, RDP...
- ✅ **File extraction:** Extract và analyze files từ traffic
- ✅ **Lua scripting:** Mở rộng detection logic
- ✅ **EVE JSON output:** Structured logging cho SIEM integration
- ✅ **Automatic protocol detection:** Không phụ thuộc vào ports
- ✅ **Rust rewrite:** Core components được viết lại bằng Rust (memory-safe)

**Rule format:**
```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET MALWARE Possible Cobalt Strike Beacon";
  flow:established,to_server;
  http.method; content:"GET";
  http.uri; content:"/activity"; startswith;
  http.header; content:"Accept|3a| */*|0d 0a|";
  threshold: type limit, track by_src, count 1, seconds 60;
  reference:url,github.com/bluscreenofjeff/Malleable-C2-Profiles;
  classtype:trojan-activity;
  sid:2029336; rev:2;
)
```

**Ưu điểm:**
- ✅ **Hiệu năng cao:** Multi-threading, hardware acceleration
- ✅ **Modern architecture:** Dễ mở rộng và maintain
- ✅ **Rich protocol support:** Deep packet inspection cho nhiều protocols
- ✅ **JSON logging:** Dễ tích hợp với ELK, Splunk, Graylog...
- ✅ **Active development:** Community và commercial support mạnh

**Nhược điểm:**
- ❌ **Memory usage:** Tốn RAM hơn Snort (do multi-threading)
- ❌ **Configuration complexity:** Nhiều options cần tuning
- ❌ **Rules compatibility:** Không 100% compatible với Snort rules

**Use cases:**
- High-speed networks (10Gbps+)
- SOC/SIEM integration (JSON logs)
- Threat hunting (file extraction, protocol logs)
- Cloud environments (AWS, Azure, GCP)

---

#### **2.3.2. Snort**

**Giới thiệu:**
- Phát triển bởi Martin Roesch từ 1998 (Cisco mua lại 2013)
- IDS/IPS phổ biến nhất thế giới
- Hiện có Snort 2 (legacy) và Snort 3 (hiện đại)

**Kiến trúc (Snort 3):**
```
┌─────────────────────────────────────────────┐
│         Packet I/O (DAQ)                    │
│  AF_PACKET, NFQ, DPDK, Netmap...            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         Decoder & Preprocessors             │
│  Ethernet, IP, TCP, UDP, ICMP...           │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│        Detection Engine                     │
│  Pattern matching (Hyperscan)              │
│  Rule evaluation                            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         Logging & Alerting                  │
│  unified2, syslog, JSON...                 │
└─────────────────────────────────────────────┘
```

**Rule format:**
```
alert tcp any any -> $HOME_NET 22 (
  msg:"GPL SCAN SSH brute force login attempt";
  flow:to_server,established;
  content:"SSH-"; depth:4;
  detection_filter:track by_src, count 5, seconds 60;
  reference:arachnids,127;
  classtype:misc-attack;
  sid:2001219; rev:9;
)
```

**Tính năng chính:**
- ✅ **Mature & stable:** 25+ years development
- ✅ **Large rule community:** Snort rules, Emerging Threats, Talos
- ✅ **Preprocessors:** Stream reassembly, HTTP inspect, SMB inspect...
- ✅ **Snort 3 improvements:** Multi-threading, plugin architecture, LuaJIT scripting

**Snort 2 vs Snort 3:**

| Feature | Snort 2 | Snort 3 |
|---------|---------|---------|
| **Threading** | Single-threaded | Multi-threaded |
| **Config** | snort.conf (complex) | snort.lua (cleaner) |
| **Performance** | ~2-3 Gbps | ~10 Gbps |
| **Scripting** | None | LuaJIT |
| **Plugin API** | Limited | Extensive |

**Ưu điểm:**
- ✅ **Industry standard:** Được sử dụng rộng rãi nhất
- ✅ **Rule availability:** Hàng chục nghìn rules từ community
- ✅ **Documentation:** Tài liệu phong phú, tutorials, books
- ✅ **Cisco support:** Commercial support từ Cisco Talos
- ✅ **Low memory footprint:** Snort 2 rất nhẹ

**Nhược điểm:**
- ❌ **Snort 2 performance:** Single-threaded, không scale với multi-core
- ❌ **Snort 3 adoption:** Chưa phổ biến như Snort 2, rules migration cần effort
- ❌ **Configuration:** Snort 2 config phức tạp
- ❌ **Limited protocol support:** Ít protocol parsers hơn Suricata

**Use cases:**
- Traditional network perimeter defense
- Environments cần stability hơn cutting-edge features
- Integration với Cisco ecosystem (Firepower)

---

#### **2.3.3. Zeek (formerly Bro)**

**Giới thiệu:**
- Phát triển từ 1995 tại Lawrence Berkeley National Lab
- Đổi tên từ "Bro" thành "Zeek" năm 2018
- **Network Security Monitor (NSM)** hơn là pure IDS/IPS

**Triết lý khác biệt:**
- Không focus vào signature-based detection
- Mục tiêu: Cung cấp **visibility** và **context** về network activity
- Generate structured logs để analysts phân tích

**Kiến trúc:**
```
┌─────────────────────────────────────────────┐
│         Packet Capture                      │
│  libpcap, AF_PACKET, PF_RING...            │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│       Event Engine                          │
│  Convert packets → Events                   │
│  (connection_established, http_request...)  │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│       Policy Scripts (Zeek language)        │
│  Default scripts + Custom scripts           │
│  Event handlers → Actions                   │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         Logging Framework                   │
│  conn.log, http.log, dns.log, ssl.log...   │
└─────────────────────────────────────────────┘
```

**Logs chính:**

| Log File | Nội dung |
|----------|----------|
| **conn.log** | Tất cả network connections (5-tuple, duration, bytes, state) |
| **http.log** | HTTP requests/responses (method, URI, status, user-agent...) |
| **dns.log** | DNS queries/responses (query, answer, TTL...) |
| **ssl.log** | TLS handshakes (version, cipher, certificate...) |
| **files.log** | Files transferred qua protocols (MD5, SHA1, MIME type...) |
| **smtp.log** | Email metadata (from, to, subject, attachments...) |
| **ssh.log** | SSH connections (version, authentication...) |
| **weird.log** | Protocol anomalies |

**Ví dụ conn.log:**
```
ts=1609459200.000000
uid=CHhAvVGS1DHFjwGM9
id.orig_h=192.168.1.100
id.orig_p=54321
id.resp_h=93.184.216.34
id.resp_p=443
proto=tcp
service=ssl
duration=120.5
orig_bytes=5432
resp_bytes=102400
conn_state=SF
```

**Zeek Scripting (detect DNS tunneling):**
```zeek
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
  # Detect unusually long DNS queries (possible tunneling)
  if (|query| > 50) {
    NOTICE([
      $note=DNS::Suspicious_Query_Length,
      $msg=fmt("Long DNS query: %s", query),
      $conn=c
    ]);
  }

  # Detect high entropy domain names (DGA)
  local entropy = calculate_entropy(query);
  if (entropy > 4.5) {
    NOTICE([
      $note=DNS::High_Entropy_Domain,
      $msg=fmt("DGA domain detected: %s (entropy: %.2f)", query, entropy),
      $conn=c
    ]);
  }
}
```

**Tính năng chính:**
- ✅ **Protocol analysis:** Deep parsing cho HTTP, DNS, TLS, SMB, RDP, SSH...
- ✅ **File extraction:** Extract files, calculate hashes, submit to sandboxes
- ✅ **Scripting:** Turing-complete language để custom detection logic
- ✅ **Intelligence framework:** Integrate threat intel feeds (IP, domain, hash blacklists)
- ✅ **Cluster support:** Distributed processing trên nhiều nodes

**Ưu điểm:**
- ✅ **Network visibility:** Rich logs → SOC analysts có context đầy đủ
- ✅ **Flexible detection:** Scripts dễ viết hơn Snort/Suricata rules cho complex logic
- ✅ **Threat hunting:** Logs là goldmine cho retrospective analysis
- ✅ **Protocol anomaly detection:** Built-in weird.log
- ✅ **Integration friendly:** Logs dễ parse, integrate với SIEM/Splunk

**Nhược điểm:**
- ❌ **Không phải IPS:** Không có inline blocking (chỉ là monitor)
- ❌ **Steep learning curve:** Zeek scripting language khác biệt
- ❌ **Resource intensive:** Tốn CPU/RAM/disk cho logging
- ❌ **Not real-time alerting focused:** Cần combine với other tools (SIEM) để alert

**Use cases:**
- Network forensics & incident response
- Threat hunting
- SOC environments (combined với SIEM)
- Compliance logging (PCI-DSS, HIPAA...)

---

#### **2.3.4. So sánh tổng hợp: Suricata vs Snort vs Zeek**

| Tiêu chí | Suricata | Snort | Zeek |
|----------|----------|-------|------|
| **Loại** | IDS/IPS/NSM | IDS/IPS | NSM (Network Monitor) |
| **Phát triển** | OISF (2009) | Cisco/Talos (1998) | Open-source (1995) |
| **Detection** | Signature + Anomaly | Signature-based | Behavior/Anomaly-based |
| **Multi-threading** | ✅ Yes | ❌ No (Snort 2)<br>✅ Yes (Snort 3) | ⚠️ Cluster mode |
| **Hiệu năng** | 10-40 Gbps | 2-3 Gbps (Snort 2)<br>10 Gbps (Snort 3) | 1-10 Gbps (depends on scripts) |
| **Memory usage** | High (2-8GB) | Low (512MB-2GB) | Very High (4-16GB) |
| **Protocol parsers** | 20+ protocols | ~10 protocols | 30+ protocols |
| **Inline blocking** | ✅ Yes (IPS mode) | ✅ Yes (IPS mode) | ❌ No |
| **Logging** | EVE JSON, unified2 | unified2, JSON | TSV logs (conn, http, dns...) |
| **Rule format** | Snort-like + Suricata keywords | Snort rules | Zeek scripts (custom language) |
| **Scripting** | Lua | LuaJIT (Snort 3) | Zeek language |
| **File extraction** | ✅ Yes | ⚠️ Limited | ✅ Yes (with hashing) |
| **TLS/SSL inspection** | ✅ JA3, cert validation | ⚠️ Basic | ✅ Full cert logging |
| **Community** | Growing | Largest | Academic + Enterprise |
| **Commercial support** | Stamus Networks, OISF | Cisco Talos | Corelight |
| **Use case** | High-speed IPS, SOC | Traditional IDS/IPS | Threat hunting, forensics |

**Khi nào dùng gì:**

**Chọn Suricata nếu:**
- Cần hiệu năng cao (10Gbps+)
- Multi-core CPUs có sẵn
- Cần JSON logs cho SIEM integration
- Muốn modern IDS/IPS với active development

**Chọn Snort nếu:**
- Cần stability, proven solution
- Cisco ecosystem (Firepower)
- Rule availability là priority
- Low-resource environments (Snort 2)

**Chọn Zeek nếu:**
- Focus vào network visibility, không cần blocking
- Threat hunting, incident response
- Cần detailed protocol logs
- Custom detection logic phức tạp

**Xu hướng:** Sử dụng **cả ba cùng lúc**:
- **Suricata/Snort:** Real-time IDS/IPS alerting
- **Zeek:** Network traffic logging & context
- **SIEM (Splunk/ELK):** Aggregate alerts + logs từ cả 3 tools

---

### 2.4. Ưu nhược điểm và so sánh chi tiết

#### **2.4.1. Hiệu năng (Performance)**

**Throughput (Gbps):**

| Tool | Single-threaded | Multi-threaded | Hardware-accelerated |
|------|----------------|----------------|---------------------|
| **Suricata** | ~2 Gbps | 10-40 Gbps | 40-100 Gbps (GPU/FPGA) |
| **Snort 2** | 2-3 Gbps | N/A | ~5 Gbps (với DAQ modules) |
| **Snort 3** | ~3 Gbps | 10-20 Gbps | 20-40 Gbps |
| **Zeek** | ~1 Gbps | 5-10 Gbps (cluster) | N/A |

**Packet loss benchmark (10 Gbps link, full ruleset):**

```
Test setup:
- 10 Gbps network interface
- 30,000 rules enabled
- Full pcap replay

Results:
┌──────────┬──────────────┬──────────────┐
│   Tool   │ Packet Loss  │  CPU Cores   │
├──────────┼──────────────┼──────────────┤
│ Suricata │     <1%      │      16      │
│ Snort 2  │     15%      │       1      │
│ Snort 3  │      2%      │      12      │
│ Zeek     │      5%      │   8 (cluster)│
└──────────┴──────────────┴──────────────┘
```

**CPU efficiency:**
- **Suricata:** Tốt nhất với multi-core (tận dụng 16+ cores)
- **Snort 3:** Tốt (8-16 cores)
- **Snort 2:** Chỉ 1 core → không scale
- **Zeek:** Cluster mode phức tạp, overhead cao

---

#### **2.4.2. Khả năng mở rộng (Scalability)**

**Vertical scaling (single machine):**

| Tool | Max cores | Max throughput | Bottleneck |
|------|-----------|----------------|------------|
| Suricata | 64+ cores | 40 Gbps | Memory bandwidth |
| Snort 3 | 32 cores | 20 Gbps | Detection engine |
| Zeek | 16 cores | 10 Gbps | Logging I/O |

**Horizontal scaling (distributed):**

**Suricata:**
```
         ┌──────────┐
Traffic ─┤ Load     ├─┐
         │ Balancer │ │
         └──────────┘ │
                      ├─→ [Suricata Node 1] → Logs → SIEM
                      ├─→ [Suricata Node 2] → Logs → SIEM
                      └─→ [Suricata Node N] → Logs → SIEM
```
- Dễ scale: Mỗi node độc lập
- Load balancing: RSS, AF_PACKET fanout, PF_RING

**Zeek Cluster:**
```
Traffic ─→ [Proxy] ─┬─→ [Worker 1] ─┐
                    ├─→ [Worker 2] ─┤
                    └─→ [Worker N] ─┴─→ [Manager] ─→ Logs
```
- Phức tạp: Cần manager + proxy + workers
- Communication overhead giữa nodes

---

#### **2.4.3. Độ chính xác (Accuracy)**

**False Positive Rate (FPR):**

Phụ thuộc vào:
1. **Rule quality:** Commercial rules < Community rules
2. **Tuning:** Mặc định có FPR cao, cần suppress/threshold
3. **Environment:** Rules viết cho enterprise có thể không fit SMB

**Thực tế:**

| Scenario | Suricata | Snort | Zeek |
|----------|----------|-------|------|
| **Default rules, no tuning** | 10-20 FP/day | 15-25 FP/day | 5-10 FP/day |
| **After 1 month tuning** | 1-3 FP/day | 1-2 FP/day | 0-1 FP/day |
| **With threat intel feeds** | 20-50 FP/day | 25-60 FP/day | 5-15 FP/day |

**False Negative Rate (FNR):**

Khó đo lường (cần biết ground truth), nhưng:
- **Signature-based (Suricata/Snort):** FNR cao cho zero-days, obfuscated attacks
- **Anomaly-based (Zeek):** FNR thấp hơn cho unknown attacks, cao hơn cho stealthy attacks

**Detection rate (public datasets):**

```
Dataset: CICIDS2017 (labeled attack traffic)

Detection Rate:
├─ Suricata (ET Open): 75%
├─ Snort (Community): 72%
└─ Zeek (default scripts): 65%

Detection Rate (with tuning + custom rules):
├─ Suricata: 92%
├─ Snort: 90%
└─ Zeek: 88%
```

---

#### **2.4.4. Khả năng tích hợp (Integration)**

**SIEM Integration:**

| Tool | Output Format | SIEM Support |
|------|---------------|--------------|
| **Suricata** | EVE JSON | ⭐⭐⭐⭐⭐ Excellent |
| **Snort** | unified2 (binary) | ⭐⭐⭐ Good (need barnyard2) |
| **Zeek** | TSV logs | ⭐⭐⭐⭐⭐ Excellent |

**Suricata EVE JSON example:**
```json
{
  "timestamp": "2024-01-15T10:30:00.123456+0000",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "10.0.0.5",
  "dest_ip": "93.184.216.34",
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "signature": "ET MALWARE CobaltStrike Beacon",
    "category": "A Network Trojan was Detected",
    "severity": 1
  },
  "http": {
    "hostname": "malicious.com",
    "url": "/beacon",
    "http_method": "GET",
    "http_user_agent": "Mozilla/5.0..."
  }
}
```
→ Dễ parse, index, query trong ELK/Splunk

**Snort unified2:**
- Binary format → cần barnyard2 để convert sang syslog/database
- Phức tạp hơn, latency cao hơn

**Zeek logs:**
```tsv
# conn.log
1610712000.000000  CHhAv...  192.168.1.100  54321  93.184.216.34  443  tcp  ssl  120.5  5432  102400  SF
```
→ TSV format, dễ parse bằng awk/python/logstash

**Threat Intelligence Integration:**

| Tool | Intel Feeds | Format |
|------|-------------|--------|
| Suricata | ✅ IP, Domain, Hash, JA3 | Rules, datasets |
| Snort | ✅ IP, Rules | Snort rules, IP lists |
| Zeek | ✅ IP, Domain, Hash, URL, Email | Intel framework (TSV) |

**Zeek Intelligence Framework example:**
```
# intel.dat
#fields  indicator  indicator_type  meta.source  meta.desc
1.2.3.4  Intel::ADDR  ThreatFeed  C2 Server
evil.com  Intel::DOMAIN  ThreatFeed  Phishing domain
44d88612fea8a8f36de82e1278abb02f  Intel::FILE_HASH  VirusTotal  Malware MD5
```

---

#### **2.4.5. Ease of Use (Dễ sử dụng)**

**Installation:**

| Tool | Difficulty | Package Manager | Build from Source |
|------|-----------|----------------|------------------|
| Suricata | ⭐⭐⭐ Medium | `apt install suricata` | Moderate |
| Snort 2 | ⭐⭐ Easy | `apt install snort` | Easy |
| Snort 3 | ⭐⭐⭐⭐ Hard | Not in repos | Complex (many deps) |
| Zeek | ⭐⭐⭐⭐ Hard | `apt install zeek` | Complex |

**Configuration:**

**Suricata (`suricata.yaml`):**
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
  port-groups:
    HTTP_PORTS: "80"

af-packet:
  - interface: eth0
    threads: 16
    cluster-type: cluster_flow

outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        - http
        - dns
        - tls
```
→ YAML format, intuitive, well-documented

**Snort 2 (`snort.conf`):**
```
var HOME_NET 192.168.0.0/16
var EXTERNAL_NET !$HOME_NET

preprocessor stream5_global: ...
preprocessor http_inspect: ...
preprocessor smtp: ...

include $RULE_PATH/community.rules
include $RULE_PATH/emerging-threats.rules

output alert_fast: alerts.log
output unified2: filename snort.u2
```
→ Config phức tạp, nhiều preprocessor options

**Zeek (scripts):**
```zeek
@load base/frameworks/notice
@load policy/protocols/conn/known-hosts
@load policy/protocols/http/detect-sqli

redef Site::local_nets = { 192.168.0.0/16 };
```
→ Scripting-based, flexible nhưng cần học Zeek language

**Learning Curve:**

```
Difficulty over time:

  High │                          ╱ Zeek
       │                    ╱────╯
       │              ╱────╯ Suricata
Medium │        ╱────╯
       │  ╱────╯ Snort 2
   Low │─╯
       └────────────────────────────→
         Week 1    Month 1    Month 3
```

---

#### **2.4.6. Community & Support**

| Tool | Community Size | Documentation | Commercial Support |
|------|---------------|---------------|-------------------|
| Suricata | ⭐⭐⭐⭐ Large | ⭐⭐⭐⭐⭐ Excellent | Stamus Networks, OISF |
| Snort | ⭐⭐⭐⭐⭐ Largest | ⭐⭐⭐⭐ Good | Cisco Talos |
| Zeek | ⭐⭐⭐ Medium | ⭐⭐⭐⭐ Good | Corelight |

**Rule sources:**

| Source | Suricata | Snort | Cost |
|--------|----------|-------|------|
| Emerging Threats Open | ✅ | ✅ | Free |
| Emerging Threats Pro | ✅ | ✅ | $1000+/year |
| Snort Community Rules | ✅ | ✅ | Free |
| Snort Registered Rules | ✅ | ✅ | Free (30-day delay) |
| Snort Subscriber Rules | ❌ | ✅ | Paid |
| Cisco Talos | ⚠️ | ✅ | Paid |

---

### 2.5. Tóm tắt và khuyến nghị

**Decision Matrix:**

```
┌─────────────────────┬──────────┬──────────┬──────────┐
│ Requirement         │ Suricata │ Snort    │ Zeek     │
├─────────────────────┼──────────┼──────────┼──────────┤
│ High throughput     │    ✅    │  ⚠️ (S3) │    ❌    │
│ Real-time blocking  │    ✅    │    ✅    │    ❌    │
│ Network visibility  │    ⭐⭐  │    ⭐    │   ⭐⭐⭐  │
│ Threat hunting      │    ⭐⭐  │    ⭐    │   ⭐⭐⭐  │
│ Easy deployment     │    ⭐⭐  │   ⭐⭐⭐  │    ⭐    │
│ Low resource        │    ❌    │    ✅    │    ❌    │
│ Protocol analysis   │   ⭐⭐⭐  │    ⭐⭐  │   ⭐⭐⭐  │
│ SIEM integration    │   ⭐⭐⭐  │    ⭐⭐  │   ⭐⭐⭐  │
│ Community support   │   ⭐⭐⭐  │   ⭐⭐⭐  │    ⭐⭐  │
└─────────────────────┴──────────┴──────────┴──────────┘
```

**Khuyến nghị triển khai:**

**Enterprise Network (Large):**
```
Internet
   │
   ├─ Firewall
   │
   ├─ [Suricata IPS - Inline] → Block threats
   │
   ├─ Core Switch
   │     │
   │     ├─ [Zeek Cluster - TAP] → Logging & visibility
   │     │
   │     └─ Servers/Workstations
   │
   └─ SIEM (Splunk/ELK)
        ├─ Suricata alerts (EVE JSON)
        └─ Zeek logs (conn, http, dns, tls...)
```

**SMB Network (Small-Medium):**
```
Internet → Firewall → [Suricata IDS - Mirror port] → SIEM
                            │
                            └─ Internal LAN
```

**SOC/Threat Hunting Team:**
```
Suricata: Real-time alerting
Zeek: Deep protocol logging, file extraction
SIEM: Correlation, dashboards
Threat Intel: Feeds integration
```

---

## 🎯 Tổng kết Part 2

Sau khi hoàn thành Part 2, bạn đã nắm vững:

✅ **Khái niệm IDS/IPS:** Sự khác biệt giữa IDS (passive) và IPS (active/inline)

✅ **NIDS vs HIDS:** Network-based và Host-based detection, ưu nhược điểm

✅ **Phương pháp phát hiện:**
- Signature-based: Nhanh, chính xác cho known attacks
- Anomaly-based: Phát hiện unknown attacks, false positive cao
- Hybrid: Kết hợp cả hai

✅ **So sánh công cụ:**
- **Suricata:** High-performance IDS/IPS, multi-threading, JSON logging
- **Snort:** Industry standard, largest community, Snort 3 modernized
- **Zeek:** Network visibility & forensics, rich protocol logs, không phải IPS

✅ **Đánh giá:**
- **Hiệu năng:** Suricata > Snort 3 > Zeek > Snort 2
- **Độ chính xác:** Cần tuning, phụ thuộc rule quality
- **Tích hợp:** Suricata (EVE JSON) và Zeek (TSV) tốt nhất cho SIEM
- **Dễ dùng:** Snort 2 > Suricata > Snort 3 > Zeek

→ **Bạn đã sẵn sàng để triển khai và vận hành IDS/IPS trong môi trường thực tế!**

---

**Tiếp theo: Part 3 sẽ đi sâu vào Suricata installation, configuration, rule writing, và tuning performance.**
