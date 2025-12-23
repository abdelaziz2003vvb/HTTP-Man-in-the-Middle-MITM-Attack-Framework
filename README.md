# HTTP Man-in-the-Middle (MITM) Attack Framework

A Python-based Man-in-the-Middle attack framework for intercepting and analyzing HTTP traffic on local networks. Uses ARP spoofing to redirect traffic and Scapy to capture HTTP POST requests containing login credentials.

## ⚠️ Legal Disclaimer

**CRITICAL WARNING**: These tools are provided for educational purposes and authorized penetration testing ONLY. 

Unauthorized interception of network traffic, ARP spoofing, or credential harvesting is **ILLEGAL** and punishable by:
- Criminal prosecution under computer fraud laws (CFAA, Computer Misuse Act, etc.)
- Heavy fines and imprisonment
- Civil lawsuits for damages
- Loss of professional certifications

**Only use these tools on networks you own or have explicit written permission to test.**

## What is This Framework?

This is a complete Man-in-the-Middle attack implementation that:

1. **Positions your machine** between a target device and the network gateway using ARP spoofing
2. **Intercepts all HTTP traffic** flowing through your machine
3. **Captures credentials** from HTTP POST requests (login forms, etc.)
4. **Maintains the connection** by forwarding traffic transparently

### Why HTTP?

HTTP traffic is **unencrypted**, making credentials and data visible in plain text. This framework specifically targets:
- Login credentials (username/password)
- Form submissions
- User data in POST requests
- Any information sent over HTTP

**Note**: HTTPS traffic is encrypted end-to-end and cannot be read with this basic setup. However, many IoT devices, legacy systems, and internal applications still use HTTP.

## Tools Included

### 1. ARP Spoofer (`spoofer.py`)
**Purpose**: Poisons the ARP cache of both the target and gateway to redirect traffic through your machine.

**How it works**:
- Sends forged ARP replies every 2 seconds
- Tells the victim: "I am the router"
- Tells the router: "I am the victim"
- Automatically restores ARP tables on exit

**Key Features**:
- MAC address resolution for target and gateway
- Continuous ARP poisoning with packet counting
- Graceful network restoration with Ctrl+C
- Non-flooding design (2-second intervals)

### 2. HTTP Packet Sniffer (`sniffer.py`)
**Purpose**: Captures and analyzes HTTP POST requests to extract login credentials.

**What it captures**:
- Full URLs (host + path) from HTTP requests
- POST request data containing keywords like:
  - username, user, login
  - password, pass
  - uname
- Raw payload data from suspicious requests

**Key Features**:
- Filters specifically for HTTP POST requests
- Keyword detection for credential fields
- Error handling for malformed packets
- Real-time display of captured credentials

## Attack Flow Diagram

```
Normal Network Flow:
┌─────────────┐         ┌─────────┐         ┌──────────┐
│   Target    │ ◄─────► │  Router │ ◄─────► │ Internet │
│  (Victim)   │         │(Gateway)│         │          │
└─────────────┘         └─────────┘         └──────────┘

MITM Attack Flow:
┌─────────────┐         ┌──────────────┐         ┌─────────┐         ┌──────────┐
│   Target    │ ◄─────► │ Your Machine │ ◄─────► │  Router │ ◄─────► │ Internet │
│  (Victim)   │         │  (Attacker)  │         │(Gateway)│         │          │
└─────────────┘         └──────────────┘         └─────────┘         └──────────┘
                         ↓ Intercepts &
                         ↓ Analyzes HTTP
                         ↓ POST Requests
```

## Prerequisites

### System Requirements
- Linux-based OS (Kali Linux, Ubuntu, Parrot OS)
- Python 3.x
- Root/sudo privileges
- Network interface in same subnet as target

### Python Dependencies
```bash
pip install scapy
# or
pip install scapy-python3
```

### Verify Network Interface
Check your network interface name:
```bash
ip a
# or
ifconfig
```

Common interface names: `eth0`, `wlan0`, `ens33`, `wlp2s0`

## Setup & Configuration

### 1. Configure Target IPs

Edit `spoofer.py` and set these variables:

```python
VICTIM_IP = "192.168.100.26"    # Target machine IP
GATEWAY_IP = "192.168.100.1"    # Router IP (usually .1 or .254)
```

**How to find these IPs**:

On the target machine (Windows):
```cmd
ipconfig
```

On Linux target:
```bash
ip route | grep default
```

Your gateway is typically the first or last IP in your subnet (e.g., 192.168.1.1, 192.168.0.254).

### 2. Configure Network Interface

Edit `sniffer.py` and set your interface:

```python
sniff_packets("eth0")  # Change to your interface name
```

### 3. Enable IP Forwarding

**CRITICAL**: Without this, the target will lose internet connectivity and the attack will be obvious.

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Verify it's enabled:
```bash
cat /proc/sys/net/ipv4/ip_forward
# Should return: 1
```

To make permanent (optional):
```bash
sudo nano /etc/sysctl.conf
# Add: net.ipv4.ip_forward=1
sudo sysctl -p
```

## Complete Attack Workflow

### Step 1: Enable IP Forwarding
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Step 2: Start ARP Spoofing
Open first terminal:
```bash
sudo python3 spoofer.py
```

You should see:
```
[*] Lancement de l'attaque ARP Spoofing...
[+] Paquets envoyés: 2
[+] Paquets envoyés: 4
[+] Paquets envoyés: 6
...
```

### Step 3: Start Packet Sniffing
Open second terminal:
```bash
sudo python3 sniffer.py
```

You should see:
```
[*] Sniffer en écoute sur eth0...
```

### Step 4: Wait for HTTP POST Requests

When the victim submits a login form over HTTP, you'll see:

```
------------------------------
[!!!] POTENTIEL MOT DE PASSE TROUVÉ !
URL: example.com/login
DONNÉES: username=admin&password=secret123
------------------------------
```

### Step 5: Stop the Attack

Press `Ctrl+C` in the spoofer terminal first. It will automatically restore the network:
```
[!] Arrêt de l'attaque. Restauration du réseau...
[+] Réseau restauré.
```

Then stop the sniffer with `Ctrl+C`.

### Step 6: Disable IP Forwarding
```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## Understanding the Code

### ARP Spoofing Process

```python
def spoof(target_ip, spoof_ip):
    # Gets target's MAC address
    target_mac = get_mac(target_ip)
    # Creates ARP reply (op=2) claiming to be spoof_ip
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)
```

**What happens**:
1. Resolves target's MAC address
2. Creates ARP reply packet
3. Claims your machine has the IP of the spoof_ip
4. Sent to target's MAC address

### HTTP POST Detection

```python
if packet[HTTPRequest].Method == b"POST":
    url = get_url(packet)
    login_info = get_login_info(packet)
```

**What it does**:
1. Filters for HTTP POST requests only (where credentials are sent)
2. Extracts the full URL
3. Searches payload for keywords: username, password, login, pass, user, uname
4. Displays captured data if keywords found

## Troubleshooting

### "Permission denied" Error
**Solution**: Run with sudo
```bash
sudo python3 spoofer.py
sudo python3 sniffer.py
```

### "Impossible de trouver l'adresse MAC"
**Causes**:
- Wrong IP address
- Target is offline
- Not on same subnet
- Firewall blocking ARP

**Solution**: 
```bash
# Verify target is reachable
ping 192.168.100.26

# Verify gateway
ip route | grep default
```

### No Packets Captured
**Causes**:
- Wrong network interface in sniffer.py
- IP forwarding not enabled
- Target not using HTTP (only HTTPS)

**Solution**:
```bash
# Check interface
ip a

# Verify forwarding
cat /proc/sys/net/ipv4/ip_forward

# Test with HTTP site (not HTTPS)
# On target, visit: http://testphp.vulnweb.com
```

### Target Loses Internet
**Cause**: IP forwarding is disabled

**Solution**:
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Only Seeing GET Requests
**Expected**: The sniffer only displays POST requests (where credentials are sent). GET requests are ignored by design.

## Detection & Defense

### How to Detect This Attack

**On Target Machine**:
```bash
# Check ARP table for duplicate IPs
arp -a
# Look for same MAC address with different IPs
```

**On Network**:
- Use ARP spoofing detection tools: `arpwatch`, `XArp`
- Monitor for excessive ARP traffic
- IDS/IPS alerts (Snort, Suricata)
- Sudden increase in network latency

### How to Defend Against This Attack

**For Users**:
1. **Use HTTPS everywhere** - Forces encrypted connections
2. **VPN** - Encrypts all traffic at network layer
3. **HSTS** - HTTP Strict Transport Security
4. **Static ARP entries** - Prevents ARP cache poisoning (on critical machines)

**For Network Administrators**:
1. **Port security** - Limit MAC addresses per switch port
2. **Dynamic ARP Inspection (DAI)** - Validates ARP packets
3. **DHCP Snooping** - Prevents DHCP-based attacks
4. **Network segmentation** - Isolate sensitive systems
5. **802.1X authentication** - Authenticates devices before network access

## Common Target Scenarios

### Scenario 1: Public WiFi Attack
- **Location**: Coffee shop, airport, hotel
- **Target**: Users on same network
- **Risk**: High (many HTTP sites, careless users)

### Scenario 2: Corporate Network Testing
- **Location**: Internal company network
- **Target**: Employees, internal systems
- **Risk**: Medium (testing for insecure internal apps)

### Scenario 3: IoT Device Analysis
- **Location**: Home network
- **Target**: Smart devices, IP cameras
- **Risk**: High (many IoT devices use HTTP)

### Scenario 4: Legacy System Assessment
- **Location**: Industrial networks
- **Target**: Old web interfaces, SCADA systems
- **Risk**: Critical (often no encryption)

## Limitations

### What This Tool CANNOT Do:
- ✗ Decrypt HTTPS traffic (requires SSL stripping/certificate attacks)
- ✗ Capture traffic outside your subnet
- ✗ Work on switched networks with port security enabled
- ✗ Bypass VPN encryption
- ✗ Defeat static ARP entries
- ✗ Work on networks with DAI enabled

### What This Tool CAN Do:
- ✓ Capture HTTP POST credentials
- ✓ Intercept unencrypted traffic
- ✓ Demonstrate ARP spoofing vulnerabilities
- ✓ Test network security posture
- ✓ Capture IoT device communications

## Legal & Ethical Considerations

### When This is LEGAL:
- ✓ Your own network and devices
- ✓ Authorized penetration testing with written contract
- ✓ Security research in isolated lab environment
- ✓ Educational purposes in controlled environment (university lab)

### When This is ILLEGAL:
- ✗ Public WiFi networks without authorization
- ✗ Corporate networks without explicit permission
- ✗ Any network you don't own or have permission to test
- ✗ "Just testing" on neighbors/friends without written consent

### Consequences of Illegal Use:
- **Criminal charges**: Computer fraud, unauthorized access, wiretapping
- **Fines**: $10,000 - $250,000+ depending on jurisdiction
- **Imprisonment**: 1-20 years depending on severity and location
- **Civil lawsuits**: Victims can sue for damages
- **Career destruction**: Permanent criminal record, loss of certifications

## Testing in Safe Environment

### Setup a Test Lab:
1. Use virtual machines (VirtualBox, VMware)
2. Create isolated network (host-only or NAT)
3. Set up vulnerable web app (DVWA, WebGoat)
4. Test VM as target
5. Kali Linux VM as attacker

### Test Environment Configuration:
```
┌─────────────────┐         ┌──────────────────┐
│  Kali Linux VM  │         │  Windows/Ubuntu  │
│   (Attacker)    │ ◄─────► │     VM (Target)  │
│  192.168.56.10  │         │  192.168.56.20   │
└─────────────────┘         └──────────────────┘
         │                           │
         └───────────┬───────────────┘
               Host-Only Network
              192.168.56.0/24
```

## Additional Resources

### Learn More About:
- **Scapy Documentation**: https://scapy.readthedocs.io/
- **ARP Protocol (RFC 826)**: https://www.ietf.org/rfc/rfc826.txt
- **MITM Attacks**: OWASP Man-in-the-Middle Guide
- **Network Security**: CEH, OSCP, Network+ certifications

### Practice Legally:
- **HackTheBox**: Legal penetration testing labs
- **TryHackMe**: Guided security learning
- **PentesterLab**: Web app security exercises
- **DVWA**: Damn Vulnerable Web Application

## Contributing

This project is for educational purposes. Contributions should:
- Maintain ethical use guidelines
- Improve detection evasion for learning
- Add defensive techniques
- Enhance documentation

## Author Notes

This framework demonstrates a fundamental network attack that has existed for decades. While modern networks have defenses, many environments remain vulnerable. Understanding this attack is crucial for:
- Security professionals
- Network administrators
- Developers building secure applications
- Anyone wanting to understand network security

**Remember**: The goal is to learn security, not to harm others. Use responsibly.

## License

Educational use only. The authors assume no liability for misuse of these tools.

---

**Final Warning**: With great power comes great responsibility. This tool can cause real harm. Use it ethically, legally, and only in authorized environments. When in doubt, DON'T.
