# HTTP Man-in-the-Middle (MITM) Attack Framework

A Python-based Man-in-the-Middle attack framework for intercepting and analyzing HTTP traffic on local networks. Designed for educational and authorized penetration testing purposes.

## ⚠️ Legal Disclaimer

**IMPORTANT**: These tools are provided for educational purposes and authorized security testing only. Unauthorized interception of network traffic, ARP spoofing, or manipulation of network communications is illegal in most jurisdictions. Only use these tools on networks you own or have explicit written permission to test.

## Tools Included

### 1. ARP Spoofer (`spoofer.py`)
Performs ARP spoofing to position your machine as a man-in-the-middle between a target and the network gateway, intercepting all traffic flowing between them.

### 2. Network Packet Sniffer (`sniffer.py`)
Captures and analyzes HTTP traffic passing through your machine, extracting URLs, form data, and potential credentials from unencrypted HTTP requests.

## What is a Man-in-the-Middle Attack?

A Man-in-the-Middle (MITM) attack intercepts communication between two parties without their knowledge. This framework uses:

1. **ARP Spoofing**: Tricks the target device and router into sending their traffic through your machine
2. **Packet Sniffing**: Captures and analyzes the redirected traffic, particularly HTTP requests
3. **Traffic Forwarding**: Passes traffic between parties so the attack remains undetected

### Why HTTP?

HTTP traffic is **unencrypted**, making it vulnerable to interception. This framework can capture:
- Login credentials sent over HTTP
- Form submissions and POST data
- Cookies and session tokens
- Browsing history and URLs visited
- Any data transmitted without HTTPS encryption

**Note**: HTTPS traffic is encrypted and cannot be easily read with this basic MITM setup. Modern websites use HTTPS, making this attack less effective than in the past, but many IoT devices, internal tools, and legacy systems still use HTTP.

## Prerequisites

### System Requirements
- Linux-based operating system (Ubuntu, Kali Linux, etc.)
- Python 3.x
- Root/sudo privileges

### Python Dependencies
```bash
pip install scapy
```

## Setup

### Enable IP Forwarding
Before using the ARP spoofer, you need to enable IP forwarding to allow traffic to flow through your machine:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

To make this permanent across reboots, edit `/etc/sysctl.conf`:
```bash
sudo nano /etc/sysctl.conf
```

Add or uncomment the following line:
```
net.ipv4.ip_forward=1
```

Then apply the changes:
```bash
sudo sysctl -p
```

### Disable IP Forwarding (After Testing)
```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## Usage

## Complete MITM Attack Workflow

### 1. Enable IP Forwarding
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### 2. Start ARP Spoofing
In one terminal:
```bash
sudo python3 spoofer.py
Target IP: 192.168.1.100      # Victim's IP
Gateway IP: 192.168.1.1        # Router's IP
```

### 3. Start Packet Sniffing
In another terminal:
```bash
sudo python3 sniffer.py
```

### 4. Monitor Intercepted Traffic
The sniffer will display:
- HTTP requests and URLs visited
- Form submissions (usernames, passwords, search queries)
- Cookies and authentication tokens
- Any unencrypted data

### 5. Stop the Attack
- Press `Ctrl+C` in both terminals
- The spoofer will automatically restore ARP tables
- Disable IP forwarding:
```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## How the MITM Attack Works

### Step-by-Step Attack Flow

1. **Enable IP Forwarding**: Your machine becomes a router, allowing traffic to pass through
2. **ARP Spoofing**: 
   - Tell the target: "I'm the gateway, send your traffic to me"
   - Tell the gateway: "I'm the target, send their traffic to me"
3. **Traffic Interception**: All traffic between target and internet flows through your machine
4. **Packet Analysis**: HTTP traffic is captured and analyzed in real-time
5. **Transparent Forwarding**: Traffic is forwarded to its intended destination, keeping the connection alive

### Visual Representation

```
Normal Traffic Flow:
Target Device ←→ Router ←→ Internet

MITM Attack Flow:
Target Device ←→ YOUR MACHINE ←→ Router ←→ Internet
                 (Intercepting & Analyzing)
```

### ARP Spoofing Technical Details
- The spoofer sends forged ARP replies to both the target and gateway
- ARP tables are poisoned to redirect traffic through your machine
- Both parties' ARP tables are restored when the script exits gracefully

### Packet Sniffing Technical Details
- Uses Scapy to capture packets on the network interface
- Filters for HTTP traffic (port 80)
- Extracts URLs, host headers, and POST data
- Displays potential credentials and sensitive information

## Common Use Cases

- **Security Audits**: Testing if employees are using HTTP on sensitive sites
- **Penetration Testing**: Authorized assessment of network security (with written permission)
- **Educational Demonstrations**: Teaching network security concepts
- **Network Analysis**: Understanding how HTTP traffic flows
- **Vulnerability Assessment**: Identifying devices using insecure protocols

## Real-World Scenarios

### Scenario 1: Coffee Shop Attack
An attacker positions themselves between victims and the coffee shop's WiFi router, capturing login credentials from users accessing HTTP sites.

### Scenario 2: Corporate Network Testing
A security professional tests if employees are transmitting sensitive data over HTTP instead of HTTPS.

### Scenario 3: IoT Device Security
Testing smart home devices that communicate using unencrypted HTTP APIs.

## Troubleshooting

### Permission Denied
- Ensure you're running the scripts with `sudo`
- Check that your user has the necessary privileges

### No Packets Captured
- Verify your network interface is active
- Check if you're on the correct network
- Ensure no firewall is blocking the traffic

### ARP Spoofing Not Working
- Confirm IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward` (should return 1)
- Verify target and gateway IPs are correct
- Check that both hosts are on the same subnet

## Stopping the Tools

Press `Ctrl+C` to gracefully stop either tool. The ARP spoofer will automatically restore the ARP tables of affected machines.

## Security Considerations

### For Attackers (Authorized Testers)
1. **Authorization**: Always obtain written permission before testing
2. **Scope**: Only target systems within the authorized scope
3. **Data Handling**: Securely handle any captured credentials
4. **Reporting**: Document findings professionally
5. **Cleanup**: Restore network state after testing

### For Defenders
Protect against MITM attacks by:
- **Use HTTPS Everywhere**: Encrypt all web traffic
- **HSTS (HTTP Strict Transport Security)**: Force HTTPS connections
- **Certificate Pinning**: Detect fraudulent certificates
- **ARP Spoofing Detection**: Use tools like arpwatch or XArp
- **Network Segmentation**: Isolate sensitive systems
- **Static ARP Entries**: Prevent ARP cache poisoning on critical hosts

### Detection Indicators
Network defenders can detect this attack through:
- Duplicate MAC addresses in ARP tables
- Increased ARP traffic on the network
- Gateway MAC address changes
- Network latency increases
- IDS/IPS alerts for ARP spoofing

### Legal Consequences
- **Unauthorized Use**: Criminal charges under computer fraud laws (CFAA in US, Computer Misuse Act in UK)
- **Civil Liability**: Lawsuits for damages and privacy violations
- **Professional Consequences**: Loss of certifications and employment

## Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [ARP Protocol (RFC 826)](https://www.ietf.org/rfc/rfc826.txt)
- [Network Security Fundamentals](https://www.sans.org/)

## Contributing

This project is for educational purposes. If you find bugs or have improvements, please ensure all contributions maintain the ethical use guidelines.

## License

Use responsibly and ethically. The authors assume no liability for misuse of these tools.

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
