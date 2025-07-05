# SMTPGhost: Enhancing Zero Trust with Email Aware Application Layer Monitoring

In the realm of SOHO (Small Office/Home Office) network security, attackers constantly search for unconventional footholds. One often overlooked vector is email whether it's phishing attempts, 
file borne exploits, or embedded command and control beacons. To elevate the defense perimeter of Oblivion Edge, our Zero Trust enabled SOHO router OS, 
I introduce a new subsystem: SMTPGhost. 
[SMTPGhost on GitHub](https://github.com/DBA1337TECH/OblivionEdge/tree/OblivionEdge_Dev/oblivion-dev/smtp_server)


# What Is SMTPGhost?

SMTPGhost is a lightweight SMTP server and client toolkit that serves a dual purpose:

    SMTP/POP3 Honeypot & Email Trap: It accepts, logs, and optionally decrypts emails sent over your network, catching suspicious or malformed payloads in transit.

    Forwarding/Forensic Relay: It compresses and encrypts email content, forwarding the forensic payload data securely for deeper inspection or archival.

SMTPGhost is embedded into the oblivion_dev/smtp_server/ module and can be deployed as a daemon on the router or as a containerized microservice alongside other network analytics tools.
# Why SMTPGhost?

Most SOHO routers blindly pass SMTP traffic between clients and upstream email servers. With SMTPGhost, we make that flow visible, monitorable, and optionally actionable. This is especially useful in:

    IoT environments where rogue devices might exfiltrate data via mail.

    Red team engagements where simulated phishing and payload delivery need catch and inspect mechanisms.

    SOC/test labs where new malware signatures are harvested and analyzed.

SMTPGhost fits perfectly into a Zero Trust model by treating even internal email as untrusted until verified.

# Architecture Overview
## SMTP Server Core (C   smtp_server.c)

The C based SMTP daemon:

    Listens on a configurable port (default: 2525).

    Accepts and parses SMTP commands (EHLO, MAIL FROM, RCPT TO, DATA, QUIT).

    Captures raw email content.

    Logs metadata including:

        sender/recipient

        source IP

        optional DNS hostname of intended forwarder

    Supports gzip compression and optional OpenSSL AES 256 encryption of logs.

    Stores logs in JSON format (smtp_debug.log) or as encrypted binaries (smtp_debug.json.enc).

 # POP3 Listener (Optional)

If   pop3 is enabled, a parallel thread opens a fake POP3 listener (port 110):

    Accepts USER, PASS, STAT, LIST, RETR, QUIT commands.

    Behaves like a minimal honeypot for fake mailboxes.

    Offers a stealthy interface for passive interaction logging.

# SMTP Test Client (Python   smtp_client.py)

A Python based client allows for local or automated email injection:

python smtp_client.py 127.0.0.1 2525

The client issues:

    Standard SMTP commands.

    Multi line message payloads.

    Proper session closure with QUIT.

This is ideal for testing parser robustness, compression, and encryption output validation.
## Security Features
### Feature	Description
AES 256 Encryption	When   key <password> is provided, all JSON logs are encrypted using OpenSSL with PBKDF2 salt.
Payload Gzipping	Email content is piped through gzip for storage efficiency and obfuscation.
DNS Forward Masking	The   dns flag allows SMTPGhost to log a "forwarding" hostname, emulating real world routing behavior for forensic fidelity.
JSON Metadata	All sessions are logged in structured format, supporting integration with SIEMs, ELK stacks, or other alerting systems.
### Sample Forensic Log
```json
{
  "FROM": "<sender@example.com>",
  "TO": "<receiver@example.com>",
  "src_ip": "192.168.1.50",
  "dst_dns": "smtp.relay.example.com",
  "Contents": "debug_email_20250705_103115.gz"
}
```

Encrypted logs are stored using OpenSSL and can be decrypted using:

```bash
openssl enc  d  aes 256 cbc  pbkdf2  in smtp_debug.json.enc  out decrypted.json
```

# Deployment Scenarios

    1. Intrusion Detection Mode (Passive):

    Run SMTPGhost on a mirrored network interface to passively observe email traffic.

    2. Sandbox Relay (Active Forwarder):

    Deploy it as a fake relay that captures and halts outbound SMTP attempts, then simulates a successful transaction. Great for phishing payload analysis.

    3. App Layer Honeypot:

    Enable both SMTP and POP3 daemons to simulate a fully functional but controlled mail server.
# RoadMap

**SMTPGhost is currently a PoC but will evolve with the following:**

    MIME Parsing for attachments

    YARA Rule Scanning for malicious payloads

    Integration with Oblivion Edge Dashboard for visual analytics

    JSON to Alert Hooks for automated flagging in the Zero Trust enforcement kernel

# Conclusion

SMTPGhost demonstrates how application layer visibility and enforcement can complement the Zero Trust network posture. By logging, inspecting, and optionally blocking SMTP/POP3 activity at the edge, we unlock new layers of detection and response capability on a platform as nimble as a SOHO router.

Stay tuned as we weaponize SMTPGhost into a first class module of the Oblivion Edge ecosystem. Email isn’t dead, so let’s stop pretending it's safe.
