# Threat Model

The threat model defines the operational boundaries of the simulated adversary. It restricts the implementation to specific capabilities and explicitly excludes others. If a feature is not described in this document, it is strictly out of scope.

## What the Adversary Can Do

The simulated Red Team controls an implant executing as an unprivileged user-mode process on the victim host. Initial access is assumed. The adversary possesses the following capabilities:

* **Outbound Communication:** Can initiate outbound HTTPS connections to a predefined server (Implementation: `transport/http_transport.py`).
* **Payload Encryption:** Encrypts all application-layer payloads using AES-256-GCM (Implementation: `common/crypto.py`).
* **Timing Evasion (Jitter):** Randomises beacon timing using configurable uniform or gaussian jitter (Implementation: `evasion/sleep_strat.py` and `agent/jitter.py`).
* **Payload Evasion (Padding):** Pads traffic payloads to variable lengths to disrupt size-based signatures (Implementation: `evasion/padding_strat.py`).
* **Fingerprint Evasion:** Rotates HTTP headers (User-Agent, Accept-Language) and randomises header order to reduce fingerprint stability (Implementation: `evasion/header_randomizer.py`).
* **Infrastructure Obfuscation:** Routes traffic through an Nginx redirector to separate the agent from the controller (Implementation: `redirector/nginx_docker.conf`).

## What the Adversary Cannot Do

The following actions are explicitly prohibited. The reasoning is tied to the academic scope of this framework, which focuses on network-layer behavioral analysis rather than host-layer exploitation.

* **No Kernel-Level Stealth or Driver Installation:** Reason: The focus is strictly on user-mode network telemetry.
* **No EDR Bypass Techniques:** Reason: Host-based evasion introduces arbitrary complexity outside the scope of network intrusion detection (Blue Team Project 2).
* **No Lateral Movement or Scanning:** Reason: The lab environment simulates a contained point-to-point C2 channel. Network scanning (ARP, SMB) is blocked by the agent executor.
* **No Privilege Escalation:** Reason: The implant assumes standard user execution.
* **No Domain Fronting or DGA:** Reason: Infrastructure is static to maintain a controlled lab environment.
* **No Persistence Mechanisms:** Reason: The agent strictly prohibits registry writes, scheduled tasks, or startup folder modifications.

## Defender Visibility

The Blue Team operates under the following visibility assumptions for network and host telemetry:

**Network Visibility (Primary):**
* Full packet capture (PCAP) is available at the lab perimeter.
* The defender has access to flow metadata, TLS handshake parameters, packet timing (inter-arrival times), and DNS queries.
* There is no TLS interception; the defender sees handshake metadata only.
* The defender does not have access to decrypted payload content.
* The defender starts blind with no prior C2 domain knowledge or signature-based blacklists.

**Host Visibility (Secondary):**
* Sysmon event logs are available, specifically Event IDs 1 (Process Create), 3 (Network Connect), and 22 (DNS Query).
* There is no kernel-mode visibility into the implant's memory.

## Detection Surface

Because payload inspection and static signatures are unavailable, the detection surface relies exclusively on behavioural anomalies:

* **Inter-Arrival Time (IAT) Variance:** Without jitter (baseline profile), the deterministic beacon interval represents a critical detection surface. Even with uniform jitter applied, the mathematical mean of IAT over time may still reveal automated periodicity compared to human web browsing.
* **Flow Statistics (Size and Rate):** The total bytes and bytes-per-second of the encrypted channel form a distinct profile. While payload padding (evasion Level 2/3) obfuscates exact command sizes, the minimum required overhead of the C2 protocol establishes a baseline packet size.
* **Shannon Entropy:** Applying random byte padding to small payloads artificially inflates the Shannon entropy of the traffic. Encrypted traffic already has high entropy, but padded encrypted traffic may exhibit entropy variations detectable through statistical analysis.
* **TLS and HTTP Handshake Metadata:** Although HTTP headers are randomized, the TLS fingerprint (e.g., JA3) remains static because the underlying Python `requests` / `ssl` configuration does not rotate. Nginx access logs on the redirector will capture the rotating User-Agent and Accept-Language headers, which could be correlated to identify synthetic pools.