# Lab Topology
Hypervisor: Oracle VirtualBox

## Network: Host-Only Ethernet Adapter
Subnet: 192.168.100.0/24
Gateway: none (isolated)
DHCP: disabled (static IPs only)

## Virtual Machines

| Role        | VM Name    | OS               | IP              | Hypervisor Adapter |
|-------------|------------|------------------|-----------------|--------------------|
| C2 Server   | c2-server  | Ubuntu 22.04 LTS | 192.168.100.10  | Host-Only          |
| Victim/Agent| c2-victim  | Windows 10       | 192.168.100.20  | Host-Only          |

## DNS
c2.lab.internal -> 192.168.100.10 (Windows hosts file entry)

## Internet Access
Both VMs have a separate NAT adapter for package installation only.
Lab C2 traffic uses the host-only adapter exclusively.

## Port Allocation (populated as phases progress)
| Port | Service           | VM         |
|------|-------------------|------------|
| 443  | Nginx redirector  | c2-server  |
| 8443 | FastAPI C2 server | c2-server  |