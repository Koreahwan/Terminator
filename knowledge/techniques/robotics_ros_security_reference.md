# Robotics/ROS Security Reference

## ROS1 vs ROS2 Security

| Feature | ROS1 | ROS2 |
|---------|------|------|
| Transport | TCPROS/UDPROS (no encryption) | DDS (optional SROS2 encryption) |
| Authentication | None | SROS2 (PKI-based, often disabled) |
| Discovery | ROS Master (single point of failure) | DDS Discovery (decentralized) |
| Access Control | None | SROS2 permissions (XML-based) |

## Top Vulnerability Classes

| # | Class | CWE | Typical Severity | Automation |
|---|-------|-----|-----------------|------------|
| 1 | ROS Auth Bypass | CWE-287 | Critical | High — rostopic/rosservice CLI |
| 2 | Node Spoofing | CWE-290 | Critical | High — rogue node registration |
| 3 | Command Injection via Topic | CWE-78 | Critical | Medium — message crafting |
| 4 | Unsafe Deserialization | CWE-502 | High | Medium — custom message types |
| 5 | Parameter Tampering | CWE-472 | High | High — rosparam set |
| 6 | Hardcoded Credentials | CWE-798 | High | High — strings/grep |
| 7 | Unencrypted Communication | CWE-319 | Medium | High — tcpdump |
| 8 | Safety System Bypass | CWE-693 | Critical | Low — hardware-dependent |

## Key Tools

- `rostopic list/echo/pub` — Topic enumeration and injection
- `rosservice list/call` — Service discovery and unauthorized calls
- `rosparam get/set` — Parameter reading and tampering
- `roswtf` — ROS configuration diagnostics
- `wireshark` + ROS dissector — Traffic analysis
- `Gazebo` — Simulation environment for safe PoC testing

## CVE Submission for Robotics

1. Check manufacturer's security contact (usually security@manufacturer.com)
2. If public GitHub repo: use GHSA (GitHub Security Advisory)
3. If no GitHub: use MITRE CVE form (https://cveform.mitre.org/)
4. CNA identification: GitHub for open-source, MITRE for commercial
5. Responsible disclosure: 90 days standard, coordinate with manufacturer

## Notable Robot Vendors & Known Issues

- **Unitree**: ROS2-based, often no SROS2 enabled
- **Universal Robots**: UR+ ecosystem, Modbus interface
- **MiR**: Fleet management, REST API + ROS bridge
- **ABB**: OPC-UA + ROS bridge, industrial protocols

## Docker Setup for ROS2 Testing

```bash
# ROS2 Humble (recommended)
docker run --rm -it --network host ros:humble bash
source /opt/ros/humble/setup.bash
ros2 topic list
ros2 service list
ros2 node list

# Gazebo simulation
docker run --rm -it --network host -e DISPLAY=$DISPLAY osrf/ros:humble-desktop gazebo
```
