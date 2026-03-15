# generate_sample_logs.py — creates realistic sample network logs for testing
from pathlib import Path
from datetime import datetime, timedelta
import random

Path("logs").mkdir(exist_ok=True)

def ts(offset_min=0):
    t = datetime.now() - timedelta(minutes=offset_min)
    return t.strftime("%b %d %H:%M:%S")

# ── Router log ─────────────────────────────────────────────────────────────────
router_log = f"""{ts(120)} router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
{ts(119)} router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
{ts(115)} router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
{ts(110)} router-cr-01 %BGP-5-ADJCHANGE: BGP peer 10.0.0.2 session dropped
{ts(108)} router-cr-01 %OSPF-5-ADJCHG: OSPF neighbor 192.168.1.1 went down
{ts(105)} router-cr-01 %CPU-4-HIGH: CPU utilization: 92% for 5 minutes
{ts(100)} router-cr-01 %CPU-4-HIGH: CPU utilization: 88% for 5 minutes
{ts(95)}  router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down
{ts(90)}  router-cr-01 %SEC-6-IPACCESSLOGP: Authentication failure for user admin from 192.168.1.50
{ts(85)}  router-cr-01 %SEC-6-IPACCESSLOGP: Authentication failure for user root from 10.10.1.5
{ts(80)}  router-cr-01 %SEC-6-IPACCESSLOGP: login failed user admin from 192.168.1.51
{ts(75)}  router-cr-01 %SEC-6-IPACCESSLOGP: invalid password user cisco from 10.0.0.99
{ts(70)}  router-cr-01 %SEC-6-IPACCESSLOGP: auth fail user test from 192.168.1.100
{ts(65)}  router-cr-01 %SYS-2-MALLOCFAIL: Memory allocation failed, memory usage: 91%
{ts(60)}  router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
{ts(55)}  router-cr-01 %BGP-5-ADJCHANGE: BGP peer session dropped neighbor 10.0.0.3 reset
{ts(50)}  router-cr-01 INFO: Interface Loopback0 is up
{ts(45)}  router-cr-01 ERROR: Routing table update failed
{ts(40)}  router-cr-01 CRITICAL: Core dump generated
{ts(35)}  router-cr-01 %CPU-4-HIGH: CPU utilization: 95% for 10 minutes
{ts(30)}  router-cr-01 INFO: NTP sync successful
{ts(25)}  router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/4, changed state to down
{ts(20)}  router-cr-01 ERROR: SNMP trap send failed
{ts(10)}  router-cr-01 INFO: System uptime 45 days
{ts(5)}   router-cr-01 WARNING: Disk space low on /var
"""

# ── Switch log ─────────────────────────────────────────────────────────────────
switch_log = f"""{ts(130)} switch-floor2 %LINK-3-UPDOWN: Interface FastEthernet0/24 changed state to down
{ts(125)} switch-floor2 %LINK-3-UPDOWN: Interface FastEthernet0/24 changed state to up
{ts(120)} switch-floor2 %LINK-3-UPDOWN: Interface FastEthernet0/23 link flap detected
{ts(115)} switch-floor2 %SEC-6-IPACCESSLOGP: Authentication failure for user admin from 10.1.1.5
{ts(110)} switch-floor2 %SEC-6-IPACCESSLOGP: login failed user manager from 10.1.1.6
{ts(105)} switch-floor2 %SEC-6-IPACCESSLOGP: auth fail user cisco from 10.1.1.7
{ts(100)} switch-floor2 %CPU-4-HIGH: CPU utilization: 87%
{ts(95)}  switch-floor2 INFO: STP topology change detected VLAN 10
{ts(90)}  switch-floor2 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, line protocol went down
{ts(85)}  switch-floor2 ERROR: MAC address table full
{ts(80)}  switch-floor2 %SYS-2-MALLOCFAIL: memory warning usage: 88%
{ts(75)}  switch-floor2 INFO: Port security enabled on Fa0/10
{ts(60)}  switch-floor2 CRITICAL: Stack member unreachable
{ts(45)}  switch-floor2 ERROR: VLAN database corruption detected
{ts(30)}  switch-floor2 INFO: Spanning tree recalculation complete
{ts(15)}  switch-floor2 %LINK-3-UPDOWN: Interface FastEthernet0/12 changed state to down
{ts(5)}   switch-floor2 INFO: Configuration saved
"""

Path("logs/router-cr-01.log").write_text(router_log)
Path("logs/switch-floor2.log").write_text(switch_log)

print("✅ Sample logs generated in logs/")
print("   - logs/router-cr-01.log")
print("   - logs/switch-floor2.log")
print("\nRun: py log_analyzer.py")
