"""Real-time packet capture, flow monitoring, alerting, and attack simulation."""

from realtime.attack_simulator import (
    build_raw_ipv4_tcp_frame,
    generate_raw_portscan_frames,
    run_realtime_simulation,
)
from realtime.monitor import (
    AlertRecord,
    RealtimeNIDSMonitor,
    align_flow_schema,
    build_iptables_block_command,
)

__all__ = [
    "AlertRecord",
    "RealtimeNIDSMonitor",
    "align_flow_schema",
    "build_iptables_block_command",
    "build_raw_ipv4_tcp_frame",
    "generate_raw_portscan_frames",
    "run_realtime_simulation",
]

