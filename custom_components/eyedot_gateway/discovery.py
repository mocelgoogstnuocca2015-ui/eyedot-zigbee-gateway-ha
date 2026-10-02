"""按完整 UID 发现网关的新地址，支持 HA 的多网卡和实际子网掩码。"""

import ipaddress
import logging
import socket
import time

from .protocol.ubia_native_codec import discovery_request
from .protocol.ubia_read_session import unpack

LOGGER = logging.getLogger(__name__)
DEFAULT_TARGETS = (("0.0.0.0", "255.255.255.255"),)
DISCOVERY_PORT = 32761


async def async_discovery_targets(hass):
    from homeassistant.components import network

    targets = []
    for adapter in await network.async_get_adapters(hass):
        if not adapter.get("enabled", False):
            continue
        for item in adapter.get("ipv4", []):
            try:
                interface = ipaddress.IPv4Interface(f"{item['address']}/{item['network_prefix']}")
            except (KeyError, ValueError):
                continue
            if (not interface.ip.is_private or interface.ip.is_loopback
                    or interface.ip.is_unspecified or interface.network.prefixlen > 30):
                continue
            # 不能假定 /24；根据实际子网掩码计算该网卡的定向广播地址。
            target = (str(interface.ip), str(interface.network.broadcast_address))
            if target not in targets:
                targets.append(target)
    return tuple(targets) + DEFAULT_TARGETS


def discover_host(uid, targets=None, timeout=4, stop_event=None):
    expected = uid.encode("ascii")
    if len(expected) != 20 or b"\0" in expected:
        raise ValueError("重新发现需要已经保存的完整 20 字节网关 UID")
    targets = targets or DEFAULT_TARGETS
    connections = {}
    destinations = {}
    try:
        for bind_ip, destination in targets:
            if bind_ip not in connections:
                connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    connection.bind((bind_ip, 0))
                    connection.setblocking(False)
                except OSError:
                    connection.close()
                    LOGGER.debug("发现网关时跳过当前不可用的本机网卡")
                    continue
                connections[bind_ip] = connection
                destinations[bind_ip] = []
            if destination not in destinations[bind_ip]:
                destinations[bind_ip].append(destination)
        if not connections:
            raise OSError("没有可用于网关发现的本机网卡")
        deadline = time.monotonic() + timeout
        next_send = 0
        request = discovery_request(0)
        while time.monotonic() < deadline:
            if stop_event and stop_event.is_set():
                raise InterruptedError("网关客户端已停止，取消地址发现")
            if time.monotonic() >= next_send:
                for bind_ip, connection in connections.items():
                    for destination in destinations[bind_ip]:
                        try:
                            connection.sendto(request, (destination, DISCOVERY_PORT))
                        except OSError:
                            LOGGER.debug("当前网卡暂时不能发送网关发现请求")
                next_send = time.monotonic() + 1
            for connection in connections.values():
                try:
                    raw, peer = connection.recvfrom(4096)
                except (BlockingIOError, socket.timeout):
                    continue
                except OSError:
                    continue
                try:
                    address = ipaddress.IPv4Address(peer[0])
                    packet = unpack(raw)
                except (ValueError, IndexError):
                    continue
                # 同网段可能有其他网关或旧地址被其他设备复用；只接受完整 UID 一致的回复。
                if (address.is_private and not address.is_multicast and not address.is_unspecified
                        and packet.command in (0x0602, 0x0604) and packet.payload[:20] == expected):
                    return str(address)
            wait = min(0.05, max(0, deadline - time.monotonic()))
            if stop_event:
                stop_event.wait(wait)
            else:
                time.sleep(wait)
        raise TimeoutError("局域网内未发现保存 UID 对应的网关")
    finally:
        for connection in connections.values():
            connection.close()
