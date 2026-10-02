"""核对完整身份匹配、广播网卡选择以及断网期间的发现边界。"""

import threading
import unittest
from collections import deque
from unittest.mock import patch

from custom_components.eyedot_gateway.discovery import async_discovery_targets, discover_host
from custom_components.eyedot_gateway.protocol.ubia_read_session import pack

UID = "TESTTESTTESTTESTABCD"
OTHER_UID = "WRNGWRNGWRNGWRNGABCD"


class Datagram:
    def __init__(self, replies=(), fail_bind=False):
        self.replies = deque(replies)
        self.fail_bind = fail_bind
        self.sent = []
        self.closed = False

    def setsockopt(self, *args):
        pass

    def bind(self, address):
        if self.fail_bind:
            raise OSError("测试网卡已离线")

    def setblocking(self, value):
        pass

    def sendto(self, raw, peer):
        self.sent.append(peer)

    def recvfrom(self, size):
        if not self.replies:
            raise BlockingIOError
        return self.replies.popleft()

    def close(self):
        self.closed = True


class DiscoveryTests(unittest.TestCase):
    def test_only_full_uid_matches_and_unrelated_replies_are_ignored(self):
        connection = Datagram([
            ("无效报文".encode(), ("192.168.50.3", 30000)),
            (pack(0x0602, OTHER_UID.encode(), flags=0x12), ("192.168.50.4", 30001)),
            (pack(0x0602, UID.encode(), flags=0x12), ("8.8.8.8", 30002)),
            (pack(0x0604, UID.encode(), flags=0x12), ("192.168.50.9", 42657)),
        ])
        with patch("custom_components.eyedot_gateway.discovery.socket.socket", return_value=connection):
            self.assertEqual(discover_host(UID), "192.168.50.9")
        self.assertTrue(connection.closed)
        self.assertEqual(connection.sent, [("255.255.255.255", 32761)])

    def test_unavailable_interface_does_not_prevent_other_interfaces(self):
        failed = Datagram(fail_bind=True)
        working = Datagram([(pack(0x0602, UID.encode(), flags=0x12), ("192.168.50.9", 42657))])
        with patch("custom_components.eyedot_gateway.discovery.socket.socket", side_effect=[failed, working]):
            found = discover_host(UID, (("192.168.60.2", "192.168.60.255"), ("0.0.0.0", "255.255.255.255")))
        self.assertEqual(found, "192.168.50.9")
        self.assertTrue(failed.closed)
        self.assertTrue(working.closed)

    def test_timeout_closes_socket_and_does_not_choose_another_uid(self):
        connection = Datagram([(pack(0x0602, OTHER_UID.encode(), flags=0x12), ("192.168.50.9", 42657))])
        with patch("custom_components.eyedot_gateway.discovery.socket.socket", return_value=connection):
            with self.assertRaises(TimeoutError):
                discover_host(UID, timeout=0.02)
        self.assertTrue(connection.closed)

    def test_shutdown_cancels_without_sending_broadcast(self):
        stop = threading.Event()
        stop.set()
        connection = Datagram()
        with patch("custom_components.eyedot_gateway.discovery.socket.socket", return_value=connection):
            with self.assertRaises(InterruptedError):
                discover_host(UID, stop_event=stop)
        self.assertTrue(connection.closed)
        self.assertEqual(connection.sent, [])


class InterfaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_enabled_lan_interface_uses_actual_prefix(self):
        adapters = [
            {"enabled": True, "ipv4": [{"address": "192.168.16.88", "network_prefix": 20}]},
            {"enabled": False, "ipv4": [{"address": "192.168.80.2", "network_prefix": 24}]},
            {"enabled": True, "ipv4": [{"address": "127.0.0.1", "network_prefix": 8}]},
            {"enabled": True, "ipv4": [{"address": "172.88.0.1", "network_prefix": 30}]},
        ]
        with patch("homeassistant.components.network.async_get_adapters", return_value=adapters):
            targets = await async_discovery_targets(object())
        self.assertEqual(targets, (("192.168.16.88", "192.168.31.255"), ("0.0.0.0", "255.255.255.255")))
