"""验证未经确认的控制、未知设备类型与会话关闭行为。"""

import unittest
import threading
import time
from collections import deque
from unittest.mock import patch

from custom_components.eyedot_gateway.client import GatewayClient, NativeSession, SetupSession
from custom_components.eyedot_gateway.protocol.ubia_read_session import IO_HEADER, NativePacket, NativeReadSession


class FakeNative:
    def __init__(self, device_type=13):
        self.device_type = device_type
        self.commands = []
        self.closed = False
        self.event_pending = False
        self.pump_calls = 0
        self.last_state_event_at = None

    def read_devices(self):
        return [{"index": 0, "type": self.device_type, "name": "测试开关"}]

    def query(self, name):
        return {"记录": [{"设备索引": 0, "状态整数": 128}]}

    def set_channel(self, index, channel, on):
        self.commands.append((index, channel, on))

    def close(self):
        self.closed = True

    def pump(self):
        self.pump_calls += 1
        time.sleep(0.01)
        changed = self.event_pending
        self.event_pending = False
        return changed

    def take_push_updates(self):
        return {}, True


class ClientTests(unittest.TestCase):
    def test_startup_with_stale_ip_recovers_same_uid(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        attempts = []

        def factory(host, *args, **kwargs):
            native = FakeNative()
            attempts.append((host, native))

            def authenticate(*args):
                if host == "192.168.50.2":
                    raise TimeoutError("旧地址已失效")

            native.authenticate = authenticate
            return native

        with patch("custom_components.eyedot_gateway.client.SetupSession", side_effect=factory), \
                patch("custom_components.eyedot_gateway.client.discover_host", return_value="192.168.50.9") as discovery:
            data = client.fetch()
        self.assertEqual(client.host, "192.168.50.9")
        self.assertEqual(client.uid, "01234567890123456789")
        self.assertEqual(data[0].state, 128)
        self.assertEqual(client.rediscovery_count, 1)
        self.assertTrue(attempts[0][1].closed)
        discovery.assert_called_once()
        client.close()

    def test_read_failure_recovers_even_if_gateway_ip_is_unchanged(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        broken = FakeNative()

        def unavailable():
            raise TimeoutError("旧 UDP 会话已失效")

        broken.read_devices = unavailable
        client._session = broken
        renewed = FakeNative()
        renewed.authenticate = lambda *args: None
        with patch("custom_components.eyedot_gateway.client.SetupSession", return_value=renewed), \
                patch("custom_components.eyedot_gateway.client.discover_host", return_value=client.host):
            self.assertEqual(client.fetch()[0].state, 128)
        self.assertTrue(broken.closed)
        self.assertEqual(client.host, "192.168.50.2")
        self.assertEqual(client.rediscovery_count, 1)
        client.close()

    def test_authentication_error_does_not_start_address_scan(self):
        client = GatewayClient("192.168.50.2", "test", "wrong", "01234567890123456789")
        native = FakeNative()

        def reject(*args):
            raise PermissionError("账号密码错误")

        native.authenticate = reject
        with patch("custom_components.eyedot_gateway.client.SetupSession", return_value=native), \
                patch("custom_components.eyedot_gateway.client.discover_host") as discovery:
            with self.assertRaises(PermissionError):
                client.fetch()
        discovery.assert_not_called()
        self.assertTrue(native.closed)
        self.assertEqual(client.host, "192.168.50.2")
        client.close()

    def test_failed_discovery_is_rate_limited_and_keeps_saved_address(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        native = FakeNative()

        def offline(*args):
            raise TimeoutError("网关离线")

        native.authenticate = offline
        with patch("custom_components.eyedot_gateway.client.SetupSession", return_value=native), \
                patch("custom_components.eyedot_gateway.client.discover_host", side_effect=TimeoutError) as discovery:
            for _ in range(2):
                with self.assertRaises(TimeoutError):
                    client.fetch()
        discovery.assert_called_once()
        self.assertEqual(client.host, "192.168.50.2")
        self.assertEqual(client.rediscovery_count, 0)
        client.close()

    def test_new_address_is_not_committed_when_its_authentication_fails(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        attempts = []

        def factory(host, *args, **kwargs):
            native = FakeNative()
            attempts.append(native)

            def authenticate(*args):
                if host == "192.168.50.2":
                    raise TimeoutError("旧地址失效")
                raise PermissionError("业务认证失败")

            native.authenticate = authenticate
            return native

        with patch("custom_components.eyedot_gateway.client.SetupSession", side_effect=factory), \
                patch("custom_components.eyedot_gateway.client.discover_host", return_value="192.168.50.9"):
            with self.assertRaises(PermissionError):
                client.fetch()
        self.assertEqual(client.host, "192.168.50.2")
        self.assertTrue(all(native.closed for native in attempts))
        client.close()

    def test_recovery_after_control_does_not_send_control_twice(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        original = FakeNative()
        reads = []

        def directory():
            reads.append(1)
            if len(reads) > 1:
                raise TimeoutError("控制后网关地址发生变化")
            return [{"index": 0, "type": 13, "name": "测试开关"}]

        original.read_devices = directory
        client._session = original
        renewed = FakeNative()
        renewed.authenticate = lambda *args: None
        renewed.query = lambda name: {"记录": [{"设备索引": 0, "状态整数": 129}]}
        with patch("custom_components.eyedot_gateway.client.SetupSession", return_value=renewed), \
                patch("custom_components.eyedot_gateway.client.discover_host", return_value="192.168.50.9"):
            self.assertEqual(client.control(0, 0, True)[0].state, 129)
        self.assertEqual(original.commands, [(0, 0, True)])
        self.assertEqual(renewed.commands, [])
        client.close()

    def test_old_directory_room_and_type_offsets_are_not_confused(self):
        session = SetupSession.__new__(SetupSession)
        raw = "测试开关".encode().ljust(32, b"\0") + bytes([7, 4, 13, 0, 255, 255, 255, 255])
        session.batch = lambda *args, **kwargs: raw
        self.assertEqual(session.read_devices(), [{"index": 7, "type": 13, "name": "测试开关"}])

    def test_success_code_without_target_state_raises_and_closes(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        native = FakeNative()
        client._session = native
        with patch("custom_components.eyedot_gateway.client.time.monotonic", side_effect=[0, 1, 5]), \
                patch("custom_components.eyedot_gateway.client.time.sleep"):
            with self.assertRaises(TimeoutError):
                client.control(0, 0, True)
        self.assertEqual(native.commands, [(0, 0, True)])
        self.assertTrue(native.closed)
        self.assertIsNone(client._session)

    def test_unknown_type_is_not_controlled(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        native = FakeNative(17)
        client._session = native
        with self.assertRaises(ValueError):
            client.control(0, 0, True)
        self.assertEqual(native.commands, [])

    def test_closed_client_does_not_reconnect(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        client.close()
        with self.assertRaises(RuntimeError):
            client.fetch()

    def test_empty_directory_does_not_query_unsupported_empty_state(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        native = FakeNative()
        native.read_devices = lambda: []
        native.query = lambda name: self.fail("空网关不应读取会返回 -1 的状态目录")
        client._session = native
        self.assertEqual(client.fetch(), {})

    def test_event_received_during_query_is_preserved_and_duplicate_is_acked(self):
        session = NativeSession.__new__(NativeSession)
        session.stop_event = None
        session.channel = 0
        session._state_event_pending = False
        session._recent_events = deque(maxlen=64)
        session.state_event_count = 0
        session._push_updates = {}
        session._push_requires_refresh = False
        ack = []
        session._send_av = ack.append
        packet = NativePacket(0x0408, 0x12, 1, 0, IO_HEADER.pack(3, 0, 4, 0x2316, 7, 0) + bytes(4))
        with patch.object(NativeReadSession, "_poll", return_value=(packet, ("192.168.50.2", 32761))):
            session._poll(time.monotonic() + 1)
        with patch.object(NativeReadSession, "_poll", return_value=None):
            self.assertTrue(session.pump())
            self.assertFalse(session.pump())
        with patch.object(NativeReadSession, "_poll", return_value=(packet, ("192.168.50.2", 32761))):
            self.assertFalse(session.pump())
        self.assertEqual(session.state_event_count, 1)
        self.assertEqual(ack, [IO_HEADER.pack(4, 0, 0, 0x2316, 7, 0)])

    def test_listener_yields_to_requests_and_stops_on_close(self):
        client = GatewayClient("192.168.50.2", "test", "test", "01234567890123456789")
        native = FakeNative()
        client._session = native
        observed = threading.Event()
        try:
            with client._lock:
                client.start_events(lambda *_: observed.set())
                native.event_pending = True
                time.sleep(0.06)
                self.assertEqual(native.pump_calls, 0)
            self.assertTrue(observed.wait(0.5))
            self.assertTrue(client.event_listener_running)
        finally:
            client.close()
        self.assertFalse(client.event_listener_running)
        self.assertTrue(native.closed)

    def test_complete_switch_push_contains_state_without_extra_query(self):
        session = NativeSession.__new__(NativeSession)
        session.stop_event = None
        session.channel = 0
        session._state_event_pending = False
        session._recent_events = deque(maxlen=64)
        session.state_event_count = 0
        session._push_updates = {}
        session._push_requires_refresh = False
        session._send_av = lambda _: None
        body = bytearray(24)
        body[12:15] = bytes([7, 13, 0x85])
        packet = NativePacket(0x0408, 0x12, 1, 0, IO_HEADER.pack(3, 0, 24, 0x2003, 9, 0) + body)
        with patch.object(NativeReadSession, "_poll", return_value=(packet, ("192.168.50.2", 32761))):
            self.assertTrue(session.pump())
        self.assertEqual(session.take_push_updates(), ({7: (13, 0x85)}, False))
        self.assertEqual(session.take_push_updates(), ({}, False))
