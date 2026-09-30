"""验证未经确认的控制、未知设备类型与会话关闭行为。"""

import unittest
from unittest.mock import patch

from custom_components.eyedot_gateway.client import GatewayClient, SetupSession


class FakeNative:
    def __init__(self, device_type=13):
        self.device_type = device_type
        self.commands = []
        self.closed = False

    def read_devices(self):
        return [{"index": 0, "type": self.device_type, "name": "测试开关"}]

    def query(self, name):
        return {"记录": [{"设备索引": 0, "状态整数": 128}]}

    def set_channel(self, index, channel, on):
        self.commands.append((index, channel, on))

    def close(self):
        self.closed = True


class ClientTests(unittest.TestCase):
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
