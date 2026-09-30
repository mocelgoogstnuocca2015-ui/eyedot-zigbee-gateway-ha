"""网关同步协议客户端；由 HA 放入执行线程，所有会话操作按锁串行执行。"""

import ipaddress
import logging
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass

from .protocol.eyedot_switch_schema import build_switch_payload
from .protocol.ubia_native_codec import discovery_request
from .protocol.ubia_read_session import IO_HEADER, NativeReadSession, unpack

LOGGER = logging.getLogger(__name__)
STATE_EVENTS = frozenset((0x2003, 0x2316))


class NativeSession(NativeReadSession):
    def __init__(self, *args, stop_event=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_event = stop_event
        self._state_event_pending = False
        self._recent_events = deque(maxlen=64)
        self.state_event_count = 0
        self.last_state_event_at = None
        self._push_updates = {}
        self._push_requires_refresh = False

    def _poll(self, deadline, *, discovering=False):
        if self.stop_event and self.stop_event.is_set():
            raise InterruptedError("网关通信已停止")
        received = super()._poll(deadline, discovering=discovering)
        if not received:
            return None
        packet, _ = received
        if packet.command == 0x0408 and packet.channel == self.channel and len(packet.payload) >= 12:
            kind, _, size, command, sequence, _ = IO_HEADER.unpack_from(packet.payload)
            if kind == 3 and len(packet.payload) == size + 12 and command in STATE_EVENTS:
                # 事件也可能在目录查询或控制等待中到达，统一记录，避免被这些路径消费后遗漏。
                marker = (command, sequence)
                if marker not in self._recent_events:
                    self._recent_events.append(marker)
                    self._state_event_pending = True
                    self.state_event_count += 1
                    self.last_state_event_at = time.monotonic()
                    body = packet.payload[12:]
                    if command == 0x2003 and len(body) == 24:
                        # 原 App 的 push_DeviceStateChange 明确读取索引 12、类型 13、状态 14。
                        # 只直接更新已验证的类型 13，其余消息仍通过目录读取核实。
                        if body[13] == 13:
                            self._push_updates[body[12]] = (body[13], body[14])
                        else:
                            self._push_requires_refresh = True
                    else:
                        self._push_requires_refresh = True
        return received

    def consume_state_event(self):
        pending = self._state_event_pending
        self._state_event_pending = False
        return pending

    def take_push_updates(self):
        updates = self._push_updates
        refresh = self._push_requires_refresh
        self._push_updates = {}
        self._push_requires_refresh = False
        return updates, refresh

    def exchange(self, command, body, response, seconds=5):
        self.sequence = self.sequence % 65535 + 1
        sequence = self.sequence
        request = IO_HEADER.pack(3, 0, len(body), command, sequence, 0) + body
        deadline = time.monotonic() + seconds
        next_send = 0
        acknowledged = False
        while time.monotonic() < deadline:
            if not acknowledged and time.monotonic() >= next_send:
                self._send_av(request)
                next_send = time.monotonic() + 0.3
            received = self._poll(deadline)
            if not received:
                continue
            packet, _ = received
            if packet.command != 0x0408 or packet.channel != self.channel or len(packet.payload) < 12:
                continue
            kind, _, size, cmd, seq, _ = IO_HEADER.unpack_from(packet.payload)
            if len(packet.payload) != 12 + size:
                continue
            if kind == 4 and cmd == command and seq == sequence:
                acknowledged = True
            elif kind == 3:
                self._send_av(IO_HEADER.pack(4, 0, 0, cmd, seq, 0))
                if cmd == response:
                    return packet.payload[12:]
        raise TimeoutError(f"网关命令 0x{command:04X} 未收到业务回复")

    def authenticate(self, username, password):
        self.discover()
        self.handshake()
        self.login(username, password)
        fields = [value.encode() for value in (username, password)]
        body = b"".join(value.ljust(32, b"\0") for value in fields)
        reply = self.exchange(0x213C, body, 0x213D)
        if len(reply) < 4 or struct.unpack_from("<i", reply)[0] < 0:
            raise PermissionError("网关业务登录失败")

    def set_channel(self, index, channel, on):
        reply = self.exchange(0x2146, build_switch_payload(13, index, channel, on), 0x2147)
        if len(reply) != 4 or struct.unpack("<i", reply)[0] != 0:
            raise RuntimeError("网关拒绝三路控制命令")

    def pump(self):
        received = self._poll(time.monotonic() + 0.15)
        if received:
            packet, _ = received
            if packet.command == 0x0408 and packet.channel == self.channel and len(packet.payload) >= 12:
                kind, _, size, cmd, seq, _ = IO_HEADER.unpack_from(packet.payload)
                if kind == 3 and len(packet.payload) == size + 12:
                    # 即时确认推送；重复包仍回 ACK，但不重复触发同一事件。
                    self._send_av(IO_HEADER.pack(4, 0, 0, cmd, seq, 0))
        return self.consume_state_event()


def discover_uid(host, bind_ip="0.0.0.0", timeout=6):
    address = ipaddress.IPv4Address(host)
    if not address.is_private or address.is_multicast or address.is_unspecified:
        raise ValueError("网关 IP 必须是明确的局域网 IPv4 地址")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.bind((bind_ip, 0))
        connection.settimeout(0.2)
        deadline = time.monotonic() + timeout
        next_send = 0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                connection.sendto(discovery_request(0), (str(address), 32761))
                next_send = time.monotonic() + 1
            try:
                raw, peer = connection.recvfrom(4096)
            except socket.timeout:
                continue
            if peer[0] != str(address):
                continue
            try:
                packet = unpack(raw)
            except ValueError:
                continue
            if packet.command in (0x0602, 0x0604) and len(packet.payload) >= 20:
                uid = packet.payload[:20].decode("ascii")
                if len(uid) == 20 and "\0" not in uid:
                    return uid
    raise TimeoutError("未发现兼容网关，请核对 IP、网线及局域网连通性")


class SetupSession(NativeSession):
    def receive_io(self, deadline):
        received = self._poll(deadline)
        if not received:
            return None
        packet, _ = received
        if packet.command != 0x0408 or packet.channel != self.channel or len(packet.payload) < 12:
            return None
        kind, _, size, command, sequence, _ = IO_HEADER.unpack_from(packet.payload)
        if kind not in (3, 4) or len(packet.payload) != 12 + size:
            return None
        if kind == 3:
            self._send_av(IO_HEADER.pack(4, 0, 0, command, sequence, 0))
        return kind, command, sequence, packet.payload[12:]

    def batch(self, command, subcommand, data=b"", *, current=0, saved=1):
        self.sequence = self.sequence % 65535 + 1
        sequence = self.sequence
        body = struct.pack("<4I", subcommand, len(data), current, saved) + data
        wire = IO_HEADER.pack(3, 0, len(body), command, sequence, 0) + body
        deadline = time.monotonic() + 8
        next_send = 0
        acknowledged = False
        seen = set()
        records = bytearray()
        while time.monotonic() < deadline:
            if not acknowledged and time.monotonic() >= next_send:
                self._send_av(wire)
                next_send = time.monotonic() + 0.3
            value = self.receive_io(deadline)
            if not value:
                continue
            kind, cmd, seq, payload = value
            if kind == 4 and cmd == command and seq == sequence:
                acknowledged = True
                continue
            if kind != 3 or cmd != command + 1 or len(payload) < 32:
                continue
            _, sub, size, _, _, _, end, result = struct.unpack_from("<7Ii", payload)
            if sub != subcommand:
                continue
            if len(payload) != size + 32 or end not in (0, 1, 2):
                raise ValueError("网关回复长度或结束标志异常")
            if result < 0:
                raise RuntimeError(f"网关业务失败：{result}")
            if (cmd, seq) in seen:
                continue
            seen.add((cmd, seq))
            if end == 1:
                return bytes(records)
            records.extend(payload[32:])
        raise TimeoutError("没有收到完整的设备查询或登记结束通知")

    def read_devices(self):
        raw = self.batch(0x2102, 3, saved=0)
        if len(raw) % 40:
            raise ValueError("设备目录不是已验证的 40 字节记录格式")
        # 旧目录子命令 3 的偏移 33 是房间索引，设备类型在 34；
        # 子命令 6 的状态目录才把设备类型放在 33，不能复用其布局。
        return [{"index": raw[i + 32], "type": raw[i + 34],
                 "name": raw[i:i + 32].split(b"\0", 1)[0].decode("utf-8", errors="replace")}
                for i in range(0, len(raw), 40)]

    def enroll(self, name, room_name, seconds=120, cancel_event=None):
        event = None
        try:
            reply = self.exchange(0x210A, bytes(16), 0x210B, seconds=3)
            if len(reply) < 32 or struct.unpack_from("<i", reply, 28)[0] < 0:
                raise RuntimeError("网关未接受配对开启命令")
            print("入网窗口已开启，等待三路开关进入搜索模式。", flush=True)
            print("侧键精确时长尚未确认，LED 停止闪烁不能代替登记结果。", flush=True)
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if cancel_event and cancel_event.is_set():
                    raise InterruptedError("配对已取消")
                value = self.receive_io(deadline)
                if value and value[0] == 3 and value[1] == 0x2170 and len(value[3]) == 40:
                    event = value[3]
                    break
        finally:
            self.exchange(0x210A, struct.pack("<4I", 2, 0, 0, 0), 0x210B, seconds=3)
            print("已发送关闭入网请求。", flush=True)
        if not event:
            raise TimeoutError("没有收到对码事件，未登记设备")
        if event[2] != 13:
            raise ValueError("收到的设备不是三路开关，本版本不登记其他类型")
        if event[0] == 2:
            print(f"开关已登记，索引 {event[1]}；无需重复添加。", flush=True)
            return self.read_devices()
        if event[0] != 0:
            raise RuntimeError("对码事件不是已验证的新设备成功事件")

        if cancel_event and cancel_event.is_set():
            raise InterruptedError("配对已取消，未写入登记")
        rooms = self.batch(0x2150, 3)
        if len(rooms) % 36:
            raise ValueError("房间目录格式异常")
        desired = text_field(room_name)
        room = next((rooms[i:i + 36] for i in range(0, len(rooms), 36) if rooms[i:i + 32] == desired), None)
        if room is None:
            self.batch(0x2150, 0, desired + bytes(4))
            rooms = self.batch(0x2150, 3)
            room = next((rooms[i:i + 36] for i in range(0, len(rooms), 36) if rooms[i:i + 32] == desired), None)
        if room is None:
            raise RuntimeError("没有读回对应房间，未继续登记")
        # 只保存刚收到的对码候选，不删除、清空或修改已有子设备。
        body = text_field(name) + struct.pack("<2I", room[32], 0) + desired
        self.batch(0x2102, 0, body)
        devices = self.read_devices()
        if not any(row["index"] == event[1] and row["type"] == 13 for row in devices):
            raise RuntimeError("没有读回刚登记的三路开关")
        return devices


def text_field(value):
    raw = value.encode("utf-8")
    if not raw or len(raw) > 31 or b"\0" in raw:
        raise ValueError("设备名和房间名须为 1 至 31 个 UTF-8 字节")
    return raw.ljust(32, b"\0")


@dataclass(frozen=True)
class DeviceState:
    index: int
    name: str
    device_type: int
    state: int | None


class GatewayClient:
    def __init__(self, host, username, password, uid=""):
        self.host = host
        self.username = username
        self.password = password
        self.uid = uid
        self._session = None
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self.cancel_pairing = threading.Event()
        self._event_stop = threading.Event()
        self._event_thread = None
        self._event_notify = None
        self.event_notifications = 0
        self.last_event_received_at = None

    def _connect(self):
        if self._closed.is_set():
            raise RuntimeError("网关客户端已关闭")
        if self._session:
            return self._session
        if not self.uid:
            self.uid = discover_uid(self.host)
        connection = SetupSession(self.host, self.uid, timeout=5, stop_event=self._closed)
        try:
            connection.authenticate(self.username, self.password)
        except Exception:
            connection.close()
            raise
        self._session = connection
        return connection

    def _discard(self):
        if self._session:
            self._session.close()
            self._session = None

    def _fetch(self):
        connection = self._connect()
        directory = connection.read_devices()
        # 空目录时旧固件的状态读取会返回 -1，不能据此把未配对网关判为登录失败。
        supported = any(row["type"] == 13 for row in directory)
        states = connection.query("all_devices")["记录"] if supported else []
        by_index = {row["设备索引"]: row["状态整数"] for row in states}
        return {row["index"]: DeviceState(row["index"], row["name"], row["type"], by_index.get(row["index"]))
                for row in directory}

    def fetch(self):
        with self._lock:
            try:
                return self._fetch()
            except Exception:
                self._discard()
                raise

    def control(self, index, channel, on):
        if not 0 <= channel < 3 or not isinstance(on, bool):
            raise ValueError("只允许三路开关的明确开、关操作")
        with self._lock:
            try:
                before = self._fetch()
                if index not in before or before[index].device_type != 13:
                    raise ValueError("设备不存在或不是已验证的三路开关")
                self._connect().set_channel(index, channel, on)
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    data = self._fetch()
                    actual = data.get(index)
                    if actual and actual.state is not None and bool(actual.state & (1 << channel)) == on:
                        return data
                    time.sleep(0.25)
                raise TimeoutError("网关接受控制命令，但没有读回目标状态")
            except Exception:
                self._discard()
                raise

    def pair(self, name="三路开关", room_name="智能家居", seconds=120):
        if not 10 <= seconds <= 180:
            raise ValueError("配对等待时间须为 10 至 180 秒")
        with self._lock:
            if self.cancel_pairing.is_set():
                raise InterruptedError("配对已取消")
            try:
                self._connect().enroll(name, room_name, seconds, self.cancel_pairing)
                return self._fetch()
            except Exception:
                self._discard()
                raise

    def start_events(self, notify):
        with self._lock:
            if self._closed.is_set():
                raise RuntimeError("客户端已关闭，不能启动收包")
            if self._event_thread and self._event_thread.is_alive():
                return
            self._event_notify = notify
            self._event_thread = threading.Thread(target=self._listen_events, name="Eyedot 网关事件", daemon=True)
            self._event_thread.start()

    def _listen_events(self):
        while not self._event_stop.is_set():
            # 查询、控制和配对期间让出同一把锁，只有当前操作能读取此 UDP 会话。
            # 空闲时持续收包和保活，不在另一个线程抢走请求对应的回复。
            if not self._lock.acquire(blocking=False):
                self._event_stop.wait(0.02)
                continue
            changed = False
            received_at = None
            updates = {}
            needs_refresh = True
            try:
                if self._session and not self._closed.is_set():
                    changed = self._session.pump()
                    received_at = self._session.last_state_event_at
                    if changed:
                        updates, needs_refresh = self._session.take_push_updates()
            except (OSError, ValueError, RuntimeError) as error:
                if not self._event_stop.is_set():
                    LOGGER.debug("推送接收中断，将通过刷新重连：%s", error)
                    self._discard()
                    changed = True
            finally:
                self._lock.release()
            if changed and not self._event_stop.is_set():
                self.event_notifications += 1
                self.last_event_received_at = received_at
                self._event_notify(updates, needs_refresh, received_at)
            self._event_stop.wait(0.01)

    @property
    def event_listener_running(self):
        return self._event_thread is not None and self._event_thread.is_alive()

    def close(self):
        self._closed.set()
        self.cancel_pairing.set()
        self._event_stop.set()
        if self._event_thread and self._event_thread is not threading.current_thread():
            self._event_thread.join(timeout=1)
        with self._lock:
            self._discard()


def validate_gateway(data):
    client = GatewayClient(data["host"], data["username"], data["password"], data.get("uid", ""))
    try:
        devices = client.fetch()
        return {**data, "uid": client.uid}, devices
    finally:
        client.close()
