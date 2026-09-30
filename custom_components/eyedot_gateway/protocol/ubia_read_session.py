"""按已还原的 UBIA UDP 直连分支实现最小只读会话；已验证一台原厂兼容网关的局域网分支。"""

import argparse
import getpass
import ipaddress
import secrets
import socket
import struct
import time
from dataclasses import dataclass

from .eyedot_read_session import QUERY_IDS, merge_switch_states, parse_read_batch
from .ubia_native_codec import discovery_request, transform


HEADER = struct.Struct("<8H")
IO_HEADER = struct.Struct("<BBHIHH")


@dataclass(frozen=True)
class NativePacket:
    command: int
    flags: int
    session_id: int
    channel: int
    payload: bytes


def unpack(data: bytes) -> NativePacket:
    if not 16 <= len(data) <= 1432:
        raise ValueError("UBIA 数据长度超出当前直连格式")
    plain = transform(data, True)
    magic, profile, size, field6, command, flags, session, channel = HEADER.unpack_from(plain)
    if magic != 0x0204 or profile != 4 or size != len(plain) - 16 or channel > 31:
        raise ValueError("UBIA 报文标志、长度或通道不符合当前格式")
    return NativePacket(command, flags, session, channel, plain[16:])


def pack(command: int, payload: bytes, *, session_id=0, channel=0, flags=0x21) -> bytes:
    if not 0 <= session_id <= 65535 or not 0 <= channel <= 31 or len(payload) > 1400:
        raise ValueError("会话字段、通道或载荷范围无效")
    return transform(HEADER.pack(0x0204, 4, len(payload), 0, command, flags, session_id, channel) + payload)


def connection_payload(username: str, password: str) -> bytes:
    fields = [value.encode("utf-8") for value in (username, password)]
    if any(len(value) > 12 or b"\0" in value for value in fields):
        raise ValueError("原生认证字段各限 12 字节，不能沿用 UDPhd 的 32 字节限制")
    return b"\x01\0\0\0" + fields[0].ljust(12, b"\0") + fields[1].ljust(12, b"\0") + bytes(8)


class NativeReadSession:
    def __init__(self, target: str, uid: str, *, port=32761, channel=0, timeout=8.0,
                 bind_ip="0.0.0.0", request_id=None):
        address = ipaddress.IPv4Address(target)
        if not (address.is_private or address.is_loopback) or address.is_multicast or address.is_unspecified:
            raise ValueError("必须指定明确的本地 IPv4 网关地址")
        uid_bytes = uid.encode("ascii")
        if len(uid_bytes) != 20 or b"\0" in uid_bytes or not 0 <= channel <= 31 or not 0 < timeout <= 30:
            raise ValueError("UID 应为 20 字节 ASCII；还需有效的通道和等待时间")
        self.address = str(address)
        self.peer = (self.address, port)
        self.uid = uid_bytes
        self.channel = channel
        self.timeout = timeout
        self.request_id = request_id if request_id is not None else secrets.randbits(24) << 8
        if not 0 <= self.request_id <= 0xFFFFFFFF:
            raise ValueError("请求标识超出 32 位范围")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((bind_ip, 0))
        except Exception:
            self.socket.close()
            raise
        self.session_id = None  # 设备侧会话号 0 是有效值，不能用真假判断表示是否已建立。
        self.state = "NEW"
        self.server_capabilities = 0
        self.sequence = 0
        self.next_live = float("inf")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.state = "CLOSED"
        self.session_id = None
        self.socket.close()

    def _send(self, data: bytes):
        self.socket.sendto(data, self.peer)

    def _poll(self, deadline: float, *, discovering=False):
        now = time.monotonic()
        # 原库的 Timer 31 每秒保活；本工具只在短时操作等待期间维持这一定时行为。
        if self.session_id is not None and now >= self.next_live:
            payload = struct.pack("<I", self.request_id) + bytes(16)
            self._send(pack(0x0427, payload, session_id=self.session_id))
            self.next_live = now + 1
        wait = min(0.1, deadline - time.monotonic())
        if wait <= 0:
            return None
        self.socket.settimeout(wait)
        try:
            data, peer = self.socket.recvfrom(4096)
        except socket.timeout:
            return None
        if peer[0] != self.address or (not discovering and peer != self.peer):
            return None
        try:
            packet = unpack(data)
        except ValueError:
            return None
        if self.session_id is not None and packet.command in (0x0408, 0x0428):
            if packet.session_id != self.session_id or packet.flags & 0xF != 2:
                return None
        return packet, peer

    def discover(self, proxy_level=0) -> dict:
        if self.state != "NEW":
            raise RuntimeError("发现应在新会话中进行")
        self._send(discovery_request(proxy_level))
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            received = self._poll(deadline, discovering=True)
            if received:
                packet, peer = received
                if packet.command in (0x0602, 0x0604) and packet.payload[:20] == self.uid:
                    # 原库使用发现回复的来源地址继续握手，端口不一定仍是广播监听端口。
                    self.peer = peer
                    self.state = "DISCOVERED"
                    return {"IP": peer[0], "端口": peer[1], "UID末四位": self.uid[-4:].decode()}
        raise TimeoutError("未收到目标 UID 的发现回复")

    def handshake(self):
        if self.state != "DISCOVERED":
            raise RuntimeError("需要先发现目标设备")
        body = self.uid + struct.pack("<I", self.request_id) + bytes(8)
        request = pack(0x0401, body)
        deadline = time.monotonic() + self.timeout
        next_send = 0
        attempts = 0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send and attempts < 4:
                self._send(request)
                next_send = time.monotonic() + 1
                attempts += 1
            received = self._poll(deadline)
            if not received:
                continue
            packet, _ = received
            # 2026-09-30 实物旧固件回复为 24 字节，新 APK 中发送函数为 32 字节。
            # 两者前 24 字节均为 UID 与请求标识，差异是末尾保留区。
            if packet.command != 0x0402 or len(packet.payload) not in (24, 32) or packet.flags & 0xF != 2:
                continue
            if packet.payload[:20] != self.uid or struct.unpack_from("<I", packet.payload, 20)[0] != self.request_id:
                continue
            if packet.flags & 0x400:
                self.state = "FAILED"
                raise PermissionError("设备拒绝传输握手，标志 0x400")
            self.session_id = packet.session_id
            self._send(pack(0x0404, body[:len(packet.payload)], session_id=self.session_id))
            self.state = "TRANSPORT_READY"
            self.next_live = time.monotonic() + 1
            return
        self.state = "FAILED"
        raise TimeoutError("传输握手没有完成")

    def _send_av(self, payload: bytes):
        if self.session_id is None:
            raise RuntimeError("传输会话尚未建立")
        self._send(pack(0x0407, payload, session_id=self.session_id, channel=self.channel))

    def login(self, username: str, password: str):
        if self.state != "TRANSPORT_READY":
            raise RuntimeError("应用认证必须在传输握手之后")
        request = connection_payload(username, password)
        deadline = time.monotonic() + self.timeout
        next_send = 0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                self._send_av(request)
                next_send = time.monotonic() + 0.3
            received = self._poll(deadline)
            if not received:
                continue
            packet, _ = received
            if packet.command != 0x0408 or packet.channel != self.channel or len(packet.payload) != 36 or packet.payload[0] != 2:
                continue
            if not struct.unpack_from("<I", packet.payload, 28)[0]:
                self.state = "FAILED"
                raise PermissionError("应用账户认证被拒绝")
            self.server_capabilities = struct.unpack_from("<I", packet.payload, 32)[0]
            self.state = "AV_AUTHENTICATED"
            return {"阶段": "AV 通道认证已通过", "服务器能力值": self.server_capabilities,
                    "支持扩展用户认证": bool(self.server_capabilities & (1 << 24)),
                    "限制": "原 App 另有用户授权分支；AV 通道认证不等于所有设备权限已核实。"}
        self.state = "FAILED"
        raise TimeoutError("应用认证未完成")

    def query(self, name: str) -> dict:
        if self.state != "AV_AUTHENTICATED":
            raise PermissionError("AV 通道认证通过后才能发起只读查询")
        if name not in QUERY_IDS:
            raise ValueError("只允许设备列表和状态查询")
        sub = QUERY_IDS[name]
        payload = struct.pack("<IIII", sub, 0, 0, 1 if sub == 6 else 0)
        self.sequence = (self.sequence + 1) & 65535 or 1
        sequence = self.sequence
        request = IO_HEADER.pack(3, 0, len(payload), 0x2102, sequence, 0) + payload
        started_at = time.monotonic()
        deadline = started_at + self.timeout
        next_send = 0
        acknowledged = False
        records = {}
        seen = set()
        started = False
        while time.monotonic() < deadline:
            if not acknowledged and time.monotonic() >= next_send and time.monotonic() - started_at < 3:
                self._send_av(request)
                next_send = time.monotonic() + 0.15
            received = self._poll(deadline)
            if not received:
                continue
            packet, _ = received
            if packet.command != 0x0408 or packet.channel != self.channel or len(packet.payload) < 12:
                continue
            kind, reserved, size, command, received_sequence, padding = IO_HEADER.unpack_from(packet.payload)
            if kind == 4 and len(packet.payload) == 12 and command == 0x2102 and received_sequence == sequence:
                acknowledged = True
                continue  # 传输 ACK 不能替代设备列表／状态回复。
            if kind != 3 or len(packet.payload) != 12 + size:
                continue
            self._send_av(IO_HEADER.pack(4, 0, 0, command, received_sequence, 0))
            # 原库对重复 IO 数据仍回 ACK，但仅向业务层交付一次。
            fingerprint = (command, received_sequence)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            if command != 0x2103 or size < 8 or struct.unpack_from("<I", packet.payload, 16)[0] != sub:
                continue
            batch = parse_read_batch(packet.payload[12:])
            if batch.end_flag == 2:
                if started:
                    raise ValueError("重复开始另一批读取，未合并不同查询结果")
                records.clear()
            if batch.end_flag == 1:
                return {"查询": name, "收到请求ACK": acknowledged, "收到结束通知": True,
                        "记录": list(records.values()), "限制": "仅验证候选 UDP 直连协议；未覆盖中继、重连与实物丢包情况。"}
            started = True
            for record in batch.records:
                records[record["设备索引"]] = record
        raise TimeoutError("读取未获得结束通知，未将 ACK 或部分数据当成成功")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--uid", required=True, help="实际设备的 20 字节 UID")
    parser.add_argument("--username", required=True)
    parser.add_argument("--channel", type=int, default=0, help="候选 AV 通道，需与实物／原 App 核对")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print("未联网。显式添加 --execute 才会交互输入密码并执行发现、握手、认证和只读查询。")
        return
    password = getpass.getpass("网关密码（最多 12 字节，不回显）：")
    with NativeReadSession(args.target, args.uid, channel=args.channel) as session:
        import json
        print(json.dumps(session.discover(), ensure_ascii=False))
        session.handshake()
        print(json.dumps(session.login(args.username, password), ensure_ascii=False))
        password = ""
        devices = session.query("all_devices")
        states = session.query("all_states")
        print(json.dumps({"设备": devices, "状态": states,
                          "开关": merge_switch_states(devices["记录"], states["记录"])}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
