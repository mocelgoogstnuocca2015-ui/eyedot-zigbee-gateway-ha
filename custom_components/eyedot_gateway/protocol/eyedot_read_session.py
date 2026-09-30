"""候选 UDPhd 协议的只读会话：发现、登录、心跳及子设备查询。"""

import argparse
import getpass
import ipaddress
import json
import socket
import struct
import time
from dataclasses import dataclass

from .eyedot_protocol import APP_PORT, GATEWAY_PORT, build_heartbeat, build_login, build_read_query, decode_packet, encode_request
from .eyedot_switch_schema import SWITCH_CHANNELS, decode_switch_state


RESPONSE_COMMAND = 0x2103
QUERY_IDS = {"all_devices": 6, "all_states": 16}


@dataclass
class ReadBatch:
    subcommand: int
    current_index: int
    count: int
    end_flag: int
    result: int
    records: list[dict]


def merge_switch_states(devices: list[dict], states: list[dict]) -> list[dict]:
    # 设备类型来自设备列表，三字节状态来自另一个查询；用设备索引连接两者。
    by_index = {row["设备索引"]: row for row in states}
    result = []
    for device in devices:
        if device["设备类型"] not in SWITCH_CHANNELS or device["设备索引"] not in by_index:
            continue
        state_bytes = bytes(by_index[device["设备索引"]]["状态原始字节"])
        if len(state_bytes) != 3:
            raise ValueError("状态记录应包含三个状态字节")
        state = int.from_bytes(state_bytes, "little")
        result.append({"名称": device["名称"], "设备索引": device["设备索引"],
                       "设备类型": device["设备类型"], "逻辑通道": decode_switch_state(device["设备类型"], state)})
    return result


def parse_read_batch(payload: bytes) -> ReadBatch:
    if len(payload) < 32:
        raise ValueError("子设备回复不足 32 字节内部头")
    cmd, sub, size, current, count, saved, end_flag, result = struct.unpack_from("<7Ii", payload)
    if sub not in (6, 16):
        raise ValueError("当前解析器不处理该子命令")
    if size != len(payload) - 32 or end_flag not in (0, 1, 2):
        raise ValueError("内部数据长度或结束标志异常")
    if result < 0:
        raise RuntimeError(f"网关读查询返回失败：{result}")
    if end_flag == 1:
        # 原 App 以独立结束通知完成查询，不能把此前收到的任意一个包当作结束。
        if size:
            raise ValueError("结束通知带有未解释数据，保留原包待核对")
        return ReadBatch(sub, current, count, end_flag, result, [])

    width = 40 if sub == 6 else 8
    if size != count * width:
        raise ValueError("本包记录数与数据长度不匹配")
    records = []
    for offset in range(32, len(payload), width):
        raw = payload[offset:offset + width]
        if sub == 6:
            records.append({"名称": raw[:32].split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                            "设备索引": raw[32], "设备类型": raw[33],
                            "状态整数": struct.unpack_from("<I", raw, 34)[0], "房间索引": raw[38]})
        else:
            # 三字节状态的位意义依设备类型而变化；不直接把它们命名为三路继电器。
            records.append({"设备索引": raw[0], "状态原始字节": list(raw[1:4]),
                            "信号原始字节": list(raw[4:6]), "状态采样字段": current})
    return ReadBatch(sub, current, count, end_flag, result, records)


class ReadOnlySession:
    def __init__(self, target: str, *, gateway_port: int = GATEWAY_PORT,
                 bind_ip: str = "0.0.0.0", reply_port: int = APP_PORT, timeout: float = 8):
        address = ipaddress.IPv4Address(target)
        if not (address.is_private or address.is_loopback) or address.is_multicast or address.is_unspecified:
            raise ValueError("目标应为明确的本地 IPv4 地址")
        if not 0 < timeout <= 30:
            raise ValueError("单次操作等待时间应为 0..30 秒")
        self.target = (str(address), gateway_port)
        self.timeout = timeout
        self.auth = 0
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((bind_ip, reply_port))
        except Exception:
            self.socket.close()
            raise
        self.reply_port = self.socket.getsockname()[1]
        self.next_heartbeat = 0.0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.auth = 0
        self.socket.close()

    def _send(self, data: bytes):
        self.socket.sendto(data, self.target)

    def _receive(self, deadline: float):
        while time.monotonic() < deadline:
            now = time.monotonic()
            if self.auth and now >= self.next_heartbeat:
                self.heartbeat()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wait = min(remaining, max(0.01, self.next_heartbeat - time.monotonic())) if self.auth else remaining
            self.socket.settimeout(wait)
            try:
                data, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            if peer != self.target:
                continue
            try:
                packet = decode_packet(data)
            except ValueError:
                continue
            if self.auth and packet.auth != self.auth:
                continue
            return packet
        raise TimeoutError("未在截止时间前收到匹配的回复；不将部分结果视为完整")

    def discover(self) -> dict:
        self._send(encode_request(0x51, reply_port=self.reply_port))
        deadline = time.monotonic() + self.timeout
        while True:
            packet = self._receive(deadline)
            if packet.message_type == 0x52:
                return packet.summary()

    def login(self, username: str, password: str):
        self.auth = 0
        self._send(build_login(username, password, reply_port=self.reply_port))
        deadline = time.monotonic() + self.timeout
        while True:
            packet = self._receive(deadline)
            if packet.message_type != 0x54:
                continue
            if packet.field20 != 0:
                raise PermissionError(f"登录失败，网关返回码 {packet.field20}")
            if packet.auth == 0:
                raise ValueError("收到零认证值；当前客户端不推断其会话语义")
            self.auth = packet.auth
            self.next_heartbeat = 0
            self.heartbeat()
            return

    def heartbeat(self):
        if not self.auth:
            raise PermissionError("需要先建立有效会话")
        self._send(build_heartbeat(self.auth, reply_port=self.reply_port))
        self.next_heartbeat = time.monotonic() + 3

    def query(self, name: str) -> dict:
        if not self.auth:
            raise PermissionError("需要先登录，再发送读查询")
        self._send(build_read_query(name, self.auth, reply_port=self.reply_port))
        deadline = time.monotonic() + self.timeout
        records = {}
        seen = set()
        started = False
        while True:
            packet = self._receive(deadline)
            if packet.message_type == 0x58 and packet.field20 != 0:
                raise RuntimeError(f"外层查询返回失败：{packet.field20}")
            if packet.message_type != 0x58 or packet.response_command != RESPONSE_COMMAND:
                continue
            if len(packet.payload) < 8:
                continue
            if struct.unpack_from("<I", packet.payload, 4)[0] != QUERY_IDS[name]:
                continue
            batch = parse_read_batch(packet.payload)
            if packet.payload in seen:
                continue
            seen.add(packet.payload)
            if batch.end_flag == 2:
                if started:
                    raise ValueError("查询中途再次出现开始标志，不能混合两轮结果")
                records.clear()
            if batch.end_flag == 1:
                return {"查询": name, "已收到结束标志": True, "记录": list(records.values()),
                        "限制": "UDP 没有已核实的完整事务编号；收齐结束标志仍不保证中间无丢包。"}
            started = True
            for record in batch.records:
                records[record["设备索引"]] = record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--execute", action="store_true", help="实际向指定网关发起只读会话")
    args = parser.parse_args()
    if not args.execute:
        print("未联网。显式添加 --execute 后，将交互输入密码并执行发现、登录和两类读查询。")
        return
    password = getpass.getpass("网关密码（不回显、不写入文件）：")
    with ReadOnlySession(args.target) as session:
        print(json.dumps(session.discover(), ensure_ascii=False, indent=2))
        session.login(args.username, password)
        password = ""
        devices = session.query("all_devices")
        states = session.query("all_states")
        print(json.dumps({"设备列表": devices, "原始状态": states,
                          "已识别开关": merge_switch_states(devices["记录"], states["记录"])}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
