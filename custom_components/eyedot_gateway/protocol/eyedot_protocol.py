"""旧 App 局域网协议实验工具：默认离线，网络功能仅发送单次发现请求。

结构来自候选 APK 的 DEX 静态分析，尚未通过原厂网关验证。
本模块不会发送配对、继电器控制、复位或固件写入命令。
"""

import argparse
import ipaddress
import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path


HEADER = struct.Struct("<BBHIIIII")
GATEWAY_PORT = 34224
APP_PORT = 34226
TYPE_NAMES = {0x51: "发现请求", 0x52: "发现回复", 0x53: "登录请求", 0x54: "登录回复", 0x57: "控制请求", 0x58: "控制回复", 0x59: "心跳请求", 0x5A: "心跳回复"}


@dataclass(frozen=True)
class Packet:
    message_type: int
    reply_port: int
    auth: int
    field16: int
    field20: int
    payload: bytes
    response_command: int | None = None

    def summary(self) -> dict:
        # 登录数据和认证字段不进入诊断输出；未知载荷也不默认转储。
        result = {
            "消息类型": TYPE_NAMES.get(self.message_type, f"未知 0x{self.message_type:x}"),
            "回复端口": self.reply_port,
            "认证字段非零": bool(self.auth),
            "偏移16字段": self.field16,
            "偏移20字段": self.field20,
            "载荷字节": len(self.payload),
            "内层回复命令": None if self.response_command is None else f"0x{self.response_command:04x}",
            "证据范围": "按候选 APK 结构解析，未验证设备兼容性",
        }
        if self.message_type == 0x54:
            result["登录结果"] = "成功" if self.field20 == 0 else "失败"
        if self.message_type == 0x52 and len(self.payload) == 120:
            record = parse_discovery_record(self.payload)
            uid = record.pop("UID")
            record["UID末四位"] = uid[-4:]
            result["发现记录"] = record
        return result


def encode_request(message_type: int, payload: bytes = b"", *, reply_port: int = APP_PORT,
                   auth: int = 0, field16: int = 0, field20: int = 0) -> bytes:
    if message_type not in (0x51, 0x53):
        raise ValueError("此实验工具只构造发现或登录请求")
    if not 1 <= reply_port <= 65535 or len(payload) > 65507 - HEADER.size:
        raise ValueError("端口或报文长度无效")
    return HEADER.pack(0x68, 0, reply_port, message_type, auth, len(payload), field16, field20) + payload


def build_login(username: str, password: str, *, reply_port: int = APP_PORT) -> bytes:
    # App 使用两个各 32 字节的字段；主动拒绝截断，避免多字节文字被截坏。
    parts = [value.encode("utf-8") for value in (username, password)]
    if any(len(part) > 32 or b"\0" in part for part in parts):
        raise ValueError("登录字段必须不超过 32 字节且不包含空字节")
    return encode_request(0x53, b"".join(part.ljust(32, b"\0") for part in parts), reply_port=reply_port)


def parse_discovery_record(data: bytes) -> dict:
    if len(data) != 120:
        raise ValueError("当前版本的发现记录应为 120 字节")
    # DeviceInfo([B,I) 中 32..107 是能力区域；当前只解释它的前四字节。
    # IP 先按小端转整数，再由 App 从高字节到低字节显示，不能直接逐字节打印。
    return {
        "UID": data[:32].split(b"\0", 1)[0].decode("utf-8", errors="replace"),
        "能力值": struct.unpack_from("<I", data, 32)[0],
        "IP": str(ipaddress.IPv4Address(struct.unpack_from("<I", data, 108)[0])),
        "设备ID": struct.unpack_from("<I", data, 112)[0],
        "端口": struct.unpack_from("<H", data, 116)[0],
        "未解释能力区字节数": 72,
    }


def build_read_query(query: str, auth: int, *, reply_port: int = APP_PORT) -> bytes:
    # 命令 0x2102 是多用途入口，必须限制到已从 getter 方法核实的读子命令。
    # 不提供任意子命令接口，避免误用同一入口下的编辑或删除操作。
    layouts = {"all_devices": (6, 0, 0, 1), "all_states": (16, 0, 0, 0)}
    if query not in layouts or not 0 < auth <= 0xFFFFFFFF or not 1 <= reply_port <= 65535:
        raise ValueError("读取类型、会话认证字段或回复端口无效")
    payload = struct.pack("<IIII", *layouts[query])
    return HEADER.pack(0x68, 0, reply_port, 0x57, auth, len(payload), 0, 0x2102) + payload


def build_heartbeat(auth: int, *, reply_port: int = APP_PORT) -> bytes:
    if not 0 < auth <= 0xFFFFFFFF or not 1 <= reply_port <= 65535:
        raise ValueError("会话认证字段或回复端口无效")
    return HEADER.pack(0x68, 0, reply_port, 0x59, auth, 0, 0, 0)


def decode_packet(data: bytes) -> Packet:
    if len(data) < HEADER.size:
        raise ValueError("报文短于 24 字节头部")
    magic, reserved, port, kind, auth, size, field16, field20 = HEADER.unpack_from(data)
    if magic != 0x68 or reserved != 0:
        raise ValueError("报文标志不符合已观察到的 68 00")

    # APK 的 SMsgAVIoctrl_ReturnDataHead2 从偏移 24 取命令、28 取数据。
    # 长度字段只计数据，不包含额外的四字节命令；不能对所有消息统一切片。
    extra = 4 if kind == 0x58 and field20 == 0 else 0
    expected = HEADER.size + extra + size
    if len(data) != expected:
        raise ValueError(f"长度不一致：头部声明需要 {expected} 字节，实际 {len(data)} 字节")
    command = struct.unpack_from("<I", data, HEADER.size)[0] if extra else None
    return Packet(kind, port, auth, field16, field20, data[HEADER.size + extra:], command)


def discover_once(target: str, *, bind_ip: str = "0.0.0.0", timeout: float = 3.0,
                  gateway_port: int = GATEWAY_PORT, reply_port: int = APP_PORT) -> list[dict]:
    address = ipaddress.IPv4Address(target)
    if not (address.is_private or address.is_loopback) or address.is_unspecified or address.is_multicast:
        raise ValueError("单次探测目标必须是明确的本地 IPv4 地址")
    if not 0 < timeout <= 10:
        raise ValueError("等待时间必须在 0 到 10 秒之间")

    results = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind((bind_ip, reply_port))
        actual_port = receiver.getsockname()[1]
        receiver.settimeout(timeout)
        receiver.sendto(encode_request(0x51, reply_port=actual_port), (str(address), gateway_port))
        # 一次请求只接受一个来自指定 IP 的发现回复，不进行网段扫描或持续广播。
        try:
            data, peer = receiver.recvfrom(65535)
        except socket.timeout:
            return results
        if peer[0] != str(address):
            raise ValueError("收到非指定目标的数据，未将其视为目标回复")
        packet = decode_packet(data)
        if packet.message_type != 0x52:
            raise ValueError("收到的不是发现回复")
        results.append({"来源IP": peer[0], "来源端口": peer[1], **packet.summary()})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("discovery-frame", help="离线显示一个发现请求，不发包")
    decode = commands.add_parser("decode", help="离线解析一条二进制 UDP 载荷")
    decode.add_argument("file", type=Path)
    discover = commands.add_parser("discover", help="仅向指定本地 IP 发一个只读发现请求")
    discover.add_argument("--target", required=True)
    discover.add_argument("--send", action="store_true", help="实际发包；省略时只显示请求")
    args = parser.parse_args()
    if args.action == "decode":
        print(json.dumps(decode_packet(args.file.read_bytes()).summary(), ensure_ascii=False, indent=2))
    elif args.action == "discover" and args.send:
        print(json.dumps(discover_once(args.target), ensure_ascii=False, indent=2))
    else:
        print("离线发现请求：", encode_request(0x51).hex(" "))
        print("没有发送网络数据。")


if __name__ == "__main__":
    main()
