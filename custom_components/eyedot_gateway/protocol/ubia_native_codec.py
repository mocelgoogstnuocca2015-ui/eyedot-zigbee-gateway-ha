"""UBIA 原生发现协议的离线编解码；由 IDA MCP 反编译结果还原，不联网。"""

import argparse
import json
import struct
from pathlib import Path


MASK = b"I believe 1 ^ill win the battle!"
PERMUTATIONS = {
    2: (1, 0),
    4: (2, 3, 0, 1),
    8: (7, 4, 3, 2, 1, 6, 5, 0),
    16: (11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3),
}


def swap(data: bytes) -> bytes:
    order = PERMUTATIONS.get(len(data), range(len(data)))
    return bytes(data[index] for index in order)


def xor(data: bytes) -> bytes:
    return bytes(value ^ MASK[index] for index, value in enumerate(data))


def rotate_words(data: bytes, base: int, reverse: bool = False) -> bytes:
    result = bytearray()
    for offset in range(0, 16, 4):
        value = int.from_bytes(data[offset:offset + 4], "little")
        shift = offset + base
        if reverse:
            shift = 32 - shift
        rotated = ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF
        result.extend(rotated.to_bytes(4, "little"))
    return bytes(result)


def transform(data: bytes, reverse: bool = False) -> bytes:
    if len(data) > 65535:
        raise ValueError("输入超出原函数的 16 位长度范围")
    result = bytearray()
    full = len(data) // 16 * 16
    for offset in range(0, full, 16):
        block = data[offset:offset + 16]
        if reverse:
            result.extend(rotate_words(xor(swap(rotate_words(block, 3, True))), 1, True))
        else:
            result.extend(rotate_words(swap(xor(rotate_words(block, 1))), 3))
    # 原函数尾部长度不足 16 时不旋转；2、4、8 字节有特殊置换。
    tail = data[full:]
    result.extend(xor(swap(tail)) if reverse else swap(xor(tail)))
    return bytes(result)


def discovery_request(proxy_level: int, extended: bool = False) -> bytes:
    if not 0 <= proxy_level <= 15:
        raise ValueError("报文中的代理等级字段应为 0..15，实物使用值尚待确认")
    command = 0x0603 if extended else 0x0601
    plain = struct.pack("<8H", 0x0204, 4, 0, 0, command, (proxy_level << 12) | 0x21, 0, 0)
    return transform(plain)


def inspect(data: bytes) -> dict:
    plain = transform(data, True)
    if len(plain) < 16:
        raise ValueError("报文不足 16 字节")
    magic, field2, size, field6, command, flags, field12, field14 = struct.unpack_from("<8H", plain)
    if magic != 0x0204:
        raise ValueError("解码后不符合已知 UBIA 报文标志")
    if len(plain) != 16 + size:
        raise ValueError("解码后长度与声明不一致")
    result = {"命令": f"0x{command:04x}", "代理等级高4位": flags >> 12,
              "标志低12位": f"0x{flags & 0xFFF:03x}", "数据长度": size,
              "偏移2字段": field2, "偏移6字段": field6, "偏移12字段": field12,
              "偏移14字段": field14, "说明": "结构符合候选协议，不等于真实网关兼容性或身份已确认"}
    if command in (0x0602, 0x0604) and size >= 20:
        uid = plain[16:36].split(b"\0", 1)[0].decode("ascii", errors="replace")
        result["UID末四位"] = uid[-4:]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    build = commands.add_parser("discovery-frame", help="只生成请求，不发送")
    build.add_argument("--proxy-level", type=int, required=True)
    decode = commands.add_parser("decode", help="离线解析一条 UDP 原始载荷")
    decode.add_argument("file", type=Path)
    args = parser.parse_args()
    if args.action == "decode":
        print(json.dumps(inspect(args.file.read_bytes()), ensure_ascii=False, indent=2))
    else:
        print("UBIA UDP 32761 发现请求候选：", discovery_request(args.proxy_level).hex(" "))
        print("仅离线生成，没有发送网络数据；代理等级值尚待实物验证。")


if __name__ == "__main__":
    main()
