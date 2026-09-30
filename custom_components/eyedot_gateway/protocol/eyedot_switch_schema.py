"""根据旧 App 的明确开关类型解析状态、生成离线控制数据；不发送任何报文。"""

import argparse
import json
import struct


SWITCH_CHANNELS = {11: 1, 12: 2, 13: 3, 14: 4}


def decode_switch_state(device_type: int, state: int) -> list[dict]:
    if device_type not in SWITCH_CHANNELS or not 0 <= state <= 0xFFFFFFFF:
        raise ValueError("只处理 App 中明确的一至四路开关类型及无符号状态值")
    # App 对开关按逻辑通道索引取位；不要套用窗帘、调光器或场景面板的解释。
    return [{"逻辑通道": channel, "开": bool((state >> channel) & 1)}
            for channel in range(SWITCH_CHANNELS[device_type])]


def build_switch_payload(device_type: int, device_index: int, channel: int, on: bool) -> bytes:
    if device_type not in SWITCH_CHANNELS or not 0 <= channel < SWITCH_CHANNELS[device_type]:
        raise ValueError("设备类型或通道索引无效")
    if not 0 <= device_index <= 255 or not isinstance(on, bool):
        raise ValueError("设备索引应为单字节，开关值应为布尔值")
    # 0x2146 的数据区。最后一字节来自实际开关 onClick 的参数 1。
    # 实物通道、设备类型和索引尚未验证，函数只用于离线复核。
    return struct.pack("<IIBBBB", device_type, 4, device_index, int(on), channel, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--type", type=int, choices=sorted(SWITCH_CHANNELS), required=True)
    parser.add_argument("--state", type=lambda text: int(text, 0), required=True)
    args = parser.parse_args()
    print(json.dumps({"设备类型": args.type, "通道": decode_switch_state(args.type, args.state),
                      "限制": "仅解释 App 定义；通道与实物按键的对应关系尚待验证。"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
