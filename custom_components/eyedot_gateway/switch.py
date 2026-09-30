"""把已验证的类型 13 设备映射成左、中、右三个原生开关。"""

import hashlib

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CHANNEL_NAMES, DOMAIN, SUPPORTED_TYPE


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    known = set()

    @callback
    def add_new_devices():
        additions = []
        for index, device in (coordinator.data or {}).items():
            if device.device_type != SUPPORTED_TYPE or index in known:
                continue
            known.add(index)
            additions.extend(EyedotSwitch(coordinator, index, channel) for channel in range(3))
        if additions:
            async_add_entities(additions)

    add_new_devices()
    entry.async_on_unload(coordinator.async_add_listener(add_new_devices))


class EyedotSwitch(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:light-switch"

    def __init__(self, coordinator, index, channel):
        super().__init__(coordinator)
        self.index = index
        self.channel = channel
        identity = hashlib.sha256(f"{coordinator.entry.data['uid']}:{index}".encode()).hexdigest()[:16]
        self._attr_unique_id = f"{identity}_{channel}"
        self._attr_name = CHANNEL_NAMES[channel]
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, identity)},
            name=coordinator.data[index].name or f"三路开关 {index}",
            manufacturer="Eyedot", model="SW-N3-01",
            via_device_id=coordinator.gateway_device_id,
        )

    @property
    def available(self):
        device = (self.coordinator.data or {}).get(self.index)
        return super().available and device is not None and device.device_type == SUPPORTED_TYPE and device.state is not None

    @property
    def is_on(self):
        device = (self.coordinator.data or {}).get(self.index)
        if device is None or device.state is None:
            return None
        return bool(device.state & (1 << self.channel))

    async def async_turn_on(self, **kwargs):
        await self.coordinator.async_control(self.index, self.channel, True)

    async def async_turn_off(self, **kwargs):
        await self.coordinator.async_control(self.index, self.channel, False)
