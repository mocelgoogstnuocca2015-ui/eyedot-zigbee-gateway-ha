"""每个网关提供一次性配对入口，按下后开放最多两分钟。"""

from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([EyedotPairButton(entry.runtime_data)])


class EyedotPairButton(CoordinatorEntity, ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "配对新开关"
    _attr_icon = "mdi:access-point-plus"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.unique_id}_pair"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.entry.unique_id)},
            name="Eyedot Zigbee 网关", manufacturer="Eyedot / ZSKJ", model="UBIA 本地网关",
            configuration_url=f"http://{coordinator.entry.data['host']}",
        )

    @property
    def available(self):
        return super().available and not (self.coordinator.pair_task and not self.coordinator.pair_task.done())

    @property
    def extra_state_attributes(self):
        return {"配对状态": self.coordinator.pair_status, "配对错误": self.coordinator.pair_error}

    async def async_press(self):
        await self.coordinator.async_pair()
