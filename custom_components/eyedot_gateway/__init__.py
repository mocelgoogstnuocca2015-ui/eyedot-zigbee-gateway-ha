"""Eyedot 原厂兼容网关的局域网集成。"""

from homeassistant.helpers import device_registry

from .const import DOMAIN, PLATFORMS
from .coordinator import EyedotCoordinator


async def async_setup_entry(hass, entry):
    coordinator = EyedotCoordinator(hass, entry)
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await coordinator.async_close()
        raise
    entry.runtime_data = coordinator
    registry = device_registry.async_get(hass)
    gateway = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.unique_id)},
        name="Eyedot Zigbee 网关", manufacturer="Eyedot / ZSKJ", model="UBIA 本地网关",
        configuration_url=f"http://{entry.data['host']}",
    )
    coordinator.gateway_device_id = gateway.id
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        await coordinator.async_start_events()
    except Exception:
        await coordinator.async_close()
        raise
    return True


async def async_unload_entry(hass, entry):
    if await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await entry.runtime_data.async_close()
        return True
    return False
