"""导出已脱敏的兼容性信息，不包含认证字段或完整网关 UID。"""

from homeassistant.components.diagnostics import async_redact_data


async def async_get_config_entry_diagnostics(hass, entry):
    coordinator = entry.runtime_data
    return {
        "connection": async_redact_data(dict(entry.data), {"host", "username", "password", "uid"}),
        "options": dict(entry.options),
        "last_update_success": coordinator.last_update_success,
        "event_listener_running": coordinator.client.event_listener_running,
        "event_notifications": coordinator.client.event_notifications,
        "last_push_refresh_seconds": coordinator.last_push_refresh_seconds,
        "devices": [{"index": item.index, "type": item.device_type,
                     "supported": item.device_type == 13, "state": item.state}
                    for item in (coordinator.data or {}).values()],
    }
