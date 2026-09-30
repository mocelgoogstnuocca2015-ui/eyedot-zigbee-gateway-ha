"""在真实 HA 核心中验证配置流程、实体、动态发现及卸载。"""

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from homeassistant import config_entries, loader
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry, entity_registry, frame
from homeassistant.setup import async_setup_component

from custom_components.eyedot_gateway.client import DeviceState
from custom_components.eyedot_gateway.const import DOMAIN


UID = "01234567890123456789"
INPUT = {"host": "192.168.50.2", "username": "test", "password": "test", "uid": ""}


class FakeClient:
    def __init__(self, host, username, password, uid):
        import threading
        self.uid = uid
        self.closed = False
        self.cancel_pairing = threading.Event()
        self.rows = {0: DeviceState(0, "测试开关", 13, 128), 1: DeviceState(1, "未知设备", 17, None)}

    def fetch(self):
        return dict(self.rows)

    def control(self, index, channel, on):
        row = self.rows[index]
        state = row.state | (1 << channel) if on else row.state & ~(1 << channel)
        self.rows[index] = DeviceState(index, row.name, row.device_type, state)
        return self.fetch()

    def close(self):
        self.closed = True
        self.cancel_pairing.set()

    def pair(self):
        self.rows[2] = DeviceState(2, "新配对开关", 13, 128)
        return self.fetch()


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        shutil.copytree(Path(__file__).resolve().parents[1] / "custom_components",
                        Path(self.directory.name) / "custom_components")
        self.hass = HomeAssistant(self.directory.name)
        self.hass.config.skip_pip = True
        self.hass.config.time_zone = "Asia/Shanghai"
        loader.async_setup(self.hass)
        frame.async_setup(self.hass)
        self.hass.config_entries = config_entries.ConfigEntries(self.hass, {})
        await self.hass.config_entries.async_initialize()
        device_registry.async_setup(self.hass)
        await device_registry.async_load(self.hass)
        await entity_registry.async_load(self.hass)
        self.client_patch = patch("custom_components.eyedot_gateway.coordinator.GatewayClient", FakeClient)
        self.client_patch.start()
        self.validate_patch = patch("custom_components.eyedot_gateway.config_flow.validate_gateway",
                                    return_value=({**INPUT, "uid": UID}, {}))
        self.validate_patch.start()
        self.assertTrue(await async_setup_component(self.hass, "homeassistant", {}))
        self.assertTrue(await async_setup_component(self.hass, DOMAIN, {}))

    async def asyncTearDown(self):
        for entry in self.hass.config_entries.async_entries(DOMAIN):
            await self.hass.config_entries.async_unload(entry.entry_id)
        await self.hass.async_stop()
        self.client_patch.stop()
        self.validate_patch.stop()
        self.directory.cleanup()

    async def add_entry(self):
        result = await self.hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"}, data=INPUT)
        self.assertEqual(result["type"], "create_entry")
        await self.hass.async_block_till_done(wait_background_tasks=True)
        return result["result"]

    async def test_entities_control_dynamic_device_and_unload(self):
        entry = await self.add_entry()
        registry = entity_registry.async_get(self.hass)
        rows = entity_registry.async_entries_for_config_entry(registry, entry.entry_id)
        self.assertEqual(len([row for row in rows if row.domain == "switch"]), 3)
        self.assertEqual(len([row for row in rows if row.domain == "button"]), 1)
        identity = hashlib.sha256(f"{UID}:0".encode()).hexdigest()[:16]
        entity = registry.async_get_entity_id("switch", DOMAIN, identity + "_0")
        self.assertEqual(self.hass.states.get(entity).state, "off")
        await self.hass.services.async_call("switch", "turn_on", {"entity_id": entity}, blocking=True)
        self.assertEqual(self.hass.states.get(entity).state, "on")
        await self.hass.services.async_call("switch", "turn_off", {"entity_id": entity}, blocking=True)
        self.assertEqual(self.hass.states.get(entity).state, "off")
        coordinator = entry.runtime_data
        coordinator.client.rows[2] = DeviceState(2, "第二只开关", 13, 128)
        await coordinator.async_request_refresh()
        await self.hass.async_block_till_done()
        rows = entity_registry.async_entries_for_config_entry(registry, entry.entry_id)
        self.assertEqual(len([row for row in rows if row.domain == "switch"]), 6)
        client = coordinator.client
        self.assertTrue(await self.hass.config_entries.async_unload(entry.entry_id))
        self.assertTrue(client.closed)

    async def test_duplicate_gateway_is_not_added_twice(self):
        await self.add_entry()
        result = await self.hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"}, data=INPUT)
        self.assertEqual(result["type"], "abort")
        self.assertEqual(result["reason"], "already_configured")

    async def test_wrong_password_returns_form_error(self):
        with patch("custom_components.eyedot_gateway.config_flow.validate_gateway", side_effect=PermissionError):
            result = await self.hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"}, data=INPUT)
        self.assertEqual(result["type"], "form")
        self.assertEqual(result["errors"]["base"], "invalid_auth")

    async def test_reconfigure_updates_entry_without_duplicates(self):
        entry = await self.add_entry()
        changed = {**INPUT, "host": "192.168.50.3", "uid": UID}
        with patch("custom_components.eyedot_gateway.config_flow.validate_gateway", return_value=(changed, {})):
            result = await self.hass.config_entries.flow.async_init(DOMAIN,
                       context={"source": "reconfigure", "entry_id": entry.entry_id}, data=changed)
        self.assertEqual(result["type"], "abort")
        self.assertEqual(entry.data["host"], changed["host"])
        self.assertEqual(len(self.hass.config_entries.async_entries(DOMAIN)), 1)
        await self.hass.async_block_till_done()

    async def test_reauth_updates_password_and_keeps_one_entry(self):
        entry = await self.add_entry()
        changed = {**INPUT, "uid": UID, "password": "new-test"}
        result = await self.hass.config_entries.flow.async_init(DOMAIN,
                   context={"source": "reauth", "entry_id": entry.entry_id}, data=dict(entry.data))
        self.assertEqual(result["type"], "form")
        with patch("custom_components.eyedot_gateway.config_flow.validate_gateway", return_value=(changed, {})):
            result = await self.hass.config_entries.flow.async_configure(result["flow_id"], user_input=changed)
        self.assertEqual(result["reason"], "reauth_successful")
        self.assertEqual(entry.data["password"], "new-test")
        self.assertEqual(len(self.hass.config_entries.async_entries(DOMAIN)), 1)
        await self.hass.async_block_till_done(wait_background_tasks=True)

    async def test_options_reload_refresh_interval(self):
        entry = await self.add_entry()
        old_client = entry.runtime_data.client
        result = await self.hass.config_entries.options.async_init(entry.entry_id, data={"scan_interval": 3})
        self.assertEqual(result["type"], "create_entry")
        await self.hass.async_block_till_done(wait_background_tasks=True)
        self.assertEqual(entry.options["scan_interval"], 3)
        self.assertEqual(entry.runtime_data.update_interval.total_seconds(), 3)
        self.assertTrue(old_client.closed)

    async def test_pair_button_discovers_device_and_reports_completion(self):
        entry = await self.add_entry()
        registry = entity_registry.async_get(self.hass)
        button = registry.async_get_entity_id("button", DOMAIN, UID + "_pair")
        await self.hass.services.async_call("button", "press", {"entity_id": button}, blocking=True)
        await self.hass.async_block_till_done(wait_background_tasks=True)
        self.assertEqual(entry.runtime_data.pair_status, "已完成")
        rows = entity_registry.async_entries_for_config_entry(registry, entry.entry_id)
        self.assertEqual(len([row for row in rows if row.domain == "switch"]), 6)
