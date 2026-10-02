"""统一读取网关状态，控制结果得到确认后再更新所有实体。"""

import asyncio
import logging
import time
from datetime import timedelta
from dataclasses import replace

from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.core import callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers import device_registry

from .client import GatewayClient
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .discovery import async_discovery_targets

LOGGER = logging.getLogger(__name__)


class EyedotCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, entry):
        super().__init__(hass, LOGGER, name=DOMAIN, config_entry=entry,
                         update_interval=timedelta(seconds=entry.options.get("scan_interval", DEFAULT_SCAN_INTERVAL)),
                         always_update=False)
        self.entry = entry
        self.client = GatewayClient(entry.data["host"], entry.data["username"], entry.data["password"], entry.data["uid"])
        self.pair_task = None
        self.pair_status = "未开始"
        self.pair_error = None
        self._closing = False
        self._push_pending = False
        self._push_task = None
        self._operation_lock = asyncio.Lock()
        self.last_push_refresh_seconds = None
        self._push_updates = {}
        self._push_received_at = None

    async def _async_update_data(self):
        if self.pair_task and not self.pair_task.done():
            return self.data or {}
        try:
            async with self._operation_lock:
                self.client.discovery_targets = await async_discovery_targets(self.hass)
                data = await self.hass.async_add_executor_job(self.client.fetch)
                self._async_sync_host()
                return data
        except PermissionError as error:
            raise ConfigEntryAuthFailed("网关登录失效，请重新认证") from error
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            raise UpdateFailed(f"网关读取失败：{error}") from error

    @callback
    def _async_sync_host(self):
        host = self.client.host
        if self.entry.data["host"] == host:
            return
        # 只在完整 UID 的新地址完成业务认证后保存；保持配置项和所有子设备标识不变。
        self.hass.config_entries.async_update_entry(self.entry, data={**self.entry.data, "host": host})
        registry = device_registry.async_get(self.hass)
        gateway_id = getattr(self, "gateway_device_id", None)
        if gateway_id:
            registry.async_update_device(gateway_id, configuration_url=f"http://{host}")
        LOGGER.info("已更新网关地址及访问链接，保留原设备和自动化关联")

    async def async_control(self, index, channel, on):
        if self.pair_task and not self.pair_task.done():
            raise HomeAssistantError("网关正在配对，请等待完成后控制")
        try:
            async with self._operation_lock:
                data = await self.hass.async_add_executor_job(self.client.control, index, channel, on)
                self._async_sync_host()
                self.async_set_updated_data(data)
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            await self.async_request_refresh()
            raise HomeAssistantError(f"没有确认开关状态：{error}") from error

    async def async_start_events(self):
        def notify(updates=None, needs_refresh=True, received_at=None):
            if not self.hass.loop.is_closed():
                self.hass.loop.call_soon_threadsafe(self._queue_push_refresh, updates or {}, needs_refresh, received_at)

        await self.hass.async_add_executor_job(self.client.start_events, notify)

    @callback
    def _queue_push_refresh(self, updates=None, needs_refresh=True, received_at=None):
        if self._closing:
            return
        self._push_pending = self._push_pending or needs_refresh
        self._push_updates.update(updates or {})
        self._push_received_at = received_at or self.client.last_event_received_at
        if self._push_task is None or self._push_task.done():
            self._push_task = self.hass.async_create_background_task(self._async_push_refresh(), "Eyedot 实时状态刷新")

    async def _async_push_refresh(self):
        try:
            # 完整状态推送直接写入；只有需要读取目录时合并 30 毫秒，避免额外请求。
            if not self._push_updates:
                await asyncio.sleep(0.03)
            while (self._push_pending or self._push_updates) and not self._closing:
                updates = self._push_updates
                self._push_updates = {}
                needs_refresh = self._push_pending
                self._push_pending = False
                received_at = self._push_received_at
                async with self._operation_lock:
                    data = dict(self.data or {})
                    for index, (device_type, state) in updates.items():
                        current = data.get(index)
                        if current is None or current.device_type != device_type or device_type != 13:
                            needs_refresh = True
                            continue
                        data[index] = replace(current, state=state)
                    if updates:
                        self.async_set_updated_data(data)
                if needs_refresh and not (self.pair_task and not self.pair_task.done()):
                    await self.async_refresh()
                if received_at is not None and self.last_update_success:
                    self.last_push_refresh_seconds = max(0, time.monotonic() - received_at)
        finally:
            self._push_task = None

    async def async_pair(self):
        if self.pair_task and not self.pair_task.done():
            raise HomeAssistantError("配对已经进行中")

        async def run_pairing():
            try:
                data = await self.hass.async_add_executor_job(self.client.pair)
                self._async_sync_host()
                self.async_set_updated_data(data)
                self.pair_status = "已完成"
            except asyncio.CancelledError:
                self.client.cancel_pairing.set()
                self.pair_status = "已取消"
                raise
            except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                self.pair_status = "未完成"
                self.pair_error = str(error)
                LOGGER.warning("配对未完成：%s", error)
            finally:
                self.pair_task = None
                self.async_update_listeners()

        self.pair_status = "配对中"
        self.pair_error = None
        self.pair_task = self.hass.async_create_background_task(run_pairing(), "Eyedot Zigbee 网关配对")
        self.async_update_listeners()

    async def async_close(self):
        self._closing = True
        self.client.cancel_pairing.set()
        tasks = []
        if self._push_task and not self._push_task.done():
            self._push_task.cancel()
            tasks.append(self._push_task)
        if self.pair_task and not self.pair_task.done():
            self.pair_task.cancel()
            tasks.append(self.pair_task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.hass.async_add_executor_job(self.client.close)
