"""统一读取网关状态，控制结果得到确认后再更新所有实体。"""

import asyncio
import logging
from datetime import timedelta

from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import GatewayClient
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

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

    async def _async_update_data(self):
        if self.pair_task and not self.pair_task.done():
            return self.data or {}
        try:
            return await self.hass.async_add_executor_job(self.client.fetch)
        except PermissionError as error:
            raise ConfigEntryAuthFailed("网关登录失效，请重新认证") from error
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            raise UpdateFailed(f"网关读取失败：{error}") from error

    async def async_control(self, index, channel, on):
        if self.pair_task and not self.pair_task.done():
            raise HomeAssistantError("网关正在配对，请等待完成后控制")
        try:
            data = await self.hass.async_add_executor_job(self.client.control, index, channel, on)
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            await self.async_request_refresh()
            raise HomeAssistantError(f"没有确认开关状态：{error}") from error
        self.async_set_updated_data(data)

    async def async_pair(self):
        if self.pair_task and not self.pair_task.done():
            raise HomeAssistantError("配对已经进行中")

        async def run_pairing():
            try:
                data = await self.hass.async_add_executor_job(self.client.pair)
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
        self.client.cancel_pairing.set()
        if self.pair_task and not self.pair_task.done():
            self.pair_task.cancel()
            await asyncio.gather(self.pair_task, return_exceptions=True)
        await self.hass.async_add_executor_job(self.client.close)
