"""通过 HA 配置界面发现网关、验证凭据并保存连接参数。"""

import ipaddress

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector

from .client import validate_gateway
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN


def connection_schema(defaults=None):
    defaults = defaults or {}
    return vol.Schema({
        vol.Required("host", default=defaults.get("host", "")): str,
        vol.Required("username", default=defaults.get("username", "admin")): str,
        vol.Required("password"): selector.TextSelector(selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)),
        vol.Optional("uid", default=defaults.get("uid", "")): str,
    })


class EyedotConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def _validate(self, user_input):
        data = dict(user_input)
        data["host"] = data["host"].strip()
        data["username"] = data["username"].strip()
        data["uid"] = data.get("uid", "").strip()
        address = ipaddress.IPv4Address(data["host"])
        if not address.is_private or address.is_multicast or address.is_unspecified:
            raise ValueError("仅接受明确的局域网 IPv4")
        if any(not value or len(value.encode()) > 12 for value in (data["username"], data["password"])):
            raise ValueError("账号密码须为 1 至 12 个 UTF-8 字节")
        return await self.hass.async_add_executor_job(validate_gateway, data)

    async def _connection_step(self, step, user_input, defaults=None):
        errors = {}
        if user_input is not None:
            try:
                data, _ = await self._validate(user_input)
            except PermissionError:
                errors["base"] = "invalid_auth"
            except ValueError:
                errors["base"] = "invalid_config"
            except (OSError, TimeoutError):
                errors["base"] = "cannot_connect"
            except RuntimeError:
                errors["base"] = "unsupported_gateway"
            else:
                await self.async_set_unique_id(data["uid"])
                if step == "reconfigure":
                    self._abort_if_unique_id_mismatch()
                    return self.async_update_reload_and_abort(self._get_reconfigure_entry(), data_updates=data,
                                                               reason="reconfigure_successful")
                if step == "reauth_confirm":
                    self._abort_if_unique_id_mismatch()
                    return self.async_update_reload_and_abort(self._get_reauth_entry(), data_updates=data)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=f"Eyedot Zigbee 网关 {data['uid'][-4:]}", data=data)
        return self.async_show_form(step_id=step, data_schema=connection_schema(defaults), errors=errors)

    async def async_step_user(self, user_input=None):
        return await self._connection_step("user", user_input)

    async def async_step_reconfigure(self, user_input=None):
        return await self._connection_step("reconfigure", user_input, self._get_reconfigure_entry().data)

    async def async_step_reauth(self, entry_data):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        return await self._connection_step("reauth_confirm", user_input, self._get_reauth_entry().data)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return EyedotOptionsFlow()


class EyedotOptionsFlow(config_entries.OptionsFlowWithReload):
    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(step_id="init", data_schema=vol.Schema({
            vol.Required("scan_interval", default=self.config_entry.options.get("scan_interval", DEFAULT_SCAN_INTERVAL)):
                vol.All(vol.Coerce(int), vol.Range(min=2, max=8)),
        }))
