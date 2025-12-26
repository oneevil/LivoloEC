from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qsl, quote, quote_plus

import aiohttp

from .const import APP_KEY, APP_SECRET


class LivoloAuthError(Exception):
    """Auth/login errors."""


class LivoloApiError(Exception):
    """API/protocol errors."""


def _http_date_gmt() -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def _b64_md5(data: bytes) -> str:
    return base64.b64encode(hashlib.md5(data).digest()).decode()


def _hmac_sha1_b64(secret: str, msg: str) -> str:
    return base64.b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha1).digest()).decode()


def _hmac_sha1_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha1).hexdigest()


def _canon_resource(url: str) -> str:
    u = urlparse(url)
    path = u.path or "/"
    q = parse_qsl(u.query, keep_blank_values=True)
    q.sort(key=lambda x: x[0])
    return path + ("?" + urlencode(q) if q else "")


def _sign_api_iot(url: str, body_bytes: bytes) -> Dict[str, str]:
    date = _http_date_gmt()
    nonce = str(uuid.uuid4())
    ts = str(int(time.time() * 1000))

    accept = "application/json; charset=utf-8"
    ctype = "application/octet-stream; charset=utf-8"
    method = "POST"
    content_md5 = _b64_md5(body_bytes)

    canon_headers = (
        f"x-ca-key:{APP_KEY}\n"
        f"x-ca-nonce:{nonce}\n"
        f"x-ca-signature-method:HmacSHA1\n"
        f"x-ca-timestamp:{ts}\n"
    )

    resource = _canon_resource(url)
    sts = f"{method}\n{accept}\n{content_md5}\n{ctype}\n{date}\n{canon_headers}{resource}"
    sig = _hmac_sha1_b64(APP_SECRET, sts)

    return {
        "date": date,
        "x-ca-signature": sig,
        "x-ca-nonce": nonce,
        "x-ca-key": APP_KEY,
        "ca_version": "1",
        "accept": accept,
        "content-md5": content_md5,
        "x-ca-timestamp": ts,
        "x-ca-signature-headers": "x-ca-nonce,x-ca-timestamp,x-ca-key,x-ca-signature-method",
        "x-ca-signature-method": "HmacSHA1",
        "user-agent": "ALIYUN-ANDROID-DEMO",
        "content-type": ctype,
    }


def _sign_loginbyoauth(login_req_json_raw: str) -> Dict[str, str]:
    """
    Важно: как в твоём bash:
      - resource в строке подписи содержит СЫРОЙ JSON (НЕ urlencoded)
      - но сам URL и form-body отправляются urlencoded/quote_plus.
    """
    date = _http_date_gmt()
    nonce = str(uuid.uuid4())
    ts = str(int(time.time() * 1000))

    accept = "application/json; charset=utf-8"
    ctype = "application/x-www-form-urlencoded; charset=utf-8"
    method = "POST"

    canon_headers = (
        f"x-ca-key:{APP_KEY}\n"
        f"x-ca-nonce:{nonce}\n"
        f"x-ca-signature-method:HmacSHA1\n"
        f"x-ca-timestamp:{ts}\n"
    )

    resource = f"/api/prd/loginbyoauth.json?loginByOauthRequest={login_req_json_raw}"
    sts = f"{method}\n{accept}\n\n{ctype}\n{date}\n{canon_headers}{resource}"
    sig = _hmac_sha1_b64(APP_SECRET, sts)

    return {
        "date": date,
        "x-ca-signature": sig,
        "x-ca-nonce": nonce,
        "x-ca-key": APP_KEY,
        "ca_version": "1",
        "accept": accept,
        "vid": f"V-{uuid.uuid4()}",
        "x-ca-timestamp": ts,
        "x-ca-signature-headers": "x-ca-nonce,x-ca-timestamp,x-ca-key,x-ca-signature-method",
        "x-ca-signature-method": "HmacSHA1",
        "user-agent": "ALIYUN-ANDROID-DEMO",
        "content-type": ctype,
    }


@dataclass
class LivoloDevice:
    element_id: str
    name: str
    product_key: str
    product_model: str
    room_name: str
    is_online: bool
    type_cn: str
    raw: Dict[str, Any]


class LivoloClient:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        email: str,
        password: str,
        country: str,
        router_mac: str,
        umid_token: str,
    ) -> None:
        self._session = session
        self._email = email
        self._password = password
        self._country = country
        self._router_mac = router_mac
        self._umid_token = umid_token

        self._region: Optional[str] = None
        self._ali_ep: Optional[str] = None
        self._iot_token: Optional[str] = None

        self._aep_client_id: str = uuid.uuid4().hex[:8]
        self._aep_device_sn: str = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        self._aep_product_key: Optional[str] = None
        self._aep_device_name: Optional[str] = None
        self._aep_device_secret: Optional[str] = None

    @property
    def iot_token(self) -> Optional[str]:
        return self._iot_token

    @property
    def aep_product_key(self) -> Optional[str]:
        return self._aep_product_key

    @property
    def aep_device_name(self) -> Optional[str]:
        return self._aep_device_name

    @property
    def aep_device_secret(self) -> Optional[str]:
        return self._aep_device_secret

    async def _post_json(self, url: str, headers: Dict[str, str], payload: Any) -> Dict[str, Any]:
        async with self._session.post(url, headers=headers, json=payload) as resp:
            text = await resp.text()
            try:
                return json.loads(text)
            except Exception as e:
                raise LivoloApiError(f"Bad JSON from {url}: {e}; body={text[:200]}") from e

    async def _post_bytes(self, url: str, headers: Dict[str, str], body_bytes: bytes) -> Dict[str, Any]:
        async with self._session.post(url, headers=headers, data=body_bytes) as resp:
            text = await resp.text()
            try:
                return json.loads(text)
            except Exception as e:
                raise LivoloApiError(f"Bad JSON from {url}: {e}; body={text[:200]}") from e

    async def ensure_login(self) -> None:
        if self._iot_token and self._aep_device_secret and self._aep_product_key and self._aep_device_name:
            return

        if self._iot_token and self._ali_ep and not (self._aep_device_secret and self._aep_product_key and self._aep_device_name):
            await self._ensure_aep_credentials()
            return

        region_body = {"email": self._email}
        region_headers = {
            "apiVer": "1.0.0",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "iot.livolo.com",
            "User-Agent": "okhttp/3.12.8",
        }
        region_json = await self._post_json("https://iot.livolo.com/user/region", region_headers, region_body)
        region = region_json.get("data")
        if not region:
            raise LivoloAuthError(f"Failed to get region: {region_json}")
        self._region = str(region)

        signin_body = {"email": self._email, "password": self._password}
        signin_headers = {
            "apiVer": "1.0.0",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "euiot.livolo.com",
            "User-Agent": "okhttp/3.12.8",
        }
        sns = await self._post_json("https://euiot.livolo.com/sns/sign_in", signin_headers, signin_body)

        code = ((sns.get("data") or {}).get("code")) if isinstance(sns, dict) else None
        ali_ep = ((sns.get("data") or {}).get("aliEndPoint")) if isinstance(sns, dict) else None

        if not code:
            raise LivoloAuthError(f"No auth code: {sns}")

        self._ali_ep = str(ali_ep or self._region)

        device_id = str(uuid.uuid4())
        login_req_obj = {
            "country": self._country,
            "authCode": code,
            "oauthPlateform": 23,
            "oauthAppKey": APP_KEY,
            "riskControlInfo": {
                "appVersion": "223",
                "USE_OA_PWD_ENCRYPT": "true",
                "utdid": "ffffffffffffffffffffffff",
                "netType": "wifi",
                "umidToken": self._umid_token,
                "locale": "en-US",
                "appVersionName": "5.4.16",
                "deviceId": device_id,
                "routerMac": self._router_mac,
                "platformVersion": "36",
                "appAuthToken": "L1sBjBhLPEBBngKbRsqqhESPgkz3UzJn",
                "appID": "com.livolo.livoloapp",
                "signType": "RSA",
                "sdkVersion": "3.4.2",
                "model": "sdk_gphone64_arm64",
                "USE_H5_NC": "true",
                "platformName": "android",
                "brand": "google",
                "yunOSId": "",
            },
        }
        login_req_json_raw = json.dumps(login_req_obj, separators=(",", ":"), ensure_ascii=False)

        login_headers = _sign_loginbyoauth(login_req_json_raw)
        host_login = f"living-account.{self._ali_ep}.aliyuncs.com"
        login_headers["host"] = host_login

        form_body = "loginByOauthRequest=" + quote_plus(login_req_json_raw)

        login_url = (
            f"https://{host_login}/api/prd/loginbyoauth.json"
            f"?loginByOauthRequest={quote(login_req_json_raw, safe='')}"
        )

        async with self._session.post(
            login_url,
            headers={k: v for k, v in login_headers.items() if k.lower() != "content-type"}
            | {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            data=form_body.encode("utf-8"),
        ) as resp:
            login_text = await resp.text()
            try:
                login_json = json.loads(login_text)
            except Exception as e:
                raise LivoloAuthError(f"Bad login JSON: {e}; body={login_text[:200]}") from e

        sid = (
            (((login_json.get("data") or {}).get("data") or {}).get("loginSuccessResult") or {}).get("sid")
            if isinstance(login_json, dict)
            else None
        )
        if not sid:
            raise LivoloAuthError(f"No sid in loginbyoauth: {login_json}")

        req_id = str(uuid.uuid4())
        cs_url = (
            f"https://{self._ali_ep}.api-iot.aliyuncs.com/account/createSessionByAuthCode"
            f"?x-ca-request-id={req_id}"
        )
        cs_payload = {
            "id": req_id,
            "params": {"request": {"authCode": sid, "accountType": "OA_SESSION", "appKey": APP_KEY}},
            "request": {"apiVer": "1.0.4", "language": "en-US"},
            "version": "1.0",
        }
        cs_bytes = json.dumps(cs_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        cs_headers = _sign_api_iot(cs_url, cs_bytes)
        cs_headers["host"] = f"{self._ali_ep}.api-iot.aliyuncs.com"

        cs_json = await self._post_bytes(cs_url, cs_headers, cs_bytes)

        iot_token = None
        if isinstance(cs_json, dict):

            def walk(x: Any) -> None:
                nonlocal iot_token
                if iot_token:
                    return
                if isinstance(x, dict):
                    v = x.get("iotToken")
                    if isinstance(v, str) and v:
                        iot_token = v
                        return
                    for vv in x.values():
                        walk(vv)
                elif isinstance(x, list):
                    for vv in x:
                        walk(vv)

            walk(cs_json)

        if not iot_token:
            raise LivoloAuthError(f"No iotToken in createSessionByAuthCode: {cs_json}")

        self._iot_token = iot_token

        await self._ensure_aep_credentials()

    async def _ensure_aep_credentials(self) -> None:
        if self._aep_device_secret and self._aep_product_key and self._aep_device_name:
            return

        if not self._ali_ep:
            raise LivoloAuthError("AEP auth requested before ali_ep is set")

        req_id = str(uuid.uuid4())
        ts = str(int(time.time() * 1000))

        sign_content = (
            f"appKey{APP_KEY}"
            f"clientId{self._aep_client_id}"
            f"deviceSn{self._aep_device_sn}"
            f"timestamp{ts}"
        )
        sign = _hmac_sha1_hex(APP_SECRET, sign_content)

        payload = {
            "id": req_id,
            "params": {
                "authInfo": {
                    "clientId": self._aep_client_id,
                    "sign": sign,
                    "deviceSn": self._aep_device_sn,
                    "timestamp": ts,
                }
            },
            "request": {"apiVer": "1.0.0", "language": "en-US"},
            "version": "1.0",
        }

        url = (
            f"https://{self._ali_ep}.api-iot.aliyuncs.com/app/aepauth/handle"
            f"?x-ca-request-id={req_id}"
        )

        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = _sign_api_iot(url, body)
        headers["host"] = f"{self._ali_ep}.api-iot.aliyuncs.com"

        resp = await self._post_bytes(url, headers, body)
        if not isinstance(resp, dict) or resp.get("code") != 200:
            raise LivoloAuthError(f"AEP auth failed: {resp}")

        data = resp.get("data") or {}
        self._aep_device_secret = data.get("deviceSecret")
        self._aep_product_key = data.get("productKey")
        self._aep_device_name = data.get("deviceName")

        _LOGGER = logging.getLogger(__name__)

        _LOGGER.debug(
            "AEP credentials received: productKey=%s deviceName=%s deviceSecret=%s",
            self._aep_product_key,
            self._aep_device_name,
            self._aep_device_secret,
        )

        if not (self._aep_device_secret and self._aep_product_key and self._aep_device_name):
            raise LivoloAuthError(f"AEP auth incomplete: {data}")

    async def list_devices(self) -> List[LivoloDevice]:
        await self.ensure_login()
        assert self._ali_ep and self._iot_token

        req_id = str(uuid.uuid4())
        hq_url = f"https://{self._ali_ep}.api-iot.aliyuncs.com/living/home/query?x-ca-request-id={req_id}"
        hq_payload = {
            "id": req_id,
            "params": {"pageSize": 20, "pageNo": 1},
            "request": {"apiVer": "1.1.0", "language": "en-US", "iotToken": self._iot_token},
            "version": "1.0",
        }
        hq_bytes = json.dumps(hq_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        hq_headers = _sign_api_iot(hq_url, hq_bytes)
        hq_headers["host"] = f"{self._ali_ep}.api-iot.aliyuncs.com"
        hq_json = await self._post_bytes(hq_url, hq_headers, hq_bytes)

        homes = []
        try:
            homes = (hq_json.get("data") or {}).get("data") or []
        except Exception:
            homes = []
        home_ids = [h.get("homeId") for h in homes if isinstance(h, dict) and h.get("homeId")]

        devices: List[LivoloDevice] = []
        page_size = 20

        for hid in home_ids:
            page = 1
            total_pages: Optional[int] = None

            while total_pages is None or page <= total_pages:
                req_id = str(uuid.uuid4())
                eq_url = (
                    f"https://{self._ali_ep}.api-iot.aliyuncs.com/living/home/element/query"
                    f"?x-ca-request-id={req_id}"
                )
                eq_payload = {
                    "id": req_id,
                    "params": {"pageSize": page_size, "pageNo": page, "homeId": str(hid)},
                    "request": {"apiVer": "1.0.8", "language": "en-US", "iotToken": self._iot_token},
                    "version": "1.0",
                }
                eq_bytes = json.dumps(eq_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                eq_headers = _sign_api_iot(eq_url, eq_bytes)
                eq_headers["host"] = f"{self._ali_ep}.api-iot.aliyuncs.com"
                eq_json = await self._post_bytes(eq_url, eq_headers, eq_bytes)

                code = eq_json.get("code") if isinstance(eq_json, dict) else None
                if code and code != 200:
                    msg = eq_json.get("message") or eq_json.get("localizedMsg") or "-"
                    raise LivoloApiError(f"element/query failed code={code} msg={msg}")

                data = (eq_json.get("data") or {}) if isinstance(eq_json, dict) else {}
                total = int(data.get("total") or 0)
                if total_pages is None:
                    total_pages = max(1, (total + page_size - 1) // page_size)

                items = data.get("items") or []
                for it in items:
                    if not isinstance(it, dict):
                        continue

                    type_cn = str(
                        it.get("deviceTypeName")
                        or it.get("typeName")
                        or it.get("categoryName")
                        or it.get("productName")
                        or it.get("productModel")
                        or ""
                    )

                    devices.append(
                        LivoloDevice(
                            element_id=str(it.get("elementId") or ""),
                            name=str(it.get("nickName") or it.get("productName") or "-"),
                            product_key=str(it.get("productKey") or "-"),
                            product_model=str(it.get("productModel") or "-"),
                            room_name=str(it.get("roomName") or "-"),
                            is_online=bool(it.get("isMqttOnline")),
                            type_cn=type_cn,
                            raw=it,
                        )
                    )

                page += 1

        return [d for d in devices if d.element_id]
