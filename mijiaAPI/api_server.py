import base64
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import struct
import threading
import time
import uuid
from collections import OrderedDict, deque
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib import parse

import anyio.to_thread
import requests
import uvicorn
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from PIL import Image
from pydantic import BaseModel
from qrcode import QRCode
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .apis import get_default_auth_path, mijiaAPI
from .devices import DeviceInfoCacheBackend, get_device_info, mijiaDevice
from .errors import APIError, DeviceActionError, DeviceGetError, DeviceSetError, LoginError
from .logger import logger


class LoginStartResponse(BaseModel):
    session_id: str
    status: str
    qr_url: str
    login_url: str
    expires_at: int


class DevicePropertyPayload(BaseModel):
    did: str
    prop_name: str
    siid: Optional[int] = None
    piid: Optional[int] = None
    value: Any = None


class DeviceActionPayload(BaseModel):
    did: str
    action_name: str
    arguments: tuple[Any, ...] = ()


class SceneRunPayload(BaseModel):
    scene_id: str


class VaultPasswordPayload(BaseModel):
    password: str


class LoginClaimPayload(BaseModel):
    session_id: str
    claim_secret: str


class ChangeVaultPasswordPayload(BaseModel):
    old_password: str
    new_password: str


class RetryConfig(BaseModel):
    request_timeout: float = 10.0
    login_timeout: float = 180.0
    max_retries: int = 2
    retry_delay: float = 0.5


@dataclass(frozen=True)
class ServerConfig:
    state_dir: Path
    request_timeout: float = 10.0
    login_timeout: float = 180.0
    max_retries: int = 2
    retry_delay: float = 0.5
    login_task_ttl: int = 300
    max_concurrent_requests: int = 1000
    acquire_timeout: float = 5.0
    keepalive_timeout: int = 20
    workers: int = 1
    allowed_hosts: tuple[str, ...] = ("*",)
    local_token_ttl_seconds: int = 30 * 24 * 3600
    max_active_login_tasks: int = 8
    allow_remote_login: bool = True
    trust_proxy_headers: bool = False
    trusted_proxy_hosts: tuple[str, ...] = ("127.0.0.1", "::1")
    trusted_client_ip_header: str = "x-client-ip"
    thread_pool_tokens: int = 128


SESSION_READ_CACHE_TTL_SECONDS = 3.0
SESSION_DEVICE_DETAIL_CACHE_TTL_SECONDS = 2.0
SESSION_META_TOUCH_INTERVAL_SECONDS = 15.0
SYNC_SNAPSHOT_REUSE_SECONDS = 2.0
SYNC_EVENT_HISTORY_LIMIT = 64
PROPERTY_CONFIRM_TIMEOUT_SECONDS = 4.0
PROPERTY_CONFIRM_INTERVAL_SECONDS = 0.25


def _env_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv_tuple(value: str) -> tuple[str, ...]:
    items = tuple(item.strip() for item in value.split(",") if item.strip())
    return items or ("*",)


def _parse_forwarded_for(value: str) -> Optional[str]:
    for part in value.split(","):
        for segment in part.split(";"):
            token = segment.strip()
            if not token.lower().startswith("for="):
                continue
            candidate = token[4:].strip().strip('"')
            if not candidate:
                continue
            if candidate.startswith("[") and "]" in candidate:
                return candidate[1:candidate.index("]")]
            return candidate
    return None


def _validate_single_ip(value: str) -> Optional[str]:
    candidate = value.strip()
    if not candidate or "," in candidate:
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(address)


def _is_trusted_proxy_host(host: str, trusted_proxy_hosts: tuple[str, ...]) -> bool:
    if "*" in trusted_proxy_hosts or host in trusted_proxy_hosts:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback


def _get_request_identity(request: Request, config: ServerConfig) -> str:
    host = request.client.host if request.client else "unknown"
    if not config.trust_proxy_headers:
        return host
    if not _is_trusted_proxy_host(host, config.trusted_proxy_hosts):
        return host
    trusted_header = config.trusted_client_ip_header.strip().lower()
    if trusted_header:
        trusted_ip = _validate_single_ip(request.headers.get(trusted_header, ""))
        if trusted_ip is not None:
            return trusted_ip
    return host


def _validate_server_config(config: ServerConfig) -> None:
    if config.workers != 1:
        raise RuntimeError("当前零知识会话模型仅支持单 worker 运行，请将 workers 设置为 1")
    if config.max_active_login_tasks < 1:
        raise RuntimeError("MIJIA_MAX_ACTIVE_LOGIN_TASKS 必须大于等于 1")


@contextmanager
def _timed_session_lock(session: "ManagedSession", operation: str):
    session.lock.acquire()
    try:
        yield
    finally:
        session.lock.release()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


class RateLimiter:
    def __init__(self, *, max_buckets: int, bucket_ttl_seconds: int):
        self.lock = threading.RLock()
        self.max_buckets = max(1, max_buckets)
        self.bucket_ttl_seconds = max(60, bucket_ttl_seconds)
        self.buckets: OrderedDict[str, list[float]] = OrderedDict()
        self._last_cleanup_at = 0.0

    def _cleanup(self, now: float) -> None:
        if now - self._last_cleanup_at < 30:
            return
        stale_before = now - self.bucket_ttl_seconds
        keys_to_remove = []
        for key, timestamps in self.buckets.items():
            active = [value for value in timestamps if value >= stale_before]
            if active:
                self.buckets[key] = active
            else:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            self.buckets.pop(key, None)
        self._last_cleanup_at = now

    def allow(self, key: str, *, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            self._cleanup(now)
            timestamps = self.buckets.get(key, [])
            timestamps = [value for value in timestamps if now - value < window_seconds]
            if len(timestamps) >= limit:
                retry_after = max(1, int(window_seconds - (now - timestamps[0])))
                self.buckets[key] = timestamps
                self.buckets.move_to_end(key)
                return False, retry_after
            if key not in self.buckets and len(self.buckets) >= self.max_buckets:
                self.buckets.popitem(last=False)
            timestamps.append(now)
            self.buckets[key] = timestamps
            self.buckets.move_to_end(key)
            return True, 0


VAULT_VERSION = 1
VAULT_PBKDF2_ITERATIONS = 300_000
MIN_VAULT_PASSWORD_LENGTH = 8
DEVICE_SPEC_CACHE_VERSION = 1
LOGIN_SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def _derive_vault_key(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def _validate_vault_password(password: str) -> None:
    if len(password) < MIN_VAULT_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"保险箱密码长度不能少于 {MIN_VAULT_PASSWORD_LENGTH} 位",
        )


def _public_error_payload(error: str, code: str) -> dict[str, str]:
    return {"error": error, "code": code}


def _path_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def _cleanup_legacy_login_task_artifacts(state_dir: Path) -> None:
    login_tasks_dir = state_dir / "login-tasks"
    sessions_dir = state_dir / "sessions"
    if not login_tasks_dir.exists():
        return

    for task_dir in login_tasks_dir.iterdir():
        try:
            task_state_path = task_dir / "task.json" if task_dir.is_dir() else None
            if task_state_path is not None and task_state_path.exists():
                payload = json.loads(task_state_path.read_text(encoding="utf-8"))
                leaked_token = payload.get("token")
                if leaked_token:
                    token_hash = hashlib.sha256(leaked_token.encode("utf-8")).hexdigest()
                    session_dir = sessions_dir / token_hash
                    meta_path = session_dir / "meta.json"
                    if meta_path.exists():
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                        meta["token_revoked_at"] = int(time.time())
                        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                    if session_dir.exists():
                        shutil.rmtree(session_dir, ignore_errors=True)
            if task_dir.is_dir():
                shutil.rmtree(task_dir, ignore_errors=True)
            else:
                task_dir.unlink(missing_ok=True)
        except Exception:
            logger.exception("清理历史 login-task 工件失败: %s", task_dir)


def _enforce_workspace_sensitive_artifacts(state_dir: Path) -> None:
    workspace = Path.cwd().resolve()
    resolved_state_dir = state_dir.resolve(strict=False)
    if _path_within(workspace, resolved_state_dir):
        raise RuntimeError(
            f"出于安全原因，状态目录不能位于当前工作区内: {resolved_state_dir}。"
            "请将 MIJIA_STATE_DIR 配置到仓库外目录后再启动。"
        )

    suspicious_paths = [
        workspace / ".mijia-server",
        workspace / ".mijia-api-data",
        workspace / ".mijia-api-legacy",
    ]
    for artifact in suspicious_paths:
        if artifact.exists():
            logger.warning("检测到工作区内敏感状态工件，请确认已加入忽略规则并避免外传: %s", artifact)

    for pattern in ("*_decrypted.har", "*_simplified.json"):
        for artifact in workspace.glob(pattern):
            logger.warning("检测到工作区内敏感导出工件，请及时清理或迁移到临时目录: %s", artifact.resolve())


def _is_sensitive_device_model(device_model: str) -> bool:
    normalized_model = (device_model or "").lower()
    return "cateye" in normalized_model or "lock" in normalized_model or "camera" in normalized_model


def _filter_sensitive_devices(session: "ManagedSession", devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    filtered_devices: list[dict[str, Any]] = []
    purged_models: set[str] = set()
    for item in devices:
        model = item.get("model", "")
        if _is_sensitive_device_model(model):
            if model and model not in purged_models:
                session.device_spec_cache.delete(model)
                purged_models.add(model)
            continue
        filtered_devices.append(item)
    return filtered_devices


class DeviceSpecLRUCache:
    def __init__(self, max_entries: int):
        self.max_entries = max(1, max_entries)
        self.lock = threading.RLock()
        self.entries: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def get(self, key: str) -> Optional[dict[str, Any]]:
        with self.lock:
            value = self.entries.pop(key, None)
            if value is None:
                return None
            self.entries[key] = value
            return value

    def set(self, key: str, value: dict[str, Any]) -> None:
        with self.lock:
            self.entries.pop(key, None)
            self.entries[key] = value
            while len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)

    def clear_prefix(self, prefix: str) -> None:
        with self.lock:
            keys_to_remove = [key for key in self.entries if key.startswith(prefix)]
            for key in keys_to_remove:
                self.entries.pop(key, None)

    def clear_key(self, key: str) -> None:
        with self.lock:
            self.entries.pop(key, None)


class EncryptedDeviceSpecCache(DeviceInfoCacheBackend):
    def __init__(
        self,
        *,
        token_hash: str,
        cache_dir: Path,
        key_provider,
        hot_cache: DeviceSpecLRUCache,
    ):
        self.token_hash = token_hash
        self.cache_dir = cache_dir
        self.key_provider = key_provider
        self.hot_cache = hot_cache

    def _model_hash(self, device_model: str) -> str:
        return hashlib.sha256(device_model.encode("utf-8")).hexdigest()

    def _hot_key(self, device_model: str) -> str:
        return f"{self.token_hash}:{self._model_hash(device_model)}"

    def _cache_file(self, device_model: str) -> Path:
        return self.cache_dir / f"{self._model_hash(device_model)}.bin"

    def _get_key(self) -> bytes:
        key = self.key_provider()
        if key is None:
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="当前会话已锁定，请先解锁")
        return key

    def _encrypt(self, device_model: str, device_info: dict[str, Any], key: bytes) -> bytes:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = json.dumps(
            {
                "device_model": device_model,
                "device_info": device_info,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return json.dumps(
            {
                "version": DEVICE_SPEC_CACHE_VERSION,
                "nonce": _b64encode(nonce),
                "tag": _b64encode(tag),
                "ciphertext": _b64encode(ciphertext),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def _decrypt(self, device_model: str, raw: bytes, key: bytes) -> Optional[dict[str, Any]]:
        try:
            payload = json.loads(raw.decode("utf-8"))
            if payload.get("version") != DEVICE_SPEC_CACHE_VERSION:
                return None
            cipher = AES.new(key, AES.MODE_GCM, nonce=_b64decode(payload["nonce"]))
            plaintext = cipher.decrypt_and_verify(_b64decode(payload["ciphertext"]), _b64decode(payload["tag"]))
            parsed = json.loads(plaintext.decode("utf-8"))
            if parsed.get("device_model") != device_model:
                return None
            return parsed["device_info"]
        except (KeyError, ValueError, json.JSONDecodeError):
            return None

    def get(self, device_model: str) -> Optional[dict[str, Any]]:
        hot_key = self._hot_key(device_model)
        cached = self.hot_cache.get(hot_key)
        if cached is not None:
            return cached
        cache_file = self._cache_file(device_model)
        if not cache_file.exists():
            return None
        cache_data = self._decrypt(device_model, cache_file.read_bytes(), self._get_key())
        if cache_data is None:
            cache_file.unlink(missing_ok=True)
            return None
        self.hot_cache.set(hot_key, cache_data)
        return cache_data

    def set(self, device_model: str, device_info: dict[str, Any]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file(device_model).write_bytes(self._encrypt(device_model, device_info, self._get_key()))
        self.hot_cache.set(self._hot_key(device_model), device_info)

    def clear_hot_cache(self) -> None:
        self.hot_cache.clear_prefix(f"{self.token_hash}:")

    def delete(self, device_model: str) -> None:
        self.hot_cache.clear_key(self._hot_key(device_model))
        self._cache_file(device_model).unlink(missing_ok=True)


class ManagedSession:
    def __init__(
        self,
        token_hash: str,
        session_dir: Path,
        retry_config: RetryConfig,
        device_spec_hot_cache: DeviceSpecLRUCache,
    ):
        self.token_hash = token_hash
        self.session_dir = session_dir
        self.retry_config = retry_config
        self.lock = threading.RLock()
        self._meta_lock = threading.RLock()
        self._runtime_cache_lock = threading.RLock()
        self._sync_lock = threading.RLock()
        self._touch_lock = threading.RLock()
        self._api: Optional[mijiaAPI] = None
        self._auth_data: Optional[dict[str, Any]] = None
        self._vault_key: Optional[bytes] = None
        self._vault_salt: Optional[bytes] = None
        self._vault_iterations: int = VAULT_PBKDF2_ITERATIONS
        self._last_touch_monotonic = 0.0
        self._meta_cache: Optional[dict[str, Any]] = None
        self._runtime_cache: dict[str, tuple[float, Any]] = {}
        self._sync_revision = 0
        self._sync_state: Optional[dict[str, Any]] = None
        self._sync_last_event: Optional[dict[str, Any]] = None
        self._sync_events: deque[dict[str, Any]] = deque(
            maxlen=SYNC_EVENT_HISTORY_LIMIT
        )
        self._sync_snapshot: Optional[dict[str, Any]] = None
        self._sync_snapshot_monotonic = 0.0
        self._device_spec_cache = EncryptedDeviceSpecCache(
            token_hash=token_hash,
            cache_dir=self.cache_path,
            key_provider=lambda: self._vault_key,
            hot_cache=device_spec_hot_cache,
        )

    @property
    def vault_path(self) -> Path:
        return self.session_dir / "vault.bin"

    @property
    def cache_path(self) -> Path:
        return self.session_dir / "device-cache"

    @property
    def meta_path(self) -> Path:
        return self.session_dir / "meta.json"

    @property
    def device_spec_cache(self) -> EncryptedDeviceSpecCache:
        return self._device_spec_cache

    @property
    def is_unlocked(self) -> bool:
        return self._api is not None and self._vault_key is not None and self.vault_path.exists()

    @property
    def has_pending_auth_data(self) -> bool:
        return self._auth_data is not None and not self.vault_path.exists()

    def _build_api(self, auth_data: dict[str, Any]) -> mijiaAPI:
        api = mijiaAPI(
            auth_data_path=str(self.session_dir / "__unused_auth.json"),
            auth_data=auth_data,
            auth_data_save_hook=self._save_auth_data_hook,
            allow_plaintext_persistence=False,
            request_timeout=self.retry_config.request_timeout,
            login_timeout=self.retry_config.login_timeout,
            max_retries=self.retry_config.max_retries,
            retry_delay=self.retry_config.retry_delay,
        )
        api.device_spec_cache = self.device_spec_cache
        return api

    def _encrypt_auth_data(
        self,
        auth_data: dict[str, Any],
        key: bytes,
        *,
        salt: bytes,
        iterations: int,
    ) -> bytes:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(
            json.dumps(auth_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        payload = {
            "version": VAULT_VERSION,
            "kdf": "pbkdf2-sha256",
            "iterations": iterations,
            "salt": _b64encode(salt),
            "nonce": _b64encode(nonce),
            "tag": _b64encode(tag),
            "ciphertext": _b64encode(ciphertext),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _write_vault(self, auth_data: dict[str, Any], key: bytes, *, salt: bytes, iterations: int) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_bytes(self._encrypt_auth_data(auth_data, key, salt=salt, iterations=iterations))

    def _load_vault_payload(self) -> dict[str, Any]:
        if not self.vault_path.exists():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="当前会话未设置保险箱密码")
        return json.loads(self.vault_path.read_text(encoding="utf-8"))

    def _decrypt_vault(self, password: str) -> tuple[dict[str, Any], bytes, bytes, int]:
        payload = self._load_vault_payload()
        if payload.get("version") != VAULT_VERSION:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="保险箱版本不受支持")
        salt = _b64decode(payload["salt"])
        iterations = int(payload.get("iterations", VAULT_PBKDF2_ITERATIONS))
        key = _derive_vault_key(password, salt, iterations)
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=_b64decode(payload["nonce"]))
            plaintext = cipher.decrypt_and_verify(_b64decode(payload["ciphertext"]), _b64decode(payload["tag"]))
        except (KeyError, ValueError):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="保险箱密码错误")
        return json.loads(plaintext.decode("utf-8")), key, salt, iterations

    def _save_auth_data_hook(self, auth_data: dict[str, Any]) -> None:
        self._auth_data = dict(auth_data)
        if self._vault_key is not None and self._vault_salt is not None and self.vault_path.exists():
            self._write_vault(
                self._auth_data,
                self._vault_key,
                salt=self._vault_salt,
                iterations=self._vault_iterations,
            )
            meta = self.read_meta()
            meta["vault_updated_at"] = int(time.time())
            self.write_meta(meta)

    def load_api(self) -> mijiaAPI:
        if not self.vault_path.exists():
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="当前会话尚未设置保险箱密码")
        if self._api is None:
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="当前会话已锁定，请先解锁")
        return self._api

    def _get_runtime_cache(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        with self._runtime_cache_lock:
            cached = self._runtime_cache.get(key)
            if cached is None:
                return None
            expires_at, value = cached
            if now >= expires_at:
                self._runtime_cache.pop(key, None)
                return None
            return value

    def _set_runtime_cache(self, key: str, value: Any, ttl_seconds: float = SESSION_READ_CACHE_TTL_SECONDS) -> Any:
        with self._runtime_cache_lock:
            self._runtime_cache[key] = (time.monotonic() + ttl_seconds, value)
        return value

    def invalidate_runtime_cache(self, *keys: str) -> None:
        with self._runtime_cache_lock:
            if not keys:
                self._runtime_cache.clear()
                return
            for key in keys:
                self._runtime_cache.pop(key, None)

    def get_cached_homes_list(self, api: mijiaAPI) -> list[dict[str, Any]]:
        cached = self._get_runtime_cache("homes_list")
        if cached is not None:
            return cached
        return self._set_runtime_cache("homes_list", api.get_homes_list())

    def get_cached_home_name_map(self, api: mijiaAPI) -> dict[str, str]:
        cached = self._get_runtime_cache("homes_map")
        if cached is not None:
            return cached
        homes = self.get_cached_homes_list(api)
        homes_map = {home["id"]: home["name"] for home in homes}
        return self._set_runtime_cache("homes_map", homes_map)

    def get_cached_devices_list(self, api: mijiaAPI) -> list[dict[str, Any]]:
        cached = self._get_runtime_cache("devices_list")
        if cached is not None:
            return cached
        devices = _filter_sensitive_devices(session=self, devices=api.get_devices_list() + api.get_shared_devices_list())
        return self._set_runtime_cache("devices_list", devices)

    def get_cached_scenes_list(self, api: mijiaAPI) -> list[dict[str, Any]]:
        cached = self._get_runtime_cache("scenes_list")
        if cached is not None:
            return cached
        return self._set_runtime_cache("scenes_list", api.get_scenes_list())

    def get_cached_device_detail(self, did: str, builder, ttl_seconds: float = SESSION_DEVICE_DETAIL_CACHE_TTL_SECONDS) -> dict[str, Any]:
        cache_key = f"device_detail:{did}"
        cached = self._get_runtime_cache(cache_key)
        if cached is not None:
            return cached
        return self._set_runtime_cache(cache_key, builder(), ttl_seconds=ttl_seconds)

    def set_pending_auth_data(self, auth_data: dict[str, Any]) -> None:
        self._auth_data = dict(auth_data)
        self._api = None
        self._vault_key = None
        self._vault_salt = None
        self._vault_iterations = VAULT_PBKDF2_ITERATIONS
        self.invalidate_runtime_cache()
        self.reset_sync_state()

    def set_vault_password(self, password: str) -> None:
        meta = self.read_meta()
        if meta.get("vault_configured"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="保险箱密码已设置，请使用修改密码接口")
        if self._auth_data is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="当前登录态不在内存中，请重新扫码登录")
        salt = get_random_bytes(16)
        key = _derive_vault_key(password, salt, VAULT_PBKDF2_ITERATIONS)
        self._vault_key = key
        self._vault_salt = salt
        self._vault_iterations = VAULT_PBKDF2_ITERATIONS
        self._write_vault(self._auth_data, key, salt=salt, iterations=VAULT_PBKDF2_ITERATIONS)
        self._api = self._build_api(self._auth_data)
        meta["vault_configured"] = True
        meta["vault_updated_at"] = int(time.time())
        self.write_meta(meta)

    def change_vault_password(self, old_password: str, new_password: str) -> bool:
        meta = self.read_meta()
        if not meta.get("vault_configured") or not self.vault_path.exists():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="当前会话尚未设置保险箱密码")
        decrypted_auth_data, _, _, _ = self._decrypt_vault(old_password)
        was_unlocked = self._api is not None and self._auth_data is not None
        auth_data = dict(self._auth_data) if was_unlocked and self._auth_data is not None else dict(decrypted_auth_data)
        salt = get_random_bytes(16)
        key = _derive_vault_key(new_password, salt, VAULT_PBKDF2_ITERATIONS)
        self._write_vault(auth_data, key, salt=salt, iterations=VAULT_PBKDF2_ITERATIONS)
        meta["vault_updated_at"] = int(time.time())
        self.write_meta(meta)
        if was_unlocked:
            self._auth_data = auth_data
            self._vault_key = key
            self._vault_salt = salt
            self._vault_iterations = VAULT_PBKDF2_ITERATIONS
            self._api = self._build_api(auth_data)
            return True
        self._auth_data = None
        self._api = None
        self._vault_key = None
        self._vault_salt = None
        self._vault_iterations = VAULT_PBKDF2_ITERATIONS
        return False

    def unlock(self, password: str) -> None:
        auth_data, key, salt, iterations = self._decrypt_vault(password)
        self._auth_data = dict(auth_data)
        self._vault_key = key
        self._vault_salt = salt
        self._vault_iterations = iterations
        self._api = self._build_api(self._auth_data)

    def lock_session(self) -> None:
        self._api = None
        self._auth_data = None
        self._vault_key = None
        self._vault_salt = None
        self._vault_iterations = VAULT_PBKDF2_ITERATIONS
        self.invalidate_runtime_cache()
        self.reset_sync_state()
        self.device_spec_cache.clear_hot_cache()

    def reset_sync_state(self) -> None:
        with self._sync_lock:
            self._sync_revision = 0
            self._sync_state = None
            self._sync_last_event = None
            self._sync_events.clear()
            self._sync_snapshot = None
            self._sync_snapshot_monotonic = 0.0

    def update_sync_state(self, snapshot: dict[str, Any]) -> tuple[int, Optional[dict[str, Any]]]:
        state = _extract_sync_state(snapshot)
        with self._sync_lock:
            self._sync_snapshot = snapshot
            self._sync_snapshot_monotonic = time.monotonic()
            if self._sync_state is None:
                self._sync_revision = 1
                self._sync_state = state
                self._sync_last_event = None
                return self._sync_revision, None

            changes, resync_required = _build_sync_delta(self._sync_state, state)
            self._sync_state = state
            if not changes and not resync_required:
                return self._sync_revision, None

            self._sync_revision += 1
            event = {
                "base_revision": self._sync_revision - 1,
                "revision": self._sync_revision,
                "generated_at": int(time.time()),
                "resync_required": resync_required,
                "changes": changes,
            }
            self._sync_last_event = event
            self._sync_events.append(event)
            return self._sync_revision, event

    def get_recent_sync_snapshot(
        self,
        max_age_seconds: float = SYNC_SNAPSHOT_REUSE_SECONDS,
    ) -> tuple[Optional[dict[str, Any]], int]:
        with self._sync_lock:
            if (
                self._sync_snapshot is None
                or time.monotonic() - self._sync_snapshot_monotonic > max_age_seconds
            ):
                return None, self._sync_revision
            return dict(self._sync_snapshot), self._sync_revision

    def invalidate_sync_snapshot(self) -> None:
        with self._sync_lock:
            self._sync_snapshot = None
            self._sync_snapshot_monotonic = 0.0

    def get_sync_event_after(self, revision: int) -> tuple[int, Optional[dict[str, Any]], bool]:
        with self._sync_lock:
            current = self._sync_revision
            if self._sync_state is None:
                return current, None, True
            if revision == current:
                return current, None, False
            pending = [
                event for event in self._sync_events
                if int(event["revision"]) > revision
            ]
            if not pending or int(pending[0]["base_revision"]) != revision:
                return current, None, True
            expected = revision
            for event in pending:
                if (
                    int(event["base_revision"]) != expected
                    or int(event["revision"]) != expected + 1
                ):
                    return current, None, True
                expected += 1
            if expected != current:
                return current, None, True
            if any(bool(event["resync_required"]) for event in pending):
                return current, None, True
            return current, _merge_sync_events(revision, pending), False

    def touch(self) -> None:
        now = time.monotonic()
        if now - self._last_touch_monotonic < SESSION_META_TOUCH_INTERVAL_SECONDS:
            return
        with self._touch_lock:
            now = time.monotonic()
            if now - self._last_touch_monotonic < SESSION_META_TOUCH_INTERVAL_SECONDS:
                return
            meta = self.read_meta()
            meta["last_seen_at"] = int(time.time())
            self.write_meta(meta)
            self._last_touch_monotonic = now

    def read_meta(self) -> dict[str, Any]:
        with self._meta_lock:
            if self._meta_cache is not None:
                return dict(self._meta_cache)
            if not self.meta_path.exists():
                self._meta_cache = {}
                return {}
            self._meta_cache = json.loads(self.meta_path.read_text(encoding="utf-8"))
            return dict(self._meta_cache)

    def write_meta(self, meta: dict[str, Any]) -> None:
        with self._meta_lock:
            self.session_dir.mkdir(parents=True, exist_ok=True)
            self.meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            self._meta_cache = dict(meta)


class SessionStore:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.retry_config = RetryConfig(
            request_timeout=config.request_timeout,
            login_timeout=config.login_timeout,
            max_retries=config.max_retries,
            retry_delay=config.retry_delay,
        )
        self.state_dir = config.state_dir
        self.sessions_dir = self.state_dir / "sessions"
        self.login_tasks_dir = self.state_dir / "login-tasks"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.login_tasks_dir.mkdir(parents=True, exist_ok=True)
        self._cache_lock = threading.RLock()
        self._login_task_lock = threading.RLock()
        self._active_login_tasks: set[str] = set()
        self._session_cache: dict[str, ManagedSession] = {}
        self._terminal_login_states: dict[str, dict[str, Any]] = {}
        self._login_claims: dict[str, dict[str, Any]] = {}
        self._login_task_owner_by_session: dict[str, str] = {}
        self._login_task_current_session_by_ip: dict[str, str] = {}
        self._cancelled_login_tasks: set[str] = set()
        self._semaphore = threading.BoundedSemaphore(config.max_concurrent_requests)
        self._device_spec_hot_cache = DeviceSpecLRUCache(int(os.getenv("MIJIA_DEVICE_SPEC_LRU_SIZE", "128")))
        self._cleanup_all_login_tasks()

    def acquire_slot(self) -> bool:
        return self._semaphore.acquire(timeout=self.config.acquire_timeout)

    def release_slot(self) -> None:
        self._semaphore.release()

    def _token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _validate_token_meta(self, token_hash: str, meta: dict[str, Any]) -> None:
        now = int(time.time())
        token_issued_at = meta.get("token_issued_at")
        token_expires_at = meta.get("token_expires_at")
        token_revoked_at = meta.get("token_revoked_at")
        if token_issued_at is None or token_expires_at is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token 元数据无效，请重新登录")
        if token_revoked_at is not None and now >= int(token_revoked_at):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token 已失效，请重新登录")
        if now >= int(token_expires_at):
            logger.info("本地 token 已过期 token_hash=%s", token_hash)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token 已过期，请重新登录")

    def _prune_login_runtime_state(self) -> None:
        now = int(time.time())
        with self._login_task_lock:
            expired_terminal_ids = [
                session_id
                for session_id, state in self._terminal_login_states.items()
                if now > int(state.get("expires_at", 0))
            ]
            for session_id in expired_terminal_ids:
                self._terminal_login_states.pop(session_id, None)
                self._prune_login_ownership(session_id)

            expired_claim_ids = [
                session_id
                for session_id, claim in self._login_claims.items()
                if now > int(claim.get("expires_at", 0))
            ]
            for session_id in expired_claim_ids:
                self._login_claims.pop(session_id, None)
                self._prune_login_ownership(session_id)

            expired_cancelled_ids = [session_id for session_id in self._cancelled_login_tasks if session_id in expired_terminal_ids or session_id in expired_claim_ids]
            for session_id in expired_cancelled_ids:
                self._cancelled_login_tasks.discard(session_id)

    def _prune_login_ownership(self, login_session_id: str) -> None:
        owner_ip = self._login_task_owner_by_session.pop(login_session_id, None)
        if owner_ip is None:
            return
        if self._login_task_current_session_by_ip.get(owner_ip) == login_session_id:
            self._login_task_current_session_by_ip.pop(owner_ip, None)

    def _assert_login_owner(self, login_session_id: str, client_ip: str) -> None:
        with self._login_task_lock:
            owner_ip = self._login_task_owner_by_session.get(login_session_id)
        if owner_ip is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="登录会话不存在")
        if owner_ip != client_ip:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="登录会话不属于当前客户端")

    def _cancel_login_task(self, login_session_id: str, *, message: str) -> None:
        now = int(time.time())
        with self._login_task_lock:
            self._cancelled_login_tasks.add(login_session_id)
            self._login_claims.pop(login_session_id, None)
            self._terminal_login_states[login_session_id] = {
                "session_id": login_session_id,
                "status": "replaced",
                "message": message,
                "expires_at": now + self.config.login_task_ttl,
                "error_code": "login_replaced",
            }
        self._cleanup_login_task(login_session_id)
        self._release_login_task(login_session_id)

    def _validated_login_session_id(self, login_session_id: str) -> str:
        if not LOGIN_SESSION_ID_RE.fullmatch(login_session_id or ""):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_public_error_payload("登录会话不存在", "login_session_not_found"),
            )
        return login_session_id

    def _task_dir(self, login_session_id: str) -> Path:
        validated_session_id = self._validated_login_session_id(login_session_id)
        base_dir = self.login_tasks_dir.resolve(strict=False)
        task_dir = (base_dir / validated_session_id).resolve(strict=False)
        if not _path_within(base_dir, task_dir) or task_dir.parent != base_dir:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_public_error_payload("登录会话不存在", "login_session_not_found"),
            )
        return task_dir

    def _task_state_path(self, login_session_id: str) -> Path:
        return self._task_dir(login_session_id) / "task.json"

    def _reserve_login_task(self, login_session_id: str) -> bool:
        with self._login_task_lock:
            if len(self._active_login_tasks) >= self.config.max_active_login_tasks:
                return False
            self._active_login_tasks.add(login_session_id)
            return True

    def _release_login_task(self, login_session_id: str) -> None:
        with self._login_task_lock:
            self._active_login_tasks.discard(login_session_id)

    def _cleanup_login_task(self, login_session_id: str) -> None:
        task_dir = self._task_dir(login_session_id)
        if task_dir.exists():
            shutil.rmtree(task_dir, ignore_errors=True)

    def _cleanup_all_login_tasks(self) -> None:
        _cleanup_legacy_login_task_artifacts(self.state_dir)

    def _read_task_state(self, login_session_id: str) -> dict[str, Any]:
        self._prune_login_runtime_state()
        state_path = self._task_state_path(login_session_id)
        if not state_path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="登录会话不存在")
        return json.loads(state_path.read_text(encoding="utf-8"))

    def _write_task_state(self, login_session_id: str, payload: dict[str, Any]) -> None:
        task_dir = self._task_dir(login_session_id)
        task_dir.mkdir(parents=True, exist_ok=True)
        self._task_state_path(login_session_id).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def get_login_qr_png(self, login_session_id: str, client_ip: str) -> bytes:
        """Encode the Xiaomi Passport long-poll URL as a local QR image."""
        self._validated_login_session_id(login_session_id)
        self._assert_login_owner(login_session_id, client_ip)
        state = self._read_task_state(login_session_id)
        login_url = str(state.get("login_url", ""))
        parsed_url = parse.urlparse(login_url)
        hostname = (parsed_url.hostname or "").lower()
        if parsed_url.scheme != "https" or not (
            hostname == "account.xiaomi.com"
            or hostname.endswith(".account.xiaomi.com")
        ):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="米家返回了不受信任的登录地址",
            )

        cache_path = self._task_dir(login_session_id) / "login-qr.png"
        if cache_path.exists():
            content = cache_path.read_bytes()
        else:
            try:
                qr = QRCode(border=4, box_size=1)
                qr.add_data(login_url)
                qr.make(fit=True)
                source = qr.make_image(
                    fill_color="black", back_color="white"
                ).get_image().convert("1")
                if source.width > 240 or source.height > 240:
                    raise ValueError("二维码矩阵超过显示区域")
                scale = min(240 // source.width, 240 // source.height)
                scaled = source.resize(
                    (source.width * scale, source.height * scale),
                    Image.Resampling.NEAREST,
                )
                canvas = Image.new("1", (240, 240), color=1)
                canvas.paste(
                    scaled,
                    ((240 - scaled.width) // 2, (240 - scaled.height) // 2),
                )
                output = io.BytesIO()
                canvas.save(output, format="PNG", optimize=False)
                content = output.getvalue()
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="登录二维码生成失败",
                ) from exc
            if len(content) > 256 * 1024:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="二维码图片超过大小限制",
                )
            cache_path.write_bytes(content)

        if len(content) < 24 or content[:8] != b"\x89PNG\r\n\x1a\n":
            cache_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="二维码响应不是有效 PNG 图片",
            )
        return content

    def get_login_qr_i1(self, login_session_id: str, client_ip: str) -> bytes:
        """Return the cached QR image in a compact LVGL I1 wire format."""
        png = self.get_login_qr_png(login_session_id, client_ip)
        width = 240
        height = 240
        stride = 32

        try:
            with Image.open(io.BytesIO(png)) as source:
                image = source.convert("L")
                if image.size != (width, height):
                    image = image.resize((width, height), Image.Resampling.NEAREST)
                image = image.point(lambda value: 255 if value >= 128 else 0, mode="1")
                packed = image.tobytes()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="二维码图片转换失败",
            ) from exc

        row_bytes = (width + 7) // 8
        if len(packed) != row_bytes * height:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="二维码图片尺寸异常",
            )

        pixels = bytearray(b"\xff" * (stride * height))
        for row in range(height):
            source_offset = row * row_bytes
            target_offset = row * stride
            pixels[target_offset : target_offset + row_bytes] = packed[
                source_offset : source_offset + row_bytes
            ]

        # HQR1 + big-endian dimensions + I1 format. LVGL's indexed image
        # data begins with two BGRA palette entries: black and white.
        header = struct.pack(">4sHHHBB", b"HQR1", width, height, stride, 1, 0)
        palette = b"\x00\x00\x00\xff\xff\xff\xff\xff"
        return header + palette + bytes(pixels)

    def get_login_qr_rgb565(self, login_session_id: str, client_ip: str) -> bytes:
        """Return the cached QR image as native little-endian RGB565 pixels."""
        png = self.get_login_qr_png(login_session_id, client_ip)
        width = 240
        height = 240
        stride = width * 2

        try:
            with Image.open(io.BytesIO(png)) as source:
                image = source.convert("L")
                if image.size != (width, height):
                    image = image.resize((width, height), Image.Resampling.NEAREST)
                mono = image.point(lambda value: 255 if value >= 128 else 0, mode="1")
                packed = mono.tobytes()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="二维码图片转换失败",
            ) from exc

        row_bytes = (width + 7) // 8
        if len(packed) != row_bytes * height:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="二维码图片尺寸异常",
            )

        pixels = bytearray(stride * height)
        for y in range(height):
            for x in range(width):
                source_byte = packed[y * row_bytes + x // 8]
                white = source_byte & (0x80 >> (x % 8))
                offset = y * stride + x * 2
                if white:
                    pixels[offset] = 0xFF
                    pixels[offset + 1] = 0xFF

        header = struct.pack(">4sHHHBB", b"HQR2", width, height, stride, 2, 0)
        return header + bytes(pixels)

    def _store_terminal_login_state(self, login_session_id: str, payload: dict[str, Any]) -> None:
        terminal_payload = dict(payload)
        terminal_payload.setdefault("session_id", login_session_id)
        terminal_payload.setdefault("expires_at", int(time.time()) + self.config.login_task_ttl)
        with self._login_task_lock:
            self._terminal_login_states[login_session_id] = terminal_payload

    def _create_login_claim(self, login_session_id: str, claim_secret: str, expires_at: int) -> None:
        with self._login_task_lock:
            self._login_claims[login_session_id] = {
                "claim_secret": claim_secret,
                "expires_at": expires_at,
                "token": None,
                "token_expires_at": None,
            }

    def _mark_login_claim_ready(self, login_session_id: str, token: str, token_expires_at: int) -> None:
        with self._login_task_lock:
            claim = self._login_claims.get(login_session_id)
            if claim is None:
                return
            claim["token"] = token
            claim["token_expires_at"] = token_expires_at

    def _clear_login_claim(self, login_session_id: str) -> None:
        with self._login_task_lock:
            self._login_claims.pop(login_session_id, None)

    def _http_get_with_retry(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        session: Optional[requests.Session] = None,
    ) -> requests.Response:
        requester = session.get if session is not None else requests.get
        last_error: Optional[Exception] = None
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                return requester(url, headers=headers, timeout=timeout or self.retry_config.request_timeout)
            except requests.exceptions.Timeout as exc:
                last_error = exc
                if attempt >= self.retry_config.max_retries:
                    raise LoginError(-10006, "请求米家服务器超时")
            except requests.exceptions.RequestException as exc:
                last_error = exc
                if attempt >= self.retry_config.max_retries:
                    raise LoginError(-10001, f"请求米家服务器失败: {exc}")
            time.sleep(self.retry_config.retry_delay)
        raise LoginError(-10001, f"请求米家服务器失败: {last_error}")

    def start_login(self, client_ip: str) -> dict[str, Any]:
        with self._login_task_lock:
            old_session_id = self._login_task_current_session_by_ip.get(client_ip)
        if old_session_id:
            self._cancel_login_task(old_session_id, message="已被同一 IP 的新登录任务替换")

        login_session_id = uuid.uuid4().hex
        if not self._reserve_login_task(login_session_id):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"当前登录任务过多，请稍后重试（最多 {self.config.max_active_login_tasks} 个并发登录任务）",
            )
        task_dir = self._task_dir(login_session_id)
        claim_secret = secrets.token_urlsafe(24)
        task_dir.mkdir(parents=True, exist_ok=True)
        try:
            with self._login_task_lock:
                self._login_task_owner_by_session[login_session_id] = client_ip
                self._login_task_current_session_by_ip[client_ip] = login_session_id

            api = mijiaAPI(
                auth_data_path=str(task_dir / "__unused_auth.json"),
                allow_plaintext_persistence=False,
                request_timeout=self.retry_config.request_timeout,
                login_timeout=self.retry_config.login_timeout,
                max_retries=self.retry_config.max_retries,
                retry_delay=self.retry_config.retry_delay,
            )
            login_http = requests.Session()
            headers = {
                "User-Agent": api.user_agent,
                "Accept-Encoding": "gzip",
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "keep-alive",
            }
            service_headers = dict(headers)
            service_headers["Cookie"] = (
                f"deviceId={api.deviceId};"
                "sdkVersion=3.4.1;"
                f"pass_o={api.pass_o};"
                f"uLocale={api.locale};"
            )
            service_ret = self._http_get_with_retry(
                api.service_login_url,
                headers=service_headers,
                session=login_http,
            )
            service_data = api._handle_ret(service_ret, verify_code=False)
            location = str(service_data.get("location", ""))
            if not location:
                raise LoginError(-1, "米家登录响应缺少 location")

            location_query = {
                key: values[0]
                for key, values in parse.parse_qs(
                    parse.urlparse(location).query
                ).items()
            }
            required_fields = ("qs", "_sign", "callback")
            missing_fields = [
                field for field in required_fields
                if not service_data.get(field) and not location_query.get(field)
            ]
            if missing_fields:
                raise LoginError(
                    -1,
                    "米家登录响应缺少字段: " + ", ".join(missing_fields),
                )

            location_data = {
                "_qrsize": "240",
                "qs": service_data.get("qs") or location_query["qs"],
                "bizDeviceType": "",
                "callback": (
                    service_data.get("callback")
                    or location_query["callback"]
                ),
                "_json": "true",
                "theme": "",
                "sid": service_data.get("sid", "mijia"),
                "needTheme": "false",
                "showActiveX": "false",
                "serviceParam": (
                    service_data.get("serviceParam")
                    or location_query.get("serviceParam", "")
                ),
                "_locale": api.locale,
                "_sign": service_data.get("_sign") or location_query["_sign"],
                "_hasLogo": "false",
                "_dc": str(int(time.time() * 1000)),
            }
            url = api.login_url + "?" + parse.urlencode(location_data)
            qr_headers = dict(headers)
            qr_headers["Referer"] = api.service_login_url
            login_ret = self._http_get_with_retry(
                url,
                headers=qr_headers,
                session=login_http,
            )
            login_data = api._handle_ret(login_ret)
            payload = {
                "session_id": login_session_id,
                "status": "waiting",
                "message": "",
                "qr_url": login_data["qr"],
                "login_url": login_data["loginUrl"],
                "lp_url": login_data["lp"],
                "created_at": int(time.time()),
                "expires_at": int(time.time()) + self.config.login_task_ttl,
            }
            self._create_login_claim(login_session_id, claim_secret, payload["expires_at"])
            self._write_task_state(login_session_id, payload)
            thread = threading.Thread(
                target=self._complete_login,
                args=(
                    login_session_id,
                    api,
                    qr_headers,
                    login_data["lp"],
                    login_http,
                ),
                daemon=True,
            )
            thread.start()
            return {
                "session_id": login_session_id,
                "status": "waiting",
                "qr_url": login_data["qr"],
                "login_url": login_data["loginUrl"],
                "expires_at": payload["expires_at"],
                "claim_secret": claim_secret,
            }
        except Exception:
            self._clear_login_claim(login_session_id)
            self._release_login_task(login_session_id)
            self._cleanup_login_task(login_session_id)
            with self._login_task_lock:
                self._prune_login_ownership(login_session_id)
            raise

    def _complete_login(
        self,
        login_session_id: str,
        api: mijiaAPI,
        headers: dict[str, str],
        long_poll_url: str,
        session: requests.Session,
    ) -> None:
        try:
            with self._login_task_lock:
                cancelled = login_session_id in self._cancelled_login_tasks
            if cancelled:
                self._store_terminal_login_state(login_session_id, {
                    "status": "replaced",
                    "message": "登录任务已被替换",
                    "error_code": "login_replaced",
                    "expires_at": int(time.time()) + self.config.login_task_ttl,
                })
                self._cleanup_login_task(login_session_id)
                return

            lp_ret = session.get(long_poll_url, headers=headers, timeout=self.retry_config.login_timeout)
            lp_data = api._handle_ret(lp_ret)
            for key in ["psecurity", "nonce", "ssecurity", "passToken", "userId", "cUserId"]:
                api.auth_data[key] = lp_data[key]
            callback_url = lp_data["location"]
            self._http_get_with_retry(
                callback_url,
                headers=headers,
                timeout=self.retry_config.request_timeout,
                session=session,
            )
            cookies = session.cookies.get_dict()
            api.auth_data.update(cookies)
            api.auth_data.update({
                "expireTime": int((time.time() + 30 * 24 * 3600) * 1000),
            })

            with self._login_task_lock:
                cancelled = login_session_id in self._cancelled_login_tasks
            if cancelled:
                self._clear_login_claim(login_session_id)
                self._store_terminal_login_state(login_session_id, {
                    "status": "replaced",
                    "message": "登录任务已被替换",
                    "error_code": "login_replaced",
                    "expires_at": int(time.time()) + self.config.login_task_ttl,
                })
                self._cleanup_login_task(login_session_id)
                return

            access_token = secrets.token_urlsafe(32)
            token_hash = self._token_hash(access_token)
            session_dir = self.sessions_dir / token_hash
            session_dir.mkdir(parents=True, exist_ok=True)
            (session_dir / "device-cache").mkdir(parents=True, exist_ok=True)
            managed_session = ManagedSession(
                token_hash,
                session_dir,
                self.retry_config,
                self._device_spec_hot_cache,
            )
            managed_session.set_pending_auth_data(api.auth_data)
            token_issued_at = int(time.time())
            token_expires_at = token_issued_at + self.config.local_token_ttl_seconds
            meta = {
                "token_hash": token_hash,
                "created_at": token_issued_at,
                "last_seen_at": token_issued_at,
                "token_issued_at": token_issued_at,
                "token_expires_at": token_expires_at,
                "token_revoked_at": None,
                "vault_configured": False,
                "vault_updated_at": None,
            }
            managed_session.write_meta(meta)
            with self._cache_lock:
                self._session_cache[token_hash] = managed_session
            with self._login_task_lock:
                cancelled = login_session_id in self._cancelled_login_tasks
            if cancelled:
                self._clear_login_claim(login_session_id)
                self._store_terminal_login_state(login_session_id, {
                    "status": "replaced",
                    "message": "登录任务已被替换",
                    "error_code": "login_replaced",
                    "expires_at": int(time.time()) + self.config.login_task_ttl,
                })
                self._cleanup_login_task(login_session_id)
                return
            self._mark_login_claim_ready(login_session_id, access_token, token_expires_at)
            self._store_terminal_login_state(login_session_id, {
                "status": "success",
                "message": "登录成功",
                "token_expires_at": token_expires_at,
                "requires_password_setup": True,
                "upstream_token_expires_at": api.auth_data.get("expireTime"),
                "expires_at": int(time.time()) + self.config.login_task_ttl,
            })
            self._cleanup_login_task(login_session_id)
        except requests.exceptions.Timeout:
            self._clear_login_claim(login_session_id)
            self._store_terminal_login_state(login_session_id, {
                "status": "timeout",
                "message": "请求米家服务器超时",
                "error_code": "login_timeout",
                "expires_at": int(time.time()) + self.config.login_task_ttl,
            })
            self._cleanup_login_task(login_session_id)
        except Exception:
            logger.exception("扫码登录失败")
            self._clear_login_claim(login_session_id)
            self._store_terminal_login_state(login_session_id, {
                "status": "error",
                "message": "登录流程失败，请重新发起扫码登录",
                "error_code": "login_failed",
                "expires_at": int(time.time()) + self.config.login_task_ttl,
            })
            self._cleanup_login_task(login_session_id)
        finally:
            self._release_login_task(login_session_id)

    def get_login_status(self, login_session_id: str, client_ip: str) -> dict[str, Any]:
        self._validated_login_session_id(login_session_id)
        self._assert_login_owner(login_session_id, client_ip)
        self._prune_login_runtime_state()
        with self._login_task_lock:
            terminal_state = self._terminal_login_states.get(login_session_id)
        if terminal_state is not None:
            return {
                key: value
                for key, value in terminal_state.items()
                if key in {
                    "session_id",
                    "status",
                    "message",
                    "qr_url",
                    "login_url",
                    "expires_at",
                    "token_expires_at",
                    "error_code",
                    "requires_password_setup",
                }
            }

        state = self._read_task_state(login_session_id)
        now = int(time.time())
        if state["status"] == "waiting" and now > state["expires_at"]:
            self._clear_login_claim(login_session_id)
            self._store_terminal_login_state(login_session_id, {
                "session_id": login_session_id,
                "status": "expired",
                "message": "二维码已过期，请重新生成",
                "expires_at": now + self.config.login_task_ttl,
            })
            self._cleanup_login_task(login_session_id)
            with self._login_task_lock:
                terminal_state = self._terminal_login_states.get(login_session_id, {})
            return {
                key: value
                for key, value in terminal_state.items()
                if key in {
                    "session_id",
                    "status",
                    "message",
                    "expires_at",
                    "error_code",
                }
            }
        response = {
            key: value
            for key, value in state.items()
            if key in {
                "session_id",
                "status",
                "message",
                "qr_url",
                "login_url",
                "expires_at",
                "error_code",
            }
        }
        return response

    def claim_login_token(self, login_session_id: str, claim_secret: str, client_ip: str) -> dict[str, Any]:
        validated_session_id = self._validated_login_session_id(login_session_id)
        self._assert_login_owner(validated_session_id, client_ip)
        self._prune_login_runtime_state()
        with self._login_task_lock:
            claim = self._login_claims.get(validated_session_id)
            if claim is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=_public_error_payload("登录会话不存在或已失效", "login_claim_not_found"),
                )
            if not secrets.compare_digest(str(claim.get("claim_secret", "")), claim_secret):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=_public_error_payload("登录凭据无效", "invalid_login_claim"),
                )
            token = claim.get("token")
            token_expires_at = claim.get("token_expires_at")
            if token is None or token_expires_at is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=_public_error_payload("登录尚未完成，请稍后重试", "login_not_ready"),
                )
            self._login_claims.pop(validated_session_id, None)
            self._prune_login_ownership(validated_session_id)
        return {
            "token": token,
            "token_type": "Bearer",
            "token_expires_at": token_expires_at,
            "requires_password_setup": True,
        }

    def get_session(self, token: str) -> ManagedSession:
        token_hash = self._token_hash(token)
        with self._cache_lock:
            session = self._session_cache.get(token_hash)
            if session is not None:
                meta = session.read_meta()
                try:
                    self._validate_token_meta(token_hash, meta)
                except HTTPException:
                    session.lock_session()
                    self._session_cache.pop(token_hash, None)
                    raise
                session.touch()
                return session
            session_dir = self.sessions_dir / token_hash
            meta_path = session_dir / "meta.json"
            vault_path = session_dir / "vault.bin"
            if not meta_path.exists() and not vault_path.exists():
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效 token")
            meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
            self._validate_token_meta(token_hash, meta)
            session = ManagedSession(
                token_hash,
                session_dir,
                self.retry_config,
                self._device_spec_hot_cache,
            )
            session.touch()
            self._session_cache[token_hash] = session
            return session

    def clear_session(self, token: str) -> dict[str, Any]:
        token_hash = self._token_hash(token)
        session_dir = self.sessions_dir / token_hash
        with self._cache_lock:
            session = self._session_cache.pop(token_hash, None)
        if session is not None:
            meta = session.read_meta()
            meta["token_revoked_at"] = int(time.time())
            session.write_meta(meta)
            session.lock_session()
        elif session_dir.exists():
            meta_path = session_dir / "meta.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                meta["token_revoked_at"] = int(time.time())
                meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        if session_dir.exists():
            try:
                shutil.rmtree(session_dir)
            except OSError:
                logger.exception("删除会话目录失败 token_hash=%s", token_hash)
        residual_paths = [
            session_dir / "vault.bin",
            session_dir / "meta.json",
            session_dir / "device-cache",
        ]
        if session_dir.exists() or any(path.exists() for path in residual_paths):
            logger.error("会话删除后仍存在残留 token_hash=%s", token_hash)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=_public_error_payload("会话清理失败，请稍后重试", "session_clear_failed"),
            )
        return {"cleared": True}


def build_device_detail(session: ManagedSession, did: str) -> dict[str, Any]:
    api = session.load_api()
    device_meta = None
    devices = session.get_cached_devices_list(api)
    for item in devices:
        if item["did"] == did:
            device_meta = item
            break
    if device_meta is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="设备不存在")

    homes = session.get_cached_home_name_map(api)
    info = get_device_info(device_meta["model"], cache_backend=session.device_spec_cache)
    readable_params = []
    prop_key_mapping = {}
    for prop in info.get("properties", []):
        if "r" in prop.get("rw", ""):
            method = prop["method"].copy()
            method["did"] = did
            readable_params.append(method)
            prop_key_mapping[(prop["method"]["siid"], prop["method"]["piid"])] = prop["name"]

    values_map: dict[str, Any] = {}
    error_map: dict[str, str] = {}
    if readable_params:
        results = api.get_devices_prop(readable_params)
        for item in results:
            prop_name = prop_key_mapping.get((item["siid"], item["piid"]))
            if prop_name is None:
                continue
            if item.get("code", 0) == 0:
                values_map[prop_name] = item.get("value")
            else:
                error_map[prop_name] = f"读取失败: {item.get('code')}"

    properties = []
    for prop in info.get("properties", []):
        properties.append({
            "name": prop["name"],
            "description": prop.get("description", ""),
            "siid": prop["method"]["siid"],
            "piid": prop["method"]["piid"],
            "type": prop.get("type", ""),
            "rw": prop.get("rw", ""),
            "notifiable": bool(prop.get("notifiable", False)),
            "range": prop.get("range"),
            "value_list": prop.get("value-list"),
            "readable": "r" in prop.get("rw", ""),
            "writable": "w" in prop.get("rw", ""),
            "current_value": values_map.get(prop["name"]),
            "current_error": error_map.get(prop["name"]),
        })

    actions = [
        {
            "name": action["name"],
            "description": action.get("description", ""),
            "siid": action["method"]["siid"],
            "aiid": action["method"]["aiid"],
        }
        for action in info.get("actions", [])
    ]

    return {
        "did": device_meta["did"],
        "name": device_meta.get("name", did),
        "model": device_meta.get("model", ""),
        "home_id": device_meta.get("home_id", ""),
        "home_name": homes.get(device_meta.get("home_id", ""), "共享设备" if device_meta.get("home_id") == "shared" else ""),
        "properties": properties,
        "actions": actions,
    }


def get_device_detail_cached(session: ManagedSession, did: str) -> dict[str, Any]:
    return session.get_cached_device_detail(did, lambda: build_device_detail(session, did))


def classify_device_type(device: dict[str, Any]) -> str:
    """Return a stable UI category from model and MIoT capabilities."""

    model = str(device.get("model", "")).lower()
    name = str(device.get("name", "")).lower()
    properties = {item.get("name", "") for item in device.get("properties", [])}
    actions = {item.get("name", "") for item in device.get("actions", [])}

    if ".wifispeaker." in model or {"play", "pause"} <= actions:
        return "speaker"
    if ".heater." in model or "target-temperature" in properties:
        return "heater"
    if ".plug." in model or "power-consumption" in properties:
        return "outlet"
    if ".light." in model or {"brightness", "color-temperature"} <= properties:
        return "light"
    if ".magnet." in model or "contact-state" in properties:
        return "contact-sensor"
    if ".sensor_ht." in model or {"temperature", "relative-humidity"} <= properties:
        return "environment-sensor"
    if model.startswith("miir.tv."):
        return "television-remote"
    if model.startswith("miir.stb."):
        return "set-top-box-remote"
    if ".switch." in model or "toggle" in actions:
        return "switch"
    if ".treadmill." in model:
        return "treadmill"
    if ".watch." in model:
        return "wearable"
    if ".fitting." in model or "tag" in name:
        return "tracker"
    return "device"


def build_family_snapshot(session: ManagedSession) -> dict[str, Any]:
    """Build one consistent, board-friendly view of the Mijia account."""

    api = session.load_api()
    homes_list = session.get_cached_homes_list(api)
    devices_list = session.get_cached_devices_list(api)
    scenes_list = session.get_cached_scenes_list(api)

    homes = []
    home_names: dict[str, str] = {}
    device_rooms: dict[str, tuple[str, str]] = {}
    for home in homes_list:
        home_id = str(home.get("id", ""))
        home_name = str(home.get("name", ""))
        home_names[home_id] = home_name
        rooms = []
        for room in home.get("roomlist", []) or []:
            room_id = str(room.get("id", ""))
            room_name = str(room.get("name", ""))
            dids = [str(did) for did in room.get("dids", []) or []]
            for did in dids:
                device_rooms[did] = (room_id, room_name)
            rooms.append({
                "id": room_id,
                "name": room_name,
                "dids": dids,
                "create_time": room.get("create_time"),
            })
        homes.append({
            "id": home_id,
            "name": home_name,
            "address": home.get("address", ""),
            "create_time": home.get("create_time"),
            "rooms": rooms,
        })

    devices = []
    online_count = 0
    detail_error_count = 0
    for item in devices_list:
        did = str(item["did"])
        home_id = str(item.get("home_id", ""))
        room_id, room_name = device_rooms.get(did, ("", ""))
        online = bool(item.get("isOnline", False))
        online_count += int(online)
        try:
            detail = get_device_detail_cached(session, did)
            properties = detail.get("properties", [])
            actions = detail.get("actions", [])
            detail_available = True
        except Exception as exc:
            did_hash = hashlib.sha256(did.encode("utf-8")).hexdigest()[:12]
            logger.warning(
                "聚合设备详情失败 did_hash=%s error=%s",
                did_hash,
                type(exc).__name__,
            )
            properties = []
            actions = []
            detail_available = False
            detail_error_count += 1

        device = {
            "did": did,
            "name": item.get("name", did),
            "model": item.get("model", ""),
            "home_id": home_id,
            "home_name": home_names.get(
                home_id,
                "共享设备" if home_id == "shared" else "",
            ),
            "room_id": room_id,
            "room_name": room_name,
            "isOnline": online,
            "detail_available": detail_available,
            "properties": properties,
            "actions": actions,
        }
        device["device_type"] = classify_device_type(device)
        devices.append(device)

    scenes = [
        {
            "scene_id": str(item["scene_id"]),
            "name": item.get("name", ""),
            "home_id": str(item.get("home_id", "")),
            "home_name": home_names.get(str(item.get("home_id", "")), ""),
            "create_time": item.get("create_time"),
        }
        for item in scenes_list
    ]
    room_count = sum(len(home["rooms"]) for home in homes)
    return {
        "generated_at": int(time.time()),
        "protocol": {
            "model": "MIoT-Spec-V2",
            "control": "cloud-http-ot",
            "event_source": "cloud-readback",
            "mqtt_connected": False,
            "panel_sync": "miot-delta-v1",
        },
        "summary": {
            "home_count": len(homes),
            "room_count": room_count,
            "device_count": len(devices),
            "online_count": online_count,
            "scene_count": len(scenes),
            "detail_error_count": detail_error_count,
            "primary_home_name": homes[0]["name"] if homes else "",
        },
        "homes": homes,
        "devices": devices,
        "scenes": scenes,
    }


def _extract_sync_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    structure = {
        "homes": sorted([
            {
                "id": home["id"],
                "name": home["name"],
                "rooms": sorted([
                    {
                        "id": room["id"],
                        "name": room["name"],
                        "dids": sorted(room["dids"]),
                    }
                    for room in home["rooms"]
                ], key=lambda room: room["id"]),
            }
            for home in snapshot["homes"]
        ], key=lambda home: home["id"]),
        "devices": sorted([
            {
                "did": device["did"],
                "name": device["name"],
                "model": device["model"],
                "home_id": device["home_id"],
                "room_id": device["room_id"],
                "room_name": device["room_name"],
                "device_type": device["device_type"],
                "detail_available": device["detail_available"],
                "properties": sorted([
                    {
                        "name": prop["name"],
                        "siid": prop["siid"],
                        "piid": prop["piid"],
                        "rw": prop["rw"],
                        "range": prop["range"],
                    }
                    for prop in device["properties"]
                ], key=lambda prop: (prop["siid"], prop["piid"])),
            }
            for device in snapshot["devices"]
        ], key=lambda device: device["did"]),
        "scenes": sorted([
            {
                "scene_id": scene["scene_id"],
                "name": scene["name"],
                "home_id": scene["home_id"],
            }
            for scene in snapshot["scenes"]
        ], key=lambda scene: scene["scene_id"]),
    }
    devices = {}
    for device in snapshot["devices"]:
        properties = {}
        for prop in device["properties"]:
            # The cloud readback path also observes readable properties that
            # are not marked notify in some older product specifications.
            # They use the same MIoT delta envelope for the panel transport.
            if not prop.get("readable", False):
                continue
            key = f"{prop['siid']}:{prop['piid']}"
            properties[key] = {
                "siid": prop["siid"],
                "piid": prop["piid"],
                "value": _normalize_sync_value(prop.get("current_value")),
                "error": _normalize_sync_value(prop.get("current_error")),
            }
        devices[device["did"]] = {
            "online": device["isOnline"],
            "properties": properties,
        }
    return {
        "structure": json.dumps(structure, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "devices": devices,
    }


def _normalize_sync_value(value: Any) -> Any:
    """Make cloud values deterministic before comparing sync revisions."""

    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {
            str(key): _normalize_sync_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_sync_value(item) for item in value]
    return value


def _build_sync_delta(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> tuple[list[dict[str, Any]], bool]:
    if previous["structure"] != current["structure"]:
        return [], True

    previous_devices = previous["devices"]
    current_devices = current["devices"]
    if previous_devices.keys() != current_devices.keys():
        return [], True

    online_changes = []
    property_changes = []
    for did, device in current_devices.items():
        old_device = previous_devices[did]
        if old_device["online"] != device["online"]:
            online_changes.append({
                "did": did,
                "previous_value": old_device["online"],
                "value": device["online"],
            })

        old_properties = old_device["properties"]
        properties = device["properties"]
        if old_properties.keys() != properties.keys():
            return [], True
        for key, prop in properties.items():
            old_prop = old_properties[key]
            if old_prop["value"] == prop["value"] and old_prop["error"] == prop["error"]:
                continue
            property_changes.append({
                "did": did,
                "siid": prop["siid"],
                "piid": prop["piid"],
                "previous_value": old_prop["value"],
                "previous_code": 0 if old_prop["error"] is None else -1,
                "value": prop["value"],
                "code": 0 if prop["error"] is None else -1,
            })

    changes = []
    if online_changes:
        changes.append({"method": "device_online_changed", "params": online_changes})
    if property_changes:
        changes.append({"method": "properties_changed", "params": property_changes})
    return changes, False


def _merge_sync_events(
    base_revision: int,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Coalesce a continuous event range without changing MIoT methods."""

    online: OrderedDict[str, dict[str, Any]] = OrderedDict()
    properties: OrderedDict[tuple[str, int, int], dict[str, Any]] = OrderedDict()
    for event in events:
        for change in event.get("changes", []):
            method = change.get("method")
            for param in change.get("params", []):
                if method == "device_online_changed":
                    key = str(param.get("did", ""))
                    merged = dict(param)
                    if key in online:
                        merged["previous_value"] = online[key].get("previous_value")
                    online[key] = merged
                    online.move_to_end(key)
                elif method == "properties_changed":
                    key = (
                        str(param.get("did", "")),
                        int(param.get("siid", 0)),
                        int(param.get("piid", 0)),
                    )
                    merged = dict(param)
                    if key in properties:
                        merged["previous_value"] = properties[key].get("previous_value")
                        merged["previous_code"] = properties[key].get("previous_code")
                    properties[key] = merged
                    properties.move_to_end(key)

    online = OrderedDict(
        (key, value) for key, value in online.items()
        if value.get("previous_value") != value.get("value")
    )
    properties = OrderedDict(
        (key, value) for key, value in properties.items()
        if (
            value.get("previous_value") != value.get("value")
            or value.get("previous_code") != value.get("code")
        )
    )

    changes = []
    if online:
        changes.append({
            "method": "device_online_changed",
            "params": list(online.values()),
        })
    if properties:
        changes.append({
            "method": "properties_changed",
            "params": list(properties.values()),
        })
    return {
        "base_revision": base_revision,
        "revision": int(events[-1]["revision"]),
        "generated_at": int(events[-1]["generated_at"]),
        "resync_required": False,
        "changes": changes,
    }


def create_app(config: ServerConfig) -> FastAPI:
    _validate_server_config(config)
    _enforce_workspace_sensitive_artifacts(config.state_dir)
    enable_docs = os.getenv("MIJIA_ENABLE_DOCS", "0") in {"1", "true", "TRUE", "True"}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        limiter = anyio.to_thread.current_default_thread_limiter()
        limiter.total_tokens = max(40, config.thread_pool_tokens)
        logger.info("AnyIO 线程池令牌数已设置为 %s", limiter.total_tokens)
        yield

    app = FastAPI(
        title="mijiaAPI Server",
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
        lifespan=lifespan,
    )
    app.state.config = config
    app.add_middleware(SecurityHeadersMiddleware)
    if config.allowed_hosts != ("*",):
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.allowed_hosts))

    store = SessionStore(config)
    bearer = HTTPBearer(auto_error=False)
    rate_window_seconds = int(os.getenv("MIJIA_RATE_WINDOW_SECONDS", "60"))
    rate_limiter = RateLimiter(
        max_buckets=int(os.getenv("MIJIA_RATE_LIMIT_MAX_BUCKETS", "10000")),
        bucket_ttl_seconds=int(os.getenv("MIJIA_RATE_BUCKET_TTL_SECONDS", str(max(300, rate_window_seconds * 2)))),
    )
    public_rate_limit = int(os.getenv("MIJIA_PUBLIC_RATE_LIMIT", "30"))
    login_rate_limit = int(os.getenv("MIJIA_LOGIN_RATE_LIMIT", "6"))
    login_daily_rate_limit = int(os.getenv("MIJIA_LOGIN_DAILY_RATE_LIMIT", "30"))
    login_daily_rate_limiter = RateLimiter(
        max_buckets=int(os.getenv("MIJIA_RATE_LIMIT_MAX_BUCKETS", "10000")),
        bucket_ttl_seconds=86400 * 2,
    )
    read_rate_limit = int(os.getenv("MIJIA_READ_RATE_LIMIT", "240"))
    write_rate_limit = int(os.getenv("MIJIA_WRITE_RATE_LIMIT", "60"))
    sync_poll_seconds = max(1.0, min(10.0, float(os.getenv("MIJIA_SYNC_POLL_SECONDS", "3"))))

    def request_slot(request: Request):
        queue_started_at = time.perf_counter()
        acquired = store.acquire_slot()
        queue_wait_ms = int((time.perf_counter() - queue_started_at) * 1000)
        request.state.queue_wait_ms = queue_wait_ms
        request.state.client_ip = _get_request_identity(request, config)
        if not acquired:
            logger.warning(
                "请求排队超时 ip=%s path=%s wait_ms=%s",
                request.state.client_ip,
                request.url.path,
                queue_wait_ms,
            )
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="请求排队超时，请稍后重试")
        try:
            yield
        finally:
            if acquired:
                store.release_slot()

    def get_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> str:
        if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 Bearer token")
        return credentials.credentials

    def get_session(token: str = Depends(get_token)) -> ManagedSession:
        return store.get_session(token)

    def enforce_public_rate_limit(request: Request) -> None:
        host = _get_request_identity(request, config)
        allowed, retry_after = rate_limiter.allow(
            f"public:{host}",
            limit=public_rate_limit,
            window_seconds=rate_window_seconds,
        )
        if not allowed:
            logger.warning("公开接口限流 ip=%s path=%s retry_after=%s", host, request.url.path, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"请求过于频繁，请在 {retry_after} 秒后重试",
            )

    def enforce_login_rate_limit(request: Request) -> None:
        host = getattr(request.state, "client_ip", None) or _get_request_identity(request, config)
        allowed, retry_after = rate_limiter.allow(
            f"login:{host}",
            limit=login_rate_limit,
            window_seconds=rate_window_seconds,
        )
        if not allowed:
            logger.warning("登录接口限流 ip=%s path=%s retry_after=%s", host, request.url.path, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"登录请求过于频繁，请在 {retry_after} 秒后重试",
            )
        allowed, retry_after = login_daily_rate_limiter.allow(
            f"login:daily:{host}",
            limit=login_daily_rate_limit,
            window_seconds=86400,
        )
        if not allowed:
            logger.warning("登录接口24小时限流 ip=%s path=%s retry_after=%s", host, request.url.path, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"24小时内登录请求已达到上限（{login_daily_rate_limit}次），请在 {retry_after} 秒后重试",
            )

    def enforce_read_rate_limit(
        request: Request,
        session: ManagedSession = Depends(get_session),
    ) -> ManagedSession:
        host = _get_request_identity(request, config)
        allowed, retry_after = rate_limiter.allow(
            f"read:{session.token_hash}:{host}",
            limit=read_rate_limit,
            window_seconds=rate_window_seconds,
        )
        if not allowed:
            logger.warning("读取接口限流 ip=%s path=%s retry_after=%s", host, request.url.path, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"读取请求过于频繁，请在 {retry_after} 秒后重试",
            )
        return session

    def enforce_write_rate_limit(
        request: Request,
        session: ManagedSession = Depends(get_session),
    ) -> ManagedSession:
        host = _get_request_identity(request, config)
        allowed, retry_after = rate_limiter.allow(
            f"write:{session.token_hash}:{host}",
            limit=write_rate_limit,
            window_seconds=rate_window_seconds,
        )
        if not allowed:
            logger.warning("写入接口限流 ip=%s path=%s retry_after=%s", host, request.url.path, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"写入请求过于频繁，请在 {retry_after} 秒后重试",
            )
        return session

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException):
        if isinstance(exc.detail, dict):
            content = exc.detail
        else:
            content = _public_error_payload(str(exc.detail), "http_error")
        return JSONResponse(status_code=exc.status_code, content=content)

    async def business_exception_handler(request: Request, exc: Exception):
        detail = str(exc)
        status_code = status.HTTP_400_BAD_REQUEST
        payload = _public_error_payload("请求处理失败，请稍后重试", "request_failed")
        if "超时" in detail.lower() or "timeout" in detail.lower():
            status_code = status.HTTP_504_GATEWAY_TIMEOUT
            payload = _public_error_payload("请求米家服务超时，请稍后重试", "upstream_timeout")
        client_ip = getattr(request.state, "client_ip", _get_request_identity(request, config))
        queue_wait_ms = getattr(request.state, "queue_wait_ms", 0)
        logger.warning(
            "API业务异常 type=%s path=%s status=%s ip=%s queue_wait_ms=%s",
            type(exc).__name__,
            request.url.path,
            status_code,
            client_ip,
            queue_wait_ms,
        )
        return JSONResponse(status_code=status_code, content=payload)

    app.add_exception_handler(LoginError, business_exception_handler)
    app.add_exception_handler(APIError, business_exception_handler)
    app.add_exception_handler(DeviceGetError, business_exception_handler)
    app.add_exception_handler(DeviceSetError, business_exception_handler)
    app.add_exception_handler(DeviceActionError, business_exception_handler)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        client_ip = getattr(request.state, "client_ip", _get_request_identity(request, config))
        queue_wait_ms = getattr(request.state, "queue_wait_ms", 0)
        logger.exception("API Server 未处理异常 ip=%s path=%s queue_wait_ms=%s", client_ip, request.url.path, queue_wait_ms)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_public_error_payload("服务器内部错误，请稍后重试", "internal_error"),
        )

    @app.get("/api/health")
    async def health():
        return {
            "ok": True,
            "mode": "api-only",
            "max_concurrent_requests": config.max_concurrent_requests,
            "thread_pool_tokens": max(40, config.thread_pool_tokens),
        }

    @app.get("/api/app")
    def app_info(
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
    ):
        url = "https://new.yxinstu.cn/api.php?id=app"
        timeout = float(os.getenv("MIJIA_APP_PROXY_TIMEOUT", "10"))
        try:
            upstream = requests.get(url, timeout=timeout)
        except requests.exceptions.Timeout:
            raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="上游请求超时") from None
        except requests.exceptions.RequestException as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"上游请求失败: {exc}") from None
        content_type = upstream.headers.get("content-type", "application/json")
        media_type = content_type.split(";", 1)[0].strip() if content_type else "application/octet-stream"
        return Response(content=upstream.content, status_code=upstream.status_code, media_type=media_type)

    @app.post("/api/login/start")
    def login_start(
        request: Request,
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
        ___: None = Depends(enforce_login_rate_limit),
    ):
        return store.start_login(request.state.client_ip)

    @app.get("/api/login/status")
    def login_status(
        request: Request,
        session_id: str,
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
    ):
        return store.get_login_status(session_id, request.state.client_ip)

    @app.get("/api/login/qr.png")
    def login_qr_png(
        request: Request,
        session_id: str,
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
    ):
        content = store.get_login_qr_png(session_id, request.state.client_ip)
        return Response(
            content=content,
            media_type="image/png",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/login/qr.i1")
    def login_qr_i1(
        request: Request,
        session_id: str,
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
    ):
        content = store.get_login_qr_i1(session_id, request.state.client_ip)
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/login/qr.rgb565")
    def login_qr_rgb565(
        request: Request,
        session_id: str,
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
    ):
        content = store.get_login_qr_rgb565(session_id, request.state.client_ip)
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/login/claim")
    def login_claim(
        request: Request,
        payload: LoginClaimPayload,
        _: None = Depends(request_slot),
        __: None = Depends(enforce_public_rate_limit),
    ):
        return store.claim_login_token(payload.session_id, payload.claim_secret, request.state.client_ip)

    @app.get("/api/session")
    def session_status(
        token: str = Depends(get_token),
        session: ManagedSession = Depends(enforce_read_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "session_status"):
            meta = session.read_meta()
            available = False
            if session.is_unlocked:
                try:
                    available = session.load_api().available
                except HTTPException:
                    available = False
            return {
                "authenticated": available,
                "token_hash": session.token_hash,
                "created_at": meta.get("created_at"),
                "last_seen_at": meta.get("last_seen_at"),
                "token_issued_at": meta.get("token_issued_at"),
                "token_expires_at": meta.get("token_expires_at"),
                "token_revoked_at": meta.get("token_revoked_at"),
                "vault_configured": bool(meta.get("vault_configured")),
                "unlocked": session.is_unlocked,
                "requires_password_setup": not bool(meta.get("vault_configured")),
                "pending_setup_in_memory": session.has_pending_auth_data,
                "vault_updated_at": meta.get("vault_updated_at"),
            }

    @app.post("/api/session/set_vault_password")
    def set_vault_password(
        payload: VaultPasswordPayload,
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        _validate_vault_password(payload.password)
        with _timed_session_lock(session, "set_vault_password"):
            session.set_vault_password(payload.password)
            return {
                "vault_configured": True,
                "unlocked": True,
            }

    @app.post("/api/session/change_vault_password")
    def change_vault_password(
        payload: ChangeVaultPasswordPayload,
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        _validate_vault_password(payload.old_password)
        _validate_vault_password(payload.new_password)
        with _timed_session_lock(session, "change_vault_password"):
            unlocked = session.change_vault_password(payload.old_password, payload.new_password)
            return {
                "vault_configured": True,
                "unlocked": unlocked,
            }

    @app.post("/api/session/unlock")
    def session_unlock(
        payload: VaultPasswordPayload,
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        _validate_vault_password(payload.password)
        with _timed_session_lock(session, "session_unlock"):
            session.unlock(payload.password)
            return {
                "vault_configured": True,
                "unlocked": True,
            }

    @app.post("/api/session/lock")
    def session_lock(
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "session_lock"):
            session.lock_session()
            return {
                "locked": True,
            }

    @app.delete("/api/session")
    def session_clear(
        token: str = Depends(get_token),
        _: None = Depends(request_slot),
        __: ManagedSession = Depends(enforce_write_rate_limit),
    ):
        return store.clear_session(token)

    @app.get("/api/devices")
    def devices(
        session: ManagedSession = Depends(enforce_read_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "devices"):
            api = session.load_api()
            homes = session.get_cached_home_name_map(api)
            devices_list = session.get_cached_devices_list(api)
            return {
                "devices": [
                    {
                        "did": item["did"],
                        "name": item.get("name", item["did"]),
                        "model": item.get("model", ""),
                        "home_id": item.get("home_id", ""),
                        "home_name": homes.get(item.get("home_id", ""), "共享设备" if item.get("home_id") == "shared" else ""),
                        "isOnline": bool(item.get("isOnline", False)),
                    }
                    for item in devices_list
                ]
            }

    @app.get("/api/scenes")
    def scenes(
        session: ManagedSession = Depends(enforce_read_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "scenes"):
            api = session.load_api()
            homes = session.get_cached_home_name_map(api)
            scenes_list = session.get_cached_scenes_list(api)
            return {
                "scenes": [
                    {
                        "scene_id": item["scene_id"],
                        "name": item["name"],
                        "home_id": item["home_id"],
                        "home_name": homes.get(item["home_id"], ""),
                    }
                    for item in scenes_list
                ]
            }

    @app.get("/api/device/detail")
    def device_detail(
        did: str,
        session: ManagedSession = Depends(enforce_read_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "device_detail"):
            return {"device": get_device_detail_cached(session, did)}

    @app.get("/api/sync")
    def family_sync(
        session: ManagedSession = Depends(enforce_read_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "family_sync"):
            snapshot, revision = session.get_recent_sync_snapshot()
            if snapshot is None:
                snapshot = build_family_snapshot(session)
                revision, _ = session.update_sync_state(snapshot)
            snapshot["sync_revision"] = revision
            return snapshot

    @app.get("/api/sync/changes")
    def family_sync_changes(
        after: int = 0,
        timeout: int = 8,
        session: ManagedSession = Depends(enforce_read_rate_limit),
        _: None = Depends(request_slot),
    ):
        timeout = max(1, min(10, timeout))
        if not session.is_unlocked:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="当前会话已锁定，请先解锁",
            )
        deadline = time.monotonic() + timeout
        stale = False

        revision, event, resync_required = session.get_sync_event_after(max(0, after))
        if resync_required:
            return {
                "base_revision": max(0, after),
                # A restarted worker has a fresh local revision counter.  The
                # client discards this response and immediately requests a
                # snapshot, so keep the handshake monotonic for older panels.
                "revision": max(revision, max(0, after)),
                "server_revision": revision,
                "generated_at": int(time.time()),
                "resync_required": True,
                "changes": [],
                "timed_out": False,
                "stale": False,
            }
        if event is not None:
            return {**event, "timed_out": False, "stale": False}

        while time.monotonic() < deadline:
            try:
                with _timed_session_lock(session, "family_sync_changes"):
                    snapshot = build_family_snapshot(session)
                revision, event = session.update_sync_state(snapshot)
                if event is not None:
                    return {**event, "timed_out": False, "stale": False}
            except HTTPException:
                raise
            except Exception as exc:
                stale = True
                logger.warning("增量同步探测失败 error=%s", type(exc).__name__)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(sync_poll_seconds, remaining))

        revision, event, resync_required = session.get_sync_event_after(max(0, after))
        if event is not None:
            return {**event, "timed_out": False, "stale": stale}
        return {
            "base_revision": max(0, after),
            "revision": max(revision, max(0, after))
                        if resync_required else revision,
            "server_revision": revision,
            "generated_at": int(time.time()),
            "resync_required": resync_required,
            "changes": [],
            "timed_out": True,
            "stale": stale,
        }

    @app.post("/api/device/property")
    def set_device_property(
        payload: DevicePropertyPayload,
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "set_device_property"):
            api = session.load_api()
            devices_list = session.get_cached_devices_list(api)
            target = next((item for item in devices_list if item["did"] == payload.did), None)
            if target is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="设备不存在")
            info = get_device_info(target["model"], cache_backend=session.device_spec_cache)
            device = mijiaDevice(
                api,
                did=payload.did,
                device_meta=target,
                device_info=info,
                sleep_time=0.0,
            )
            prop_name = payload.prop_name
            prop = device.prop_list.get(prop_name)
            if prop is None and payload.siid is not None and payload.piid is not None:
                match = next(
                    (
                        (name, candidate)
                        for name, candidate in device.prop_list.items()
                        if candidate.method.get("siid") == payload.siid
                        and candidate.method.get("piid") == payload.piid
                    ),
                    None,
                )
                if match is not None:
                    prop_name, prop = match
            if prop is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="设备不支持该属性",
                )
            result = device.set(prop_name, payload.value)
            code = int(result.get("code", 0))
            accepted = code in (0, 1)
            confirmed = False
            current_value: Any = None
            confirmation = "rpc-rejected"
            deadline = time.monotonic() + PROPERTY_CONFIRM_TIMEOUT_SECONDS

            if accepted and "r" in prop.rw:
                confirmation = "readback-timeout"
                while time.monotonic() < deadline:
                    try:
                        current_value = device.get(prop_name)
                        if current_value == payload.value:
                            confirmed = True
                            confirmation = "cloud-readback"
                            break
                    except (DeviceGetError, APIError):
                        pass
                    time.sleep(PROPERTY_CONFIRM_INTERVAL_SECONDS)
            elif accepted:
                confirmation = "rpc-only"

            session.invalidate_runtime_cache(f"device_detail:{payload.did}")
            session.invalidate_sync_snapshot()
            return {
                "did": payload.did,
                "prop_name": prop_name,
                "value": payload.value,
                "method": "set_properties",
                "siid": prop.method["siid"],
                "piid": prop.method["piid"],
                "code": code,
                "accepted": accepted,
                "confirmed": confirmed,
                "current_value": current_value,
                "confirmation": confirmation,
            }

    @app.post("/api/device/action")
    def run_device_action(
        payload: DeviceActionPayload,
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "run_device_action"):
            api = session.load_api()
            devices_list = session.get_cached_devices_list(api)
            target = next((item for item in devices_list if item["did"] == payload.did), None)
            if target is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="设备不存在")
            info = get_device_info(target["model"], cache_backend=session.device_spec_cache)
            device = mijiaDevice(
                api,
                did=payload.did,
                device_meta=target,
                device_info=info,
                sleep_time=0.0,
            )
            result = device.run_action(
                payload.action_name,
                _in=list(payload.arguments),
            )
            code = int(result.get("code", 0))
            session.invalidate_runtime_cache(f"device_detail:{payload.did}")
            session.invalidate_sync_snapshot()
            return {
                "did": payload.did,
                "action_name": payload.action_name,
                "method": "action",
                "code": code,
                "accepted": code in (0, 1),
                "confirmed": code == 0,
            }

    @app.post("/api/scenes/run")
    def run_scene(
        payload: SceneRunPayload,
        session: ManagedSession = Depends(enforce_write_rate_limit),
        _: None = Depends(request_slot),
    ):
        with _timed_session_lock(session, "run_scene"):
            api = session.load_api()
            scenes_list = session.get_cached_scenes_list(api)
            target = next((item for item in scenes_list if item["scene_id"] == payload.scene_id), None)
            if target is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="场景不存在")
            result = api.run_scene(target["scene_id"], target["home_id"])
            session.invalidate_runtime_cache()
            session.invalidate_sync_snapshot()
            return {
                "scene_id": target["scene_id"],
                "name": target["name"],
                "result": result,
                "method": "run_scene",
                "accepted": True,
            }

    return app


def create_app_from_env() -> FastAPI:
    allowed_hosts_env = os.getenv("MIJIA_ALLOWED_HOSTS", "*")
    config = ServerConfig(
        state_dir=Path(os.getenv("MIJIA_STATE_DIR", str(get_default_auth_path().parent.parent / ".mijia-server"))),
        request_timeout=float(os.getenv("MIJIA_REQUEST_TIMEOUT", "10")),
        login_timeout=float(os.getenv("MIJIA_LOGIN_TIMEOUT", "180")),
        max_retries=int(os.getenv("MIJIA_REQUEST_RETRIES", "2")),
        retry_delay=float(os.getenv("MIJIA_REQUEST_RETRY_DELAY", "0.5")),
        login_task_ttl=int(os.getenv("MIJIA_LOGIN_TASK_TTL", "300")),
        max_concurrent_requests=int(os.getenv("MIJIA_MAX_CONCURRENCY", "1000")),
        acquire_timeout=float(os.getenv("MIJIA_ACQUIRE_TIMEOUT", "5")),
        keepalive_timeout=int(os.getenv("MIJIA_KEEPALIVE_TIMEOUT", "20")),
        workers=int(os.getenv("MIJIA_API_WORKERS", "1")),
        allowed_hosts=_parse_csv_tuple(allowed_hosts_env),
        local_token_ttl_seconds=int(os.getenv("MIJIA_LOCAL_TOKEN_TTL_SECONDS", str(30 * 24 * 3600))),
        max_active_login_tasks=int(os.getenv("MIJIA_MAX_ACTIVE_LOGIN_TASKS", "8")),
        allow_remote_login=_env_truthy(os.getenv("MIJIA_ALLOW_REMOTE_LOGIN", "1")),
        trust_proxy_headers=_env_truthy(os.getenv("MIJIA_TRUST_PROXY_HEADERS", "0")),
        trusted_proxy_hosts=_parse_csv_tuple(os.getenv("MIJIA_TRUSTED_PROXY_HOSTS", "127.0.0.1,::1")),
        thread_pool_tokens=int(os.getenv("MIJIA_THREADPOOL_TOKENS", "128")),
    )
    return create_app(config)


def run_api_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8123,
    state_dir: Optional[Path] = None,
    workers: int = 1,
    max_concurrent_requests: int = 1000,
) -> None:
    if state_dir is None:
        state_dir = get_default_auth_path().parent.parent / ".mijia-server"
    if workers != 1:
        raise ValueError("当前零知识会话模型仅支持单 worker 运行，请将 --workers 设置为 1")
    os.environ["MIJIA_STATE_DIR"] = str(Path(state_dir))
    os.environ["MIJIA_API_WORKERS"] = str(workers)
    os.environ["MIJIA_MAX_CONCURRENCY"] = str(max_concurrent_requests)
    logger.info("Mijia API Server 已启动: http://%s:%s", host, port)
    logger.info("状态目录: %s", os.environ["MIJIA_STATE_DIR"])
    uvicorn.run(
        "mijiaAPI.api_server:create_app_from_env",
        factory=True,
        host=host,
        port=port,
        workers=workers,
        timeout_keep_alive=int(os.getenv("MIJIA_KEEPALIVE_TIMEOUT", "20")),
        limit_concurrency=max_concurrent_requests,
        backlog=2048,
        server_header=False,
        date_header=False,
    )
