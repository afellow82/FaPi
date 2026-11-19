#!/usr/bin/env python3
"""FaPi Highscore API: JSON-backed score lists with Cloudflare Access admin protection."""
from __future__ import annotations

import fcntl
import json
import logging
import math
import os
import re
import shutil
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from threading import Lock
from typing import Any, Iterator

import jwt
from flask import Flask, jsonify, make_response, request
from jwt import PyJWKClient

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("FAPI_DATA_DIR", "/var/lib/fapi-highscores"))
DATA_FILE = DATA_DIR / "highscores.json"
LOCK_FILE = DATA_DIR / "highscores.lock"
BACKUP_DIR = DATA_DIR / "backups"
MAX_BACKUPS = 30
MAX_NAME_LENGTH = 20
MAX_TIME_MS = 7 * 24 * 60 * 60 * 1000

IMAGE_IDS = (
    "rainbow", "christmas", "flowers", "hearts", "abstract", "vfb",
    "waterpolo", "coast", "duesseldorf", "recorder", "toronto", "parrot",
    "mandala", "neubrandenburg", "zingst",
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fapi-highscores")
_jwks_clients: dict[str, PyJWKClient] = {}
_jwks_lock = Lock()


class StorageError(RuntimeError):
    pass


def empty_data() -> dict[str, list[dict[str, Any]]]:
    return {image_id: [] for image_id in IMAGE_IDS}


@contextmanager
def data_lock(exclusive: bool) -> Iterator[None]:
    """Cross-process lock shared by reads and exclusive for mutations."""
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    fd = os.open(LOCK_FILE, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_write(data: dict[str, list[dict[str, Any]]]) -> None:
    """Write JSON to a same-directory temp file, fsync, then atomically replace."""
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".highscores-", suffix=".tmp", dir=DATA_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, DATA_FILE)
        dir_fd = os.open(DATA_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def read_data_unlocked() -> dict[str, list[dict[str, Any]]]:
    if not DATA_FILE.exists():
        data = empty_data()
        atomic_write(data)
        return data

    try:
        with DATA_FILE.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageError("Die Highscore-Datei kann nicht gelesen werden.") from exc

    if not isinstance(raw, dict):
        raise StorageError("Die Highscore-Datei hat eine ungültige Struktur.")
    unknown = set(raw) - set(IMAGE_IDS)
    if unknown:
        raise StorageError("Die Highscore-Datei enthält unbekannte Bildkennungen.")

    data: dict[str, list[dict[str, Any]]] = {}
    for image_id in IMAGE_IDS:
        entries = raw.get(image_id, [])
        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            raise StorageError(f"Die Highscore-Liste für {image_id} ist beschädigt.")
        data[image_id] = entries
    return data


def backup_data_unlocked() -> str:
    """Create and sync a private backup before a destructive operation."""
    if not DATA_FILE.exists():
        atomic_write(empty_data())
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_name = f"highscores-{stamp}.json"
    backup_path = BACKUP_DIR / backup_name
    shutil.copyfile(DATA_FILE, backup_path)
    os.chmod(backup_path, 0o600)
    with backup_path.open("rb") as handle:
        os.fsync(handle.fileno())

    backups = sorted(BACKUP_DIR.glob("highscores-*.json"), key=lambda p: p.name, reverse=True)
    for old_backup in backups[MAX_BACKUPS:]:
        old_backup.unlink(missing_ok=True)
    return backup_name


def get_access_admin_claims() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    """Fail closed unless a valid Cloudflare Access JWT matches configured AUD and admin email."""
    team_domain = os.environ.get("FAPI_ACCESS_TEAM_DOMAIN", "").strip().rstrip("/")
    audience = os.environ.get("FAPI_ACCESS_AUD", "").strip()
    admin_emails = {
        item.strip().casefold()
        for item in os.environ.get("FAPI_ADMIN_EMAILS", "").split(",")
        if item.strip()
    }
    if not team_domain or not audience or not admin_emails:
        return None, (jsonify(error="admin_auth_not_configured"), 503)
    if not team_domain.startswith("https://"):
        return None, (jsonify(error="invalid_admin_auth_configuration"), 503)

    token = request.headers.get("Cf-Access-Jwt-Assertion", "").strip()
    if not token:
        return None, (jsonify(error="admin_auth_required"), 401)

    jwks_url = f"{team_domain}/cdn-cgi/access/certs"
    try:
        with _jwks_lock:
            client = _jwks_clients.get(jwks_url)
            if client is None:
                client = PyJWKClient(jwks_url, cache_keys=True)
                _jwks_clients[jwks_url] = client
        signing_key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=team_domain,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except (jwt.PyJWTError, Exception) as exc:
        # Do not disclose token-validation details to callers.
        log.info("Cloudflare Access admin token rejected: %s", type(exc).__name__)
        return None, (jsonify(error="admin_auth_invalid"), 403)

    email = str(claims.get("email", "")).strip().casefold()
    if not email or email not in admin_emails:
        return None, (jsonify(error="admin_not_authorized"), 403)
    return claims, None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        claims, denied = get_access_admin_claims()
        if denied is not None:
            return denied
        request.admin_claims = claims  # type: ignore[attr-defined]
        return view(*args, **kwargs)
    return wrapped


def json_error(message: str, status: int):
    response = jsonify(error=message)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 4096

    # Initialize an empty file if needed, without overwriting an existing one.
    with data_lock(exclusive=True):
        read_data_unlocked()

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", service="fapi-highscores")

    @app.get("/api/highscores")
    def get_highscores():
        try:
            with data_lock(exclusive=False):
                data = read_data_unlocked()
            response = make_response(jsonify(highscores=data))
            response.headers["Cache-Control"] = "no-store"
            return response
        except StorageError:
            log.exception("Could not read highscore data")
            return json_error("highscore_storage_unavailable", 500)

    @app.get("/api/admin/check")
    @admin_required
    def admin_check():
        response = make_response(jsonify(ok=True, authenticated=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/highscores")
    def submit_highscore():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return json_error("invalid_json", 400)

        image_id = payload.get("image")
        if not isinstance(image_id, str) or image_id not in IMAGE_IDS:
            return json_error("invalid_image", 400)

        raw_score = payload.get("score")
        if isinstance(raw_score, bool) or not isinstance(raw_score, int) or abs(raw_score) > 1_000_000_000:
            return json_error("invalid_score", 400)

        raw_time = payload.get("timeMs")
        if isinstance(raw_time, bool) or not isinstance(raw_time, (int, float)):
            return json_error("invalid_time", 400)
        if not math.isfinite(float(raw_time)) or raw_time < 0 or raw_time > MAX_TIME_MS:
            return json_error("invalid_time", 400)

        raw_name = payload.get("name", "")
        if not isinstance(raw_name, str):
            return json_error("invalid_name", 400)
        # Collapse whitespace and remove control characters; keep <ohne Name> unchanged.
        name = re.sub(r"[\x00-\x1f\x7f]", "", raw_name)
        name = " ".join(name.split())[:MAX_NAME_LENGTH] or "<ohne Name>"

        entry = {
            "id": uuid.uuid4().hex,
            "name": name,
            "score": raw_score,
            "timeMs": round(float(raw_time), 1),
            "timestamp": int(time.time() * 1000),
        }

        try:
            with data_lock(exclusive=True):
                data = read_data_unlocked()
                ranked = list(data[image_id]) + [entry]
                ranked.sort(
                    key=lambda item: (
                        -int(item.get("score", 0)),
                        float(item.get("timeMs", 0)),
                        int(item.get("timestamp", 0)),
                    )
                )
                rank = next(index + 1 for index, item in enumerate(ranked) if item.get("id") == entry["id"])
                if rank > 10:
                    return json_error("not_in_top_10", 409)
                data[image_id] = ranked[:10]
                atomic_write(data)
            response = jsonify(ok=True, rank=rank, entry=entry, entries=data[image_id])
            response.headers["Cache-Control"] = "no-store"
            return response, 201
        except (StorageError, OSError, ValueError, TypeError):
            log.exception("Could not save highscore")
            return json_error("highscore_storage_unavailable", 500)

    @app.delete("/api/admin/highscores/<image_id>")
    @admin_required
    def delete_image_highscores(image_id: str):
        if image_id not in IMAGE_IDS:
            return json_error("invalid_image", 404)
        try:
            with data_lock(exclusive=True):
                data = read_data_unlocked()
                backup_name = backup_data_unlocked()
                deleted_count = len(data[image_id])
                data[image_id] = []
                atomic_write(data)
            return jsonify(ok=True, image=image_id, deleted=deleted_count, backup=backup_name)
        except (StorageError, OSError):
            log.exception("Could not delete image highscore list")
            return json_error("highscore_storage_unavailable", 500)

    @app.delete("/api/admin/highscores")
    @admin_required
    def delete_all_highscores():
        try:
            with data_lock(exclusive=True):
                data = read_data_unlocked()
                backup_name = backup_data_unlocked()
                deleted_count = sum(len(entries) for entries in data.values())
                data = empty_data()
                atomic_write(data)
            return jsonify(ok=True, deleted=deleted_count, backup=backup_name)
        except (StorageError, OSError):
            log.exception("Could not delete all highscores")
            return json_error("highscore_storage_unavailable", 500)

    @app.errorhandler(413)
    def request_too_large(_error):
        return json_error("request_too_large", 413)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8002)
