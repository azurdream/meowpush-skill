#!/usr/bin/env python3
"""Send MeowPush notifications and manage application authorization safely."""

from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import UUID, uuid4

from secure_store import SecureStore, StoreError


SEND_URL = "https://send.meowpush.com/"
AUTH_URL = "https://accounts.meowpush.com/api/v1/application-authorization-requests"
CREDENTIALS = "pk-credentials.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
TRANSPORTS = {"apns", "fcm", "hms", "wns", "unifiedpush"}
FAILURE_REASONS = {
    "unknown_key", "unregistered", "payload_too_large", "quota_exceeded",
    "target_ineligible", "rejected", "platform_unsupported", "upstream_unavailable", "internal",
}
ERROR_CODES = FAILURE_REASONS | {
    "invalid_request", "not_found", "rate_limited", "target_limit_exceeded",
    "application_authorization_request_not_found",
    "application_authorization_delivery_expired",
    "application_authorization_invalidated",
    "application_authorization_request_expired",
    "application_authorization_delivery_invalidated",
    "invalid_application_reauthorization_token", "service_unavailable",
}


class AppError(Exception):
    """An explicitly safe message: never construct it from external values."""

    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.message, self.exit_code = code, message, exit_code


@dataclass
class HTTPResponse:
    status: int
    headers: dict
    data: object


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON value")


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=_reject_constant)


def request_json(method, url, *, payload=None, bearer=None):
    """One verified HTTPS request. Do not retry, follow redirects, or log bodies."""
    if not (url == SEND_URL or url == AUTH_URL or
            re.fullmatch(re.escape(AUTH_URL) + r"/[A-Za-z0-9_-]{1,128}/result", url)):
        raise AppError("invalid_endpoint", "Only official MeowPush API endpoints are supported.")
    headers = {"Accept": "application/json", "User-Agent": "meowpush-skill/1"}
    if bearer is not None:
        if not isinstance(bearer, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", bearer):
            raise AppError("invalid_credential", "The local authorization credential is invalid.")
        headers["Authorization"] = "Bearer " + bearer
    body = None
    if payload is not None:
        try:
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, UnicodeError):
            raise AppError("invalid_json", "The request must contain valid UTF-8 JSON.") from None
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers, method=method)
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=30)
        except HTTPError as exc:
            response = exc
        with response:
            status = response.code
            response_headers = dict(response.headers.items())
            raw = response.read(MAX_JSON_BYTES + 1)
        data = None
        if len(raw) <= MAX_JSON_BYTES:
            try:
                data = parse_json(raw.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                pass
        return HTTPResponse(status, response_headers, data)
    except (URLError, OSError, TimeoutError, ValueError, HTTPException, EOFError):
        raise AppError("network_error", "The API request could not be completed. Its outcome may be unknown; do not automatically retry.", 3) from None


def config_directory():
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if not base or not Path(base).is_absolute():
            raise AppError("missing_appdata", "An absolute APPDATA directory is required on Windows.")
        return Path(base) / "MeowPush"
    base = os.environ.get("XDG_CONFIG_HOME")
    if base and not Path(base).is_absolute():
        raise AppError("invalid_config_path", "XDG_CONFIG_HOME must be an absolute directory.")
    return (Path(base) if base else Path.home() / ".config") / "meowpush"


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def profile_name(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or value.strip() != value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise AppError("invalid_profile", "Profile names must be nonempty, at most 64 characters, and contain no control characters.")
    return value


def key_type(value):
    if not isinstance(value, str) or not re.fullmatch(r"mp(?:dv|gp|ap)[a-z0-9]{1,128}", value):
        raise AppError("invalid_profile", "The selected profile does not contain a valid Push Key.")
    return {"mpdv": "device", "mpgp": "group", "mpap": "application"}[value[:4]]


def valid_uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Missing time zone")
    return dt.timestamp()


def safe_time(value):
    try:
        return datetime.fromtimestamp(timestamp(value), timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def interval(value):
    if not integer(value, 1):
        raise AppError("invalid_response", "The API returned an invalid query interval.", 3)
    return value


def profile_fingerprint(value):
    if value is None:
        return None
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def validate_config(config):
    if not isinstance(config, dict) or type(config.get("version")) is not int or config["version"] != 1 or not isinstance(config.get("profiles"), dict):
        raise AppError("invalid_config", "The credential file must use the version 1 named-profile schema.")
    for name, profile in config["profiles"].items():
        profile_name(name)
        if not isinstance(profile, dict):
            raise AppError("invalid_config", "A stored profile is not a JSON object.")
        key_type(profile.get("push_key"))
    default = config.get("default_profile")
    if default is not None:
        profile_name(default)
        if default not in config["profiles"]:
            raise AppError("invalid_config", "The default profile does not exist. The credential file was not changed.")
    return config


def retry_seconds(headers, now):
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[0-9]{1,9}", value):
        return int(value)
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is not None:
            return max(0, math.ceil(dt.timestamp() - now))
    except (ValueError, OverflowError, TypeError):
        pass
    return None


def error_summary(response, now):
    data = response.data
    code = data.get("error", {}).get("code") if isinstance(data, dict) and isinstance(data.get("error"), dict) else None
    out = {"ok": False, "status": "api_error", "http_status": response.status,
           "error": code if isinstance(code, str) and code in ERROR_CODES else "api_error",
           "message": "The API did not complete the requested operation. No automatic retry was made."}
    delay = retry_seconds(response.headers, now)
    if delay is not None:
        out["retry_after_seconds"] = delay
    if 300 <= response.status < 400:
        out.update(error="redirect_blocked", message="The API returned a redirect, which was not followed.")
    return out


def validate_metadata(metadata, mode):
    if not isinstance(metadata, dict) or set(metadata) - {"name", "description", "icon_url"}:
        raise AppError("invalid_metadata", "Metadata must be an object containing only name, description, and icon_url.")
    if mode == "create" or "name" in metadata:
        name = metadata.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
            raise AppError("invalid_metadata", "Application name must contain 1 to 64 characters.")
    if "description" in metadata and metadata["description"] is not None:
        if not isinstance(metadata["description"], str) or len(metadata["description"]) > 1024:
            raise AppError("invalid_metadata", "Application description must be a string of at most 1024 characters.")
    icon = metadata.get("icon_url")
    if icon is not None:
        try:
            if not isinstance(icon, str):
                raise ValueError("Invalid URL")
            parsed = urlsplit(icon)
            valid = parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and len(icon.encode()) <= 2048
        except (TypeError, ValueError, UnicodeError):
            valid = False
        if not valid:
            raise AppError("invalid_metadata", "Application icon must be a public HTTPS URL without embedded credentials.")
    return metadata.copy()


class MeowPush:
    def __init__(self, store, transport=request_json, clock=time.time):
        self.store, self.transport, self.clock = store, transport, clock

    def _config(self):
        value = self.store.read_json(CREDENTIALS)
        return validate_config(value) if value is not None else None

    def profiles(self):
        config = self._config()
        return {"ok": True, "status": "configured" if config and config["profiles"] else "not_configured",
                "credentials_file": str(self.store.directory / CREDENTIALS),
                "default_profile": config.get("default_profile") if config else None,
                "profiles": [{"name": name, "key_type": key_type(value["push_key"])}
                             for name, value in (config["profiles"].items() if config else [])]}

    def _select(self, config, name):
        if config is None:
            raise AppError("not_configured", "No credential file is configured. Start application authorization first.")
        chosen = profile_name(name) if name is not None else config.get("default_profile")
        if chosen is None:
            raise AppError("profile_required", "No default profile is configured. Select a named profile explicitly.")
        if chosen not in config["profiles"]:
            raise AppError("profile_not_found", "The selected profile does not exist. No other profile was used.")
        return chosen, config["profiles"][chosen]

    def auth_start(self, profile, metadata, mode="create", replace=False):
        profile_name(profile)
        if mode not in {"create", "reauthorize"}:
            raise AppError("invalid_mode", "Authorization mode must be create or reauthorize.")
        metadata = validate_metadata(metadata, mode)
        self.store.ensure()
        with self.store.lock():
            config = self._config()
            previous = config["profiles"].get(profile) if config else None
            if previous is not None and not replace:
                raise AppError("replacement_confirmation_required", "Confirm replacement of this profile with the user before passing --replace.")
            bearer = None
            payload = {"mode": mode, "metadata": metadata}
            if mode == "reauthorize":
                if previous is None or key_type(previous["push_key"]) != "application" or not valid_uuid(previous.get("application_id")) or not isinstance(previous.get("reauthorization_token"), str):
                    raise AppError("reauthorization_unavailable", "This profile has no usable application reauthorization credentials.")
                bearer = previous["reauthorization_token"]
                payload["application_id"] = previous["application_id"]
            state_id = uuid4().hex
            state_file = "authorization-" + state_id + ".json"
            state = {"version": 1, "profile": profile, "mode": mode, "metadata": metadata,
                     "previous_profile_hash": profile_fingerprint(previous)}
            if mode == "reauthorize":
                state["application_id"] = previous["application_id"]
            # Verify protected writes before creating a remote request.
            self.store.write_json(state_file, state)
            try:
                response = self.transport("POST", AUTH_URL, payload=payload, bearer=bearer)
                if response.status != 201:
                    self.store.remove(state_file)
                    return error_summary(response, self.clock())
                data = response.data
                if not isinstance(data, dict):
                    raise ValueError("Invalid response")
                request_id, secret = data.get("request_id"), data.get("poll_secret")
                if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id) or not isinstance(secret, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", secret):
                    raise ValueError("Invalid authorization credentials")
                invitation = data.get("authorization_url")
                parsed = urlsplit(invitation) if isinstance(invitation, str) else None
                if not parsed or parsed.scheme != "https" or parsed.netloc != "accounts.meowpush.com" or parsed.path != "/new-app" or parsed.fragment or parse_qs(parsed.query) != {"rid": [request_id]}:
                    raise ValueError("Invalid invitation")
                expiry = data.get("expires_at")
                if timestamp(expiry) <= self.clock():
                    raise ValueError("Expired request")
                state.update(request_id=request_id, poll_secret=secret, expires_at=expiry,
                             poll_interval_seconds=interval(data.get("poll_interval_seconds")),
                             next_query_at=self.clock())
                self.store.write_json(state_file, state)
            except (ValueError, TypeError, OverflowError):
                self.store.remove(state_file)
                raise AppError("invalid_response", "The API returned an invalid authorization response. Setup is incomplete.", 3) from None
            except AppError:
                self.store.remove(state_file)
                raise
            return {"ok": True, "status": "awaiting_user", "state_id": state_id,
                    "authorization_url": invitation, "profile": profile,
                    "application_name": metadata.get("name"), "expires_at": safe_time(expiry),
                    "message": "Ask the user to approve this invitation and reply before querying the result."}

    def auth_finish(self, state_id, user_confirmed=False):
        if not user_confirmed:
            raise AppError("user_confirmation_required", "Wait for the user's reply after authorization before querying the result.")
        if not isinstance(state_id, str) or not re.fullmatch(r"[a-f0-9]{32}", state_id):
            raise AppError("invalid_state", "Use the state_id returned by auth start.")
        state_file = "authorization-" + state_id + ".json"
        self.store.ensure()
        with self.store.lock():
            state = self.store.read_json(state_file)
            if state is None:
                raise AppError("state_not_found", "No pending authorization exists for this state_id.")
            if state.get("version") != 1 or state.get("mode") not in {"create", "reauthorize"} or not isinstance(state.get("request_id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", state["request_id"]) or not isinstance(state.get("poll_secret"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", state["poll_secret"]):
                raise AppError("invalid_state", "The authorization state is incomplete or invalid. It was not changed.")
            profile = profile_name(state.get("profile"))
            delay = interval(state.get("poll_interval_seconds"))
            next_query = state.get("next_query_at", 0)
            if type(next_query) not in (int, float) or not math.isfinite(next_query):
                raise AppError("invalid_state", "The authorization query deadline is invalid.")
            if self.clock() < next_query:
                return {"ok": False, "status": "query_too_soon", "state_id": state_id,
                        "retry_after_seconds": math.ceil(next_query - self.clock())}
            # Persist the interval before the GET so crashes and network failures cannot poll rapidly.
            state["next_query_at"] = self.clock() + delay
            self.store.write_json(state_file, state)
            response = self.transport("GET", AUTH_URL + "/" + state["request_id"] + "/result", bearer=state["poll_secret"])
            if response.status != 200:
                summary = error_summary(response, self.clock())
                summary["state_id"] = state_id
                if response.status in {404, 410}:
                    self.store.remove(state_file)
                    summary["state_removed"] = True
                elif response.status == 429:
                    state["next_query_at"] = self.clock() + max(delay, summary.get("retry_after_seconds", delay))
                    self.store.write_json(state_file, state)
                return summary
            data = response.data
            if not isinstance(data, dict) or not isinstance(data.get("status"), str) or data["status"] not in {"pending", "approved", "rejected", "expired", "invalidated"}:
                raise AppError("invalid_response", "The authorization result is invalid. Protected state was retained.", 3)
            status = data["status"]
            if status in {"rejected", "expired", "invalidated"}:
                self.store.remove(state_file)
                return {"ok": False, "status": status, "state_id": state_id, "state_removed": True}
            state["poll_interval_seconds"] = interval(data.get("poll_interval_seconds"))
            state["next_query_at"] = self.clock() + state["poll_interval_seconds"]
            if not safe_time(data.get("expires_at")):
                raise AppError("invalid_response", "The authorization result has no valid deadline. Protected state was retained.", 3)
            state["expires_at"] = data["expires_at"]
            self.store.write_json(state_file, state)
            if status == "pending":
                return {"ok": False, "status": "pending", "state_id": state_id,
                        "message": "Authorization is not complete. Wait for another user confirmation before querying again."}
            result = data.get("result")
            if not isinstance(result, dict) or not valid_uuid(result.get("application_id")) or not integer(result.get("key_version"), 1) or not integer(result.get("connection_version"), 1):
                raise AppError("invalid_response", "The approved credential result is invalid. Protected state was retained.", 3)
            try:
                if key_type(result.get("push_key")) != "application" or timestamp(result.get("expires_at")) <= self.clock() or timestamp(data["expires_at"]) <= self.clock():
                    raise ValueError("Invalid result")
            except (ValueError, TypeError, OverflowError, AppError):
                raise AppError("invalid_response", "The approved credential result is invalid or expired. Protected state was retained.", 3) from None
            if state["mode"] == "reauthorize" and result["application_id"] != state.get("application_id"):
                raise AppError("application_mismatch", "The approved application does not match the selected profile.", 3)
            token = result.get("reauthorization_token")
            if token is not None and (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", token)):
                raise AppError("invalid_response", "The approved reauthorization credential is invalid.", 3)
            config = self._config()
            existing = config["profiles"].get(profile) if config else None
            saved = {key: result[key] for key in ("push_key", "application_id", "key_version", "connection_version")}
            if token is not None:
                saved["reauthorization_token"] = token
            elif existing and existing.get("application_id") == result["application_id"] and existing.get("reauthorization_token"):
                saved["reauthorization_token"] = existing["reauthorization_token"]
            # Allow the exact saved result after a previous read-back failure, but no concurrent overwrite.
            if profile_fingerprint(existing) != state.get("previous_profile_hash") and existing != saved:
                raise AppError("profile_changed", "This profile changed while authorization was pending. It was not overwritten.")
            if config is None:
                config = {"version": 1, "default_profile": profile, "profiles": {}}
            updated = dict(config)
            updated["profiles"] = dict(config["profiles"])
            updated["profiles"][profile] = saved
            self.store.write_json(CREDENTIALS, updated)
            verified = self._config()
            if verified != updated:
                raise AppError("verification_failed", "Credential read-back verification failed. Setup is incomplete; protected state was retained.")
            self.store.remove(state_file)
            metadata = state.get("metadata", {})
            return {"ok": True, "status": "configured", "profile": profile,
                    "application_name": metadata.get("name"),
                    "credentials_file": str(self.store.directory / CREDENTIALS)}

    def send(self, payload, profile=None):
        if not isinstance(payload, dict) or "key" in payload or "keys" in payload:
            raise AppError("invalid_payload", "Provide a JSON message object without key or keys. Credentials are loaded from a profile.")
        if not isinstance(payload.get("body"), str) or not 1 <= len(payload["body"]) <= 4000:
            raise AppError("invalid_payload", "Message body must be a string containing 1 to 4000 characters.")
        chosen, credentials = self._select(self._config(), profile)
        message = dict(payload)
        message["key"] = credentials["push_key"]
        response = self.transport("POST", SEND_URL, payload=message)
        data = response.data
        if not isinstance(data, dict) or not all(integer(data.get(k)) for k in ("accepted", "failed")) or not valid_uuid(data.get("notification_id")) or not isinstance(data.get("results"), list):
            if not 200 <= response.status < 300:
                return error_summary(response, self.clock())
            raise AppError("unknown_outcome", "The send response was invalid. Delivery outcome is unknown; do not automatically resend.", 3)
        results = data["results"]
        if any(not isinstance(item, dict) or not isinstance(item.get("status"), str) or item["status"] not in {"accepted", "failed"} for item in results) or any(sum(item["status"] == status for item in results) != data[count] for status, count in (("accepted", "accepted"), ("failed", "failed"))):
            raise AppError("unknown_outcome", "The send response counts were inconsistent. Delivery outcome is unknown; do not automatically resend.", 3)
        clean_results = []
        for item in results:
            clean = {"status": item["status"]}
            if isinstance(item.get("transport"), str) and item["transport"] in TRANSPORTS:
                clean["transport"] = item["transport"]
            if item.get("status") == "failed":
                reason = item.get("reason")
                clean["reason"] = reason if isinstance(reason, str) and reason in FAILURE_REASONS else "unknown_failure"
                retry_at = safe_time(item.get("retry_at"))
                if retry_at:
                    clean["retry_at"] = retry_at
            clean_results.append(clean)
        success = 200 <= response.status < 300 and data["accepted"] > 0 and data["failed"] == 0
        status = "accepted" if success else "partial_failure" if data["accepted"] > 0 and data["failed"] > 0 else "not_accepted" if data["accepted"] == 0 else "unknown_outcome"
        summary = {"ok": success, "status": status, "profile": chosen,
                   "http_status": response.status, "notification_id": str(UUID(data["notification_id"])),
                   "accepted": data["accepted"], "failed": data["failed"], "results": clean_results,
                   "message": "Acceptance by a push provider does not confirm delivery or display on a device. No automatic retry was made."}
        delay = retry_seconds(response.headers, self.clock())
        if delay is not None:
            summary["retry_after_seconds"] = delay
        return summary


def read_input(path):
    try:
        if path == "-":
            raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
        else:
            with open(path, "rb") as file:
                raw = file.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("Input too large")
        return parse_json(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise AppError("invalid_input", "Input must be readable UTF-8 JSON no larger than 2 MiB, without duplicate fields or non-finite numbers.") from None


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error echoes unrecognized arguments, which might contain a secret.
        raise AppError("invalid_arguments", "Invalid command arguments. Use --help for supported options; never pass credentials as arguments.")


def parser():
    cli = SafeArgumentParser(description=__doc__)
    cli.add_argument("--config-dir", type=Path, help="Use an explicit protected credential directory instead of the per-user default.")
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("profiles", help="List profile names and key types without exposing credentials.")
    auth = commands.add_parser("auth", help="Request or finish user-approved application authorization.")
    stages = auth.add_subparsers(dest="stage", required=True)
    start = stages.add_parser("start", help="Create an authorization invitation and protected local state.")
    start.add_argument("--profile", required=True)
    start.add_argument("--metadata", required=True, help="Metadata JSON file, or - for standard input.")
    start.add_argument("--mode", choices=("create", "reauthorize"), default="create")
    start.add_argument("--replace", action="store_true", help="The user has confirmed replacing this existing profile's credentials.")
    finish = stages.add_parser("finish", help="Query once after the user replies; save and verify approved credentials.")
    finish.add_argument("--state", required=True, help="Non-secret state_id returned by auth start.")
    finish.add_argument("--user-confirmed", action="store_true", help="The user has replied after reviewing the authorization invitation.")
    send = commands.add_parser("send", help="Send one notification using a stored profile.")
    send.add_argument("--profile", help="Exact profile name; omission selects default_profile.")
    send.add_argument("--payload", required=True, help="Message JSON file without keys, or - for standard input.")
    return cli


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        directory = args.config_dir.expanduser().absolute() if args.config_dir is not None else config_directory()
        service = MeowPush(SecureStore(directory))
        if args.command == "profiles":
            result = service.profiles()
        elif args.command == "send":
            result = service.send(read_input(args.payload), args.profile)
        elif args.stage == "start":
            result = service.auth_start(args.profile, read_input(args.metadata), args.mode, args.replace)
        else:
            result = service.auth_finish(args.state, args.user_confirmed)
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        return 0 if result.get("ok") else 1
    except (AppError, StoreError) as exc:
        print(json.dumps({"ok": False, "status": "error", "error": exc.code, "message": exc.message}))
        return getattr(exc, "exit_code", 2)
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "status": "interrupted", "message": "Operation interrupted. Any in-flight request may have an unknown outcome; do not automatically retry."}))
        return 130
    except Exception:
        # HTTP errors can echo requests and responses. Never expose tracebacks to agent tools.
        print(json.dumps({"ok": False, "status": "error", "error": "unexpected_error", "message": "The operation could not be completed safely. Any in-flight request may have an unknown outcome; no automatic retry was made."}))
        return 3


if __name__ == "__main__":
    sys.exit(main())
