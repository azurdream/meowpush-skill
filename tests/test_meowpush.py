"""Runtime contract tests using fake credentials and simulated HTTP only."""

from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
from http.client import IncompleteRead
import json
from pathlib import Path
import subprocess
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, Request


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from meowpush import AppError, HTTPResponse, MeowPush, NoRedirect, request_json  # noqa: E402
from secure_store import SecureStore, StoreError  # noqa: E402


DEVICE_KEY = "mpdv0000000000000001"
GROUP_KEY = "mpgp0000000000000001"
APP_KEY = "mpap00000000000000000000000001"
OTHER_APP_KEY = "mpap00000000000000000000000002"
POLL_SECRET = "B" * 43
REAUTH_TOKEN = "C" * 43
REQUEST_ID = "A" * 43
APPLICATION_ID = "019f1000-0000-7000-8000-000000000017"
NOTIFICATION_ID = "019cf5f1-7f2d-7d18-8be1-6f27e1916b52"
AUTH_URL = "https://accounts.meowpush.com/new-app?rid=" + REQUEST_ID
START_TIME = 1893456000.0  # 2030-01-01T00:00:00Z


class FakeTransport:
    """Capture calls and consume supplied responses; never access the network."""

    def __init__(self):
        self.responses = []
        self.calls = []

    def queue(self, data, status=200, headers=None):
        self.responses.append(HTTPResponse(status, headers or {}, copy.deepcopy(data)))

    def __call__(self, method, url, *, payload=None, bearer=None):
        self.calls.append({
            "method": method,
            "url": url,
            "payload": copy.deepcopy(payload),
            "bearer": bearer,
        })
        if not self.responses:
            raise AssertionError("Unexpected HTTP request; no fixture was queued.")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def send_response(accepted=1, failed=0):
    return {
        "notification_id": NOTIFICATION_ID,
        "accepted": accepted,
        "failed": failed,
        "results": [
            {"status": "accepted", "transport": "apns", "key": DEVICE_KEY,
             "source_keys": [DEVICE_KEY, APP_KEY], "message_id": "provider-id"}
            for _ in range(accepted)
        ] + [
            {"status": "failed", "transport": "fcm", "key": DEVICE_KEY,
             "source_keys": [DEVICE_KEY], "reason": "upstream_error"}
            for _ in range(failed)
        ],
    }


def authorization_request():
    return {
        "request_id": REQUEST_ID,
        "authorization_url": AUTH_URL,
        "poll_secret": POLL_SECRET,
        "expires_at": "2030-01-01T01:00:00Z",
        "poll_interval_seconds": 2,
    }


def authorization_result(status="approved", *, include_token=True):
    result = None
    if status == "approved":
        result = {
            "application_id": APPLICATION_ID,
            "push_key": APP_KEY,
            "key_version": 3,
            "connection_version": 4,
            "expires_at": "2030-01-01T00:30:00Z",
        }
        if include_token:
            result["reauthorization_token"] = REAUTH_TOKEN
    return {
        "status": status,
        "result": result,
        "expires_at": "2030-01-01T00:30:00Z",
        "poll_interval_seconds": 2,
    }


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meowpush-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "config"
        self.store = SecureStore(self.directory)
        self.store.ensure()
        self.transport = FakeTransport()
        self.now = START_TIME
        self.app = MeowPush(self.store, transport=self.transport, clock=lambda: self.now)

    def credentials(self, profiles=None, default="default"):
        config = {
            "version": 1,
            "default_profile": default,
            "profiles": profiles or {"default": {"push_key": DEVICE_KEY}},
        }
        self.store.write_json("pk-credentials.json", config)
        return config

    def start(self, profile="default", mode="create", replace=False):
        self.transport.queue(authorization_request(), status=201)
        output = self.app.auth_start(profile, {"name": "Test Agent"}, mode=mode,
                                     replace=replace)
        self.assertTrue(output["ok"])
        self.assertEqual(output["authorization_url"], AUTH_URL)
        self.assert_secret_free(output)
        self.now += 2
        return output["state_id"]

    def state_file(self, state_id):
        return "authorization-" + state_id + ".json"

    def assert_secret_free(self, value):
        serialized = json.dumps(value, default=str)
        for secret in (DEVICE_KEY, GROUP_KEY, APP_KEY, OTHER_APP_KEY, POLL_SECRET, REAUTH_TOKEN):
            self.assertNotIn(secret, serialized)

    def assert_rejected(self, operation):
        """A failure can be a safe exception or an explicit unsuccessful result."""
        try:
            result = operation()
        except (AppError, StoreError) as error:
            self.assert_secret_free(str(error))
            return None
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)
        return result

    def test_missing_configuration_can_be_inspected_without_network(self):
        result = self.app.profiles()
        self.assertIn("status", result)
        self.assert_secret_free(result)
        self.assertEqual(self.transport.calls, [])
        self.assertIsNone(self.store.read_json("pk-credentials.json"))

    def test_profile_listing_does_not_expose_secrets(self):
        self.credentials({
            "default": {"push_key": DEVICE_KEY},
            "group": {"push_key": GROUP_KEY},
            "application": {"push_key": APP_KEY, "application_id": APPLICATION_ID,
                            "reauthorization_token": REAUTH_TOKEN,
                            "key_version": 1, "connection_version": 1},
        })
        result = self.app.profiles()
        self.assert_secret_free(result)
        self.assertEqual({entry["name"] for entry in result["profiles"]},
                         {"default", "group", "application"})
        self.assertEqual(self.transport.calls, [])

    def test_old_device_profile_and_default_selection(self):
        self.credentials()
        self.transport.queue(send_response())
        result = self.app.send({"body": "Finished."})
        self.assertTrue(result["ok"])
        self.assertEqual(self.transport.calls[0]["payload"],
                         {"body": "Finished.", "key": DEVICE_KEY})
        self.assertEqual(self.transport.calls[0]["url"], "https://send.meowpush.com/")
        self.assertEqual(self.transport.calls[0]["method"], "POST")
        self.assertIsNone(self.transport.calls[0]["bearer"])
        self.assert_secret_free(result)

    def test_explicit_group_profile_uses_only_its_key(self):
        self.credentials({"default": {"push_key": DEVICE_KEY},
                          "work": {"push_key": GROUP_KEY}})
        self.transport.queue(send_response())
        self.app.send({"body": "Finished."}, profile="work")
        self.assertEqual(self.transport.calls[0]["payload"]["key"], GROUP_KEY)
        self.assertNotIn("keys", self.transport.calls[0]["payload"])

    def test_application_profile_is_sent_as_one_key(self):
        self.credentials({"default": {"push_key": APP_KEY, "application_id": APPLICATION_ID,
                                      "key_version": 1, "connection_version": 1}})
        self.transport.queue(send_response())
        self.app.send({"body": "Finished."})
        self.assertEqual(self.transport.calls[0]["payload"]["key"], APP_KEY)
        self.assertNotIn("keys", self.transport.calls[0]["payload"])

    def test_explicit_missing_profile_does_not_fall_back(self):
        self.credentials()
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}, profile="missing"))
        self.assertEqual(self.transport.calls, [])

    def test_missing_default_does_not_choose_arbitrary_profile(self):
        self.credentials(default="missing")
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}))
        self.assertEqual(self.transport.calls, [])

    def test_missing_credentials_do_not_start_authorization_automatically(self):
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}))
        self.assertEqual(self.transport.calls, [])

    def test_invalid_credentials_are_not_overwritten(self):
        malformed = {"version": 9, "profiles": {"default": {"push_key": DEVICE_KEY}}}
        self.store.write_json("pk-credentials.json", malformed)
        self.assert_rejected(lambda: self.app.auth_start("default", {"name": "Test"}))
        self.assertEqual(self.store.read_json("pk-credentials.json"), malformed)
        self.assertEqual(self.transport.calls, [])

    def test_advanced_payload_is_preserved_without_mutating_input(self):
        self.credentials()
        payload = {
            "title": "Build complete", "body": "All checks passed.",
            "sound": "default", "url": "https://example.com/build/7",
            "image": "https://example.com/result.png", "data": {"build": 7},
            "apns": {"headers": {"apns-priority": "10"}},
            "future_field": {"some": ["new", "capability"]},
        }
        original = copy.deepcopy(payload)
        self.transport.queue(send_response())
        self.app.send(payload)
        self.assertEqual(payload, original)
        self.assertEqual(self.transport.calls[0]["payload"], {**original, "key": DEVICE_KEY})

    def test_user_supplied_keys_are_rejected_before_network(self):
        self.credentials()
        for field, value in (("key", APP_KEY), ("keys", [APP_KEY])):
            with self.subTest(field=field):
                self.assert_rejected(lambda: self.app.send({"body": "Finished.", field: value}))
        self.assertEqual(self.transport.calls, [])

    def test_payload_requires_a_nonempty_body(self):
        self.credentials()
        for payload in ([], None, {}, {"body": ""}, {"body": 3}, {"body": "x" * 4001}):
            with self.subTest(payload_type=type(payload).__name__):
                self.assert_rejected(lambda: self.app.send(payload))
        self.assertEqual(self.transport.calls, [])

    def test_partial_acceptance_is_not_complete_success_and_is_not_retried(self):
        self.credentials()
        self.transport.queue(send_response(accepted=1, failed=1))
        result = self.app.send({"body": "Finished."})
        self.assertFalse(result["ok"])
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(len(self.transport.calls), 1)
        self.assert_secret_free(result)

    def test_send_quota_result_preserves_safe_retry_after_header(self):
        self.credentials()
        response = send_response(accepted=0, failed=1)
        response["results"][0]["reason"] = "quota_exceeded"
        self.transport.queue(response, status=429, headers={"Retry-After": "30"})
        result = self.app.send({"body": "Finished."})
        self.assertFalse(result["ok"])
        self.assertEqual(result["retry_after_seconds"], 30)
        self.assertEqual(result["results"][0]["reason"], "quota_exceeded")
        self.assertEqual(len(self.transport.calls), 1)
        self.assert_secret_free(result)

    def test_zero_acceptance_is_not_success(self):
        self.credentials()
        for failed in (0, 1):
            with self.subTest(failed=failed):
                self.transport.queue(send_response(accepted=0, failed=failed))
                result = self.app.send({"body": "Finished."})
                self.assertFalse(result["ok"])
                self.assertEqual(result["accepted"], 0)
        self.assertEqual(len(self.transport.calls), 2)

    def test_malformed_or_inconsistent_success_responses_fail_safely(self):
        self.credentials()
        samples = [None, {}, {"accepted": 1, "failed": 0},
                   {**send_response(), "accepted": True},
                   {**send_response(), "failed": -1},
                   {**send_response(), "accepted": 2},
                   {**send_response(), "results": []},
                   {**send_response(), "notification_id": APP_KEY}]
        for sample in samples:
            with self.subTest(sample=type(sample).__name__):
                self.transport.queue(sample)
                self.assert_rejected(lambda: self.app.send({"body": "Finished."}))
        self.assertEqual(len(self.transport.calls), len(samples))

    def test_api_errors_do_not_echo_server_messages_or_keys(self):
        self.credentials()
        self.transport.queue({"error": {"code": "unknown_key", "message": APP_KEY},
                              "push_key": DEVICE_KEY}, status=400)
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}))
        self.assertEqual(len(self.transport.calls), 1)

    def test_response_extra_fields_cannot_leak_secrets(self):
        self.credentials()
        response = send_response()
        response["echo"] = POLL_SECRET
        response["results"][0]["message_id"] = REAUTH_TOKEN
        response["results"][0]["reason"] = APP_KEY
        self.transport.queue(response)
        result = self.app.send({"body": "Finished."})
        self.assert_secret_free(result)

    def test_malformed_result_status_is_a_safe_failure(self):
        self.credentials()
        response = send_response()
        response["results"][0]["status"] = [APP_KEY]
        self.transport.queue(response)
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}))

    def test_malformed_transport_is_not_printed_or_allowed_to_crash(self):
        self.credentials()
        response = send_response()
        response["results"][0]["transport"] = {"secret": APP_KEY}
        self.transport.queue(response)
        try:
            result = self.app.send({"body": "Finished."})
        except AppError as error:
            self.assert_secret_free(str(error))
        else:
            self.assert_secret_free(result)

    def test_malformed_authorization_status_retains_state_without_exposing_response(self):
        state_id = self.start()
        self.transport.queue({"status": [POLL_SECRET], "result": {"push_key": APP_KEY}})
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))

    def test_timeout_does_not_retry(self):
        self.credentials()
        self.transport.responses.append(AppError("network_error", "Request outcome is unknown."))
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}))
        self.assertEqual(len(self.transport.calls), 1)

    def test_redirect_response_does_not_trigger_another_request(self):
        self.credentials()
        self.transport.queue(None, status=307, headers={"Location": "https://example.com/"})
        self.assert_rejected(lambda: self.app.send({"body": "Finished."}))
        self.assertEqual(len(self.transport.calls), 1)

    def test_authorization_start_stores_private_state_and_omits_secrets_from_output(self):
        state_id = self.start()
        state = self.store.read_json(self.state_file(state_id))
        self.assertIsNotNone(state)
        self.assertEqual(state["poll_secret"], POLL_SECRET)
        self.assertEqual(state["request_id"], REQUEST_ID)
        self.assertIsNone(self.store.read_json("pk-credentials.json"))
        self.assertEqual(self.transport.calls[0]["payload"]["mode"], "create")
        self.assertIsNone(self.transport.calls[0]["bearer"])

    def test_user_reply_is_required_before_query(self):
        state_id = self.start()
        self.assert_rejected(lambda: self.app.auth_finish(state_id))
        self.assertEqual(len(self.transport.calls), 1)
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))

    def test_pending_then_approved_persists_only_credential_fields(self):
        state_id = self.start()
        self.transport.queue(authorization_result("pending"))
        pending = self.app.auth_finish(state_id, user_confirmed=True)
        self.assertEqual(pending["status"], "pending")
        self.assertIsNone(self.store.read_json("pk-credentials.json"))
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))
        self.now += 2
        self.transport.queue(authorization_result())
        approved = self.app.auth_finish(state_id, user_confirmed=True)
        self.assertTrue(approved["ok"])
        self.assert_secret_free(approved)
        config = self.store.read_json("pk-credentials.json")
        self.assertEqual(config["version"], 1)
        self.assertEqual(config["default_profile"], "default")
        self.assertEqual(config["profiles"]["default"], {
            "push_key": APP_KEY, "application_id": APPLICATION_ID,
            "reauthorization_token": REAUTH_TOKEN, "key_version": 3,
            "connection_version": 4,
        })
        self.assertIsNone(self.store.read_json(self.state_file(state_id)))
        query = self.transport.calls[-1]
        self.assertEqual(query["method"], "GET")
        self.assertEqual(query["bearer"], POLL_SECRET)
        self.assertNotIn(POLL_SECRET, query["url"])

    def test_query_interval_is_enforced_locally(self):
        state_id = self.start()
        self.transport.queue(authorization_result("pending"))
        self.app.auth_finish(state_id, user_confirmed=True)
        count = len(self.transport.calls)
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertEqual(len(self.transport.calls), count)

    def test_approval_can_be_retrieved_after_the_original_request_deadline(self):
        state_id = self.start()
        # Approval near the pending deadline opens a separate retrieval window.
        # The original expires_at alone cannot prove the request is unusable.
        self.now = START_TIME + 3900
        response = authorization_result()
        response["expires_at"] = "2030-01-01T01:30:00Z"
        response["result"]["expires_at"] = "2030-01-01T01:30:00Z"
        self.transport.queue(response)
        result = self.app.auth_finish(state_id, user_confirmed=True)
        self.assertTrue(result["ok"])
        self.assertIsNotNone(self.store.read_json("pk-credentials.json"))

    def test_rate_limit_retains_state_and_enforces_retry_after(self):
        state_id = self.start()
        self.transport.queue({"error": {"code": "rate_limited", "message": POLL_SECRET}},
                              status=429, headers={"Retry-After": "60"})
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))
        self.now += 3
        count = len(self.transport.calls)
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertEqual(len(self.transport.calls), count)
        self.now += 60
        self.transport.queue(authorization_result())
        self.assertTrue(self.app.auth_finish(state_id, user_confirmed=True)["ok"])

    def test_terminal_authorization_states_remove_temporary_state(self):
        for status in ("rejected", "expired", "invalidated"):
            with self.subTest(status=status):
                state_id = self.start(profile=status)
                self.transport.queue(authorization_result(status))
                self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
                self.assertIsNone(self.store.read_json(self.state_file(state_id)))
        self.assertIsNone(self.store.read_json("pk-credentials.json"))

    def test_terminal_http_authorization_errors_remove_state(self):
        for status, code in ((404, "application_authorization_request_not_found"),
                             (410, "application_authorization_delivery_expired")):
            with self.subTest(status=status):
                state_id = self.start()
                self.transport.queue({"error": {"code": code, "message": POLL_SECRET}},
                                      status=status)
                self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
                self.assertIsNone(self.store.read_json(self.state_file(state_id)))

    def test_transient_authorization_error_keeps_recovery_state(self):
        state_id = self.start()
        self.transport.queue({"error": {"code": "service_unavailable", "message": POLL_SECRET}},
                              status=503)
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))

    def test_save_failure_keeps_authorization_state_for_recovery(self):
        state_id = self.start()
        self.transport.queue(authorization_result())
        real_write = self.store.write_json

        def fail_credentials_write(name, data):
            if name == "pk-credentials.json":
                raise StoreError("write_failed", "The credentials could not be saved.")
            return real_write(name, data)

        with patch.object(self.store, "write_json", side_effect=fail_credentials_write):
            self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))
        self.assertIsNone(self.store.read_json("pk-credentials.json"))
        self.now += 2
        self.transport.queue(authorization_result())
        self.assertTrue(self.app.auth_finish(state_id, user_confirmed=True)["ok"])

    def test_existing_profiles_and_default_survive_new_application(self):
        original = self.credentials({"personal": {"push_key": DEVICE_KEY},
                                     "work": {"push_key": GROUP_KEY}}, default="personal")
        state_id = self.start(profile="builds")
        self.transport.queue(authorization_result())
        self.app.auth_finish(state_id, user_confirmed=True)
        saved = self.store.read_json("pk-credentials.json")
        self.assertEqual(saved["default_profile"], "personal")
        for name, value in original["profiles"].items():
            self.assertEqual(saved["profiles"][name], value)
        self.assertEqual(saved["profiles"]["builds"]["push_key"], APP_KEY)

    def test_replacing_an_existing_profile_requires_confirmation(self):
        original = self.credentials()
        self.assert_rejected(lambda: self.app.auth_start("default", {"name": "Test"}))
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.store.read_json("pk-credentials.json"), original)

    def test_concurrent_profile_change_is_not_overwritten(self):
        state_id = self.start(profile="builds")
        concurrent = self.credentials({"builds": {"push_key": DEVICE_KEY}}, default="builds")
        self.transport.queue(authorization_result())
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertEqual(self.store.read_json("pk-credentials.json"), concurrent)
        self.assertIsNotNone(self.store.read_json(self.state_file(state_id)))

    def test_reauthorization_retains_existing_token_when_not_returned(self):
        self.credentials({"default": {
            "push_key": APP_KEY, "application_id": APPLICATION_ID,
            "reauthorization_token": REAUTH_TOKEN, "key_version": 2, "connection_version": 2,
        }})
        state_id = self.start(mode="reauthorize", replace=True)
        request = self.transport.calls[0]
        self.assertEqual(request["bearer"], REAUTH_TOKEN)
        self.assertEqual(request["payload"]["application_id"], APPLICATION_ID)
        self.assertEqual(request["payload"]["mode"], "reauthorize")
        self.transport.queue(authorization_result(include_token=False))
        result = self.app.auth_finish(state_id, user_confirmed=True)
        self.assertTrue(result["ok"])
        self.assert_secret_free(result)
        profile = self.store.read_json("pk-credentials.json")["profiles"]["default"]
        self.assertEqual(profile["reauthorization_token"], REAUTH_TOKEN)
        self.assertEqual(profile["key_version"], 3)
        self.assertEqual(profile["connection_version"], 4)

    def test_reauthorization_cannot_change_application_identity(self):
        self.credentials({"default": {
            "push_key": APP_KEY, "application_id": APPLICATION_ID,
            "reauthorization_token": REAUTH_TOKEN, "key_version": 2, "connection_version": 2,
        }})
        state_id = self.start(mode="reauthorize", replace=True)
        response = authorization_result(include_token=False)
        response["result"]["application_id"] = "019f1000-0000-7000-8000-000000000018"
        self.transport.queue(response)
        self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        saved = self.store.read_json("pk-credentials.json")["profiles"]["default"]
        self.assertEqual(saved["application_id"], APPLICATION_ID)

    def test_state_identifier_cannot_escape_the_configuration_directory(self):
        for state_id in ("../outside", "/tmp/outside", "", ".."):
            with self.subTest(state_id=state_id):
                self.assert_rejected(lambda: self.app.auth_finish(state_id, user_confirmed=True))
        self.assertEqual(self.transport.calls, [])

    def test_cli_runs_from_outside_the_skill_and_prints_only_safe_json(self):
        self.credentials()
        process = subprocess.run(
            [sys.executable, str(SCRIPTS / "meowpush.py"), "--config-dir", str(self.directory),
             "profiles"], cwd=self.temp.name, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assert_secret_free(result)
        self.assertEqual(process.stderr, "")

    def test_cli_rejects_secret_injection_without_echoing_payload(self):
        self.credentials()
        process = subprocess.run(
            [sys.executable, str(SCRIPTS / "meowpush.py"), "--config-dir", str(self.directory),
             "send", "--payload", "-"],
            input=json.dumps({"body": "Finished.", "key": APP_KEY}), cwd=self.temp.name,
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assert_secret_free(process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertFalse(result["ok"])


class FakeHTTPStream:
    def __init__(self, raw, status=200, headers=None):
        self.raw = raw
        self.code = status
        self.headers = headers or {"Content-Type": "application/json"}
        self.read_sizes = []
        self.closed = False

    def read(self, size):
        self.read_sizes.append(size)
        return self.raw[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True


class HTTPTransportTests(unittest.TestCase):
    def test_truncated_http_stream_is_unknown_and_not_retried(self):
        stream = FakeHTTPStream(b"")
        stream.read = Mock(side_effect=IncompleteRead(APP_KEY.encode(), 100))
        opener = Mock()
        opener.open.return_value = stream
        with patch("meowpush.build_opener", return_value=opener):
            with self.assertRaises(AppError) as caught:
                request_json("POST", "https://send.meowpush.com/", payload={"body": "Done."})
        self.assertNotIn(APP_KEY, str(caught.exception))
        self.assertIn("unknown", caught.exception.message)
        opener.open.assert_called_once()
        self.assertTrue(stream.closed)

    def test_transport_uses_verified_tls_explicit_timeout_and_json_body(self):
        stream = FakeHTTPStream(json.dumps(send_response()).encode())
        opener = Mock()
        opener.open.return_value = stream
        with patch("meowpush.build_opener", return_value=opener) as builder:
            result = request_json("POST", "https://send.meowpush.com/",
                                  payload={"body": "Finished.", "key": DEVICE_KEY})
        self.assertEqual(result.status, 200)
        self.assertEqual(result.data["accepted"], 1)
        handlers = builder.call_args.args
        https = next(handler for handler in handlers if isinstance(handler, HTTPSHandler))
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https._context.check_hostname)
        self.assertTrue(any(isinstance(handler, NoRedirect) for handler in handlers))
        request = opener.open.call_args.args[0]
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})
        self.assertEqual(json.loads(request.data), {"body": "Finished.", "key": DEVICE_KEY})
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertTrue(stream.closed)
        opener.open.assert_called_once()

    def test_query_credential_is_in_header_and_not_url_or_body(self):
        stream = FakeHTTPStream(json.dumps(authorization_result("pending")).encode())
        opener = Mock()
        opener.open.return_value = stream
        url = "https://accounts.meowpush.com/api/v1/application-authorization-requests/" + REQUEST_ID + "/result"
        with patch("meowpush.build_opener", return_value=opener):
            request_json("GET", url, bearer=POLL_SECRET)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer " + POLL_SECRET)
        self.assertNotIn(POLL_SECRET, request.full_url)
        self.assertIsNone(request.data)

    def test_nonofficial_or_insecure_endpoint_is_rejected_before_network(self):
        for endpoint in ("http://send.meowpush.com/", "https://example.com/",
                         "https://send.meowpush.com.evil.example/",
                         "https://accounts.meowpush.com/api/v1/application-authorization-requests/../result"):
            with self.subTest(endpoint=endpoint), patch("meowpush.build_opener") as builder:
                with self.assertRaises(AppError):
                    request_json("POST", endpoint, payload={"body": "Finished."})
                builder.assert_not_called()

    def test_redirect_handler_never_creates_a_followup_request(self):
        redirect = NoRedirect()
        request = Request("https://send.meowpush.com/", data=b"{}", method="POST")
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.assertIsNone(redirect.redirect_request(
                    request, None, status, "Redirect", {}, "https://example.com/"))

    def test_http_error_is_parsed_internally_without_printing_response(self):
        payload = {"error": {"code": "invalid_request", "message": APP_KEY}}
        error = HTTPError("https://send.meowpush.com/", 400, "Rejected " + APP_KEY,
                          {"Content-Type": "application/json"},
                          BytesIO(json.dumps(payload).encode()))
        opener = Mock()
        opener.open.side_effect = error
        output, errors = StringIO(), StringIO()
        with patch("meowpush.build_opener", return_value=opener), redirect_stdout(output), redirect_stderr(errors):
            result = request_json("POST", "https://send.meowpush.com/", payload={"body": "Finished."})
        self.assertEqual(result.status, 400)
        self.assertEqual(result.data, payload)
        self.assertEqual(output.getvalue() + errors.getvalue(), "")
        opener.open.assert_called_once()

    def test_network_exception_is_redacted_and_never_retried(self):
        opener = Mock()
        opener.open.side_effect = URLError("Request containing " + APP_KEY + " failed")
        output, errors = StringIO(), StringIO()
        with patch("meowpush.build_opener", return_value=opener), redirect_stdout(output), redirect_stderr(errors):
            with self.assertRaises(AppError) as caught:
                request_json("POST", "https://send.meowpush.com/", payload={"body": "Finished."})
        self.assertNotIn(APP_KEY, str(caught.exception))
        self.assertEqual(output.getvalue() + errors.getvalue(), "")
        opener.open.assert_called_once()

    def test_malformed_response_does_not_echo_raw_bytes(self):
        for raw in (b"not-json " + APP_KEY.encode(), b"\xff" + APP_KEY.encode(),
                    b'{"accepted":1,"accepted":2}', b'{"accepted":NaN}'):
            with self.subTest(raw_kind=raw[:1]):
                stream = FakeHTTPStream(raw)
                opener = Mock()
                opener.open.return_value = stream
                output, errors = StringIO(), StringIO()
                with patch("meowpush.build_opener", return_value=opener), redirect_stdout(output), redirect_stderr(errors):
                    result = request_json("POST", "https://send.meowpush.com/", payload={"body": "Finished."})
                self.assertIsNone(result.data)
                self.assertEqual(output.getvalue() + errors.getvalue(), "")
                self.assertTrue(stream.closed)

    def test_response_reads_are_bounded_and_oversize_data_is_discarded(self):
        stream = FakeHTTPStream(b"x" * (3 * 1024 * 1024))
        opener = Mock()
        opener.open.return_value = stream
        with patch("meowpush.build_opener", return_value=opener):
            result = request_json("POST", "https://send.meowpush.com/", payload={"body": "Finished."})
        self.assertIsNone(result.data)
        self.assertEqual(len(stream.read_sizes), 1)
        self.assertGreater(stream.read_sizes[0], 0)
        self.assertLess(stream.read_sizes[0], len(stream.raw))

    def test_nonfinite_request_values_and_header_injection_never_reach_network(self):
        with patch("meowpush.build_opener") as builder:
            with self.assertRaises(AppError):
                request_json("POST", "https://send.meowpush.com/", payload={"body": "Finished.", "data": float("nan")})
            with self.assertRaises(AppError):
                request_json("POST", "https://send.meowpush.com/", bearer="token\r\nInjected: value")
            builder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
