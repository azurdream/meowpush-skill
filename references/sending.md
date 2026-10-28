# Sending and command reference

## Commands

Use Python 3.10+ and the absolute path of `scripts/meowpush.py` within the installed skill. The helper has no third-party Python dependencies.

```text
python3 <skill-directory>/scripts/meowpush.py [--config-dir DIR] profiles
python3 <skill-directory>/scripts/meowpush.py [--config-dir DIR] auth start --profile NAME --metadata FILE [--mode create|reauthorize] [--replace]
python3 <skill-directory>/scripts/meowpush.py [--config-dir DIR] auth finish --state ID --user-confirmed
python3 <skill-directory>/scripts/meowpush.py [--config-dir DIR] send [--profile NAME] --payload FILE
```

`FILE` may be `-` to read JSON from standard input. Run a command with `--help` for its usage. Use the available Python 3.10+ executable on the host; on Windows this may be `py -3` instead of `python3`.

The global `--config-dir` argument is optional. Normal operation uses the platform's standard per-user MeowPush credential directory. Never put a key or token in an argument, environment-variable override, or payload file.

The helper prints JSON summaries and English error messages. A nonzero exit means the operation did not fully succeed; inspect the safe summary rather than interpreting an HTTP status alone. `profiles` does not send, and `auth finish` does not send an optional test automatically.

## Message composition

Send a JSON object with a required `body`, containing 1–4000 characters. A plain completion message may look like:

```json
{
  "title": "Build complete",
  "body": "The release build finished and its smoke checks passed.",
  "sound": "default"
}
```

Use the actual outcome and the user's language. Do not copy this example's success claim unless those checks really passed.

For a message linking to a relevant result:

```json
{
  "title": "Report ready",
  "body": "The requested report is ready to review.",
  "url": "https://example.com/reports/latest",
  "group": "reports",
  "data": { "report_type": "weekly" }
}
```

Replace the example URL with the user's actual result link, or omit it. The helper accepts a single profile per request. Device, Group, and Application profiles all work; the credential remains local and is injected at runtime. Do not include `key` or `keys` in the input JSON.

## Optional message fields

Use only options that fit the user's request. Omit unnecessary properties instead of inventing notification behavior.

| Field | Purpose |
| --- | --- |
| `title`, `subtitle` | Short title and optional secondary text. |
| `body` | Required notification content. |
| `url` | Link or deep link to open when the notification is tapped. |
| `icon` | Public HTTPS source icon, such as a service logo. |
| `image` | Public HTTPS picture illustrating the event. |
| `sound` | `default`, `silent`, `bell`, `chime`, `alarm`, or `ding`. |
| `level` | `passive`, `active`, or `time-sensitive`; `active` is the usual default. |
| `badge` | Absolute badge number; `0` clears it. Presentation varies by platform. |
| `group` | Visual grouping for related notifications. |
| `collapse_id` | Replace an earlier displayed notification with the same ID where supported. |
| `ttl` | Expiry in seconds; the API default is one day. |
| `data` | JSON object of additional app data; top-level members `aps` and `mp` are reserved. |

For advanced use, the API also accepts `group_filter` and the `apns`, `fcm`, `hms`, `wns`, and `unifiedpush` override objects. The helper preserves advanced fields instead of imposing a reduced local API schema. Consult the current [MeowPush API](https://docs.meowpush.com/en/api/) for unfamiliar options or changed behavior. Do not invent override schemas. Group filters apply to Group/Application target sets; do not add them to a direct Device profile.

The `critical` level depends on service and device capabilities and may be rejected. Do not select it merely because a task failed. Media, sound, urgency, grouping, and badge presentation vary across platforms; do not promise identical device presentation.

## Results and retries

The send endpoint is `POST https://send.meowpush.com/`. The helper validates the response and emits only a safe summary. It never prints the raw result entries that contain `key` or `source_keys`.

| Result | Meaning and next action |
| --- | --- |
| Accepted count greater than zero, failed count zero | The provider accepted all reported targets. Report acceptance, not confirmed device display. |
| Some accepted and some failed | Partial success. Explain the partial result; do not resend to the whole profile automatically. |
| Zero accepted | No accepted delivery is confirmed. Report the failure or empty target result. |
| Timeout, malformed response, or uncertain network outcome | Delivery status is unknown. Do not claim success or automatically send again. |
| Invalid configuration/profile | Stop and explain the configuration issue; do not fall back to another profile. |
| Invalid or revoked key | Report the failure. An update or new application needs the user's direction. |
| Rate/quota limit | Respect `Retry-After` or a reported retry time. Do not repeatedly retry or change profiles to bypass it. |

The helper performs no automatic POST retries. The server already has bounded provider retries; another send is a new notification request and can consume quota and duplicate the original. `collapse_id` controls presentation where supported and does not make retries idempotent. Any later retry should follow the user's intent and the known result, with duplicate risk explained when the first result is uncertain.

## Operational boundaries

- Keep TLS certificate verification enabled. Redirects are rejected, including redirects to another MeowPush host.
- Never rerun a failed command with verbose HTTP logging or print raw response bodies to debug it.
- Keep the selected profile fixed in scheduled tasks. A missing profile or credential file is a failure, not permission to pick a replacement.
- The helper sends messages only. It does not wait for the main task, run a scheduler, or infer a completion event; the agent owns that timing.
