---
name: meowpush
description: Send MeowPush notifications and set up their local credentials. Use when the user explicitly requests MeowPush, a push notification, or an external notification such as "notify me when done", "ping my phone when the build finishes", or "alert me if this fails", including equivalent requests in the user's language. Supports immediate messages and notifications at the requested task outcome. Do not activate for ordinary conversational updates without a notification request or when the user specifies a different notification channel.
---

# MeowPush

Turn the user's notification intent into a correctly timed message. Use the bundled Python 3.10+ helper for credentials, authorization, and sending. Routine use is self-contained; consult the [official API documentation](https://docs.meowpush.com/en/api/) when a new capability or an API change requires it.

## Understand the request

- An explicit request to send a notification authorizes that send. Do not ask for another confirmation merely because it uses MeowPush. Honor an explicitly chosen alternative channel.
- For an immediate message, send after its content and recipient profile are clear from the request. Ask only for material information that is genuinely missing.
- For "notify me when done", remember the requested event while performing the main task, then send once the agreed work is complete. A progress milestone or a request for user input is not completion. If the user requests failure alerts or the outcome of a run, report the actual failure or outcome; never describe failed or incomplete work as successful.
- Read the user's intent semantically, regardless of the language they use. Write notification content in the requested language, or the conversation's language when unspecified.
- A general instruction to keep the user informed in chat does not authorize external notifications. Do not send a test, progress update, or additional message that the user did not request.

## Resolve the installation and profile early

Locate this installed `SKILL.md` through the host's skill context. Resolve `scripts/meowpush.py` relative to that directory and invoke it using its absolute path; the working directory may be unrelated to the skill.

```bash
python3 /absolute/path/to/meowpush/scripts/meowpush.py profiles
```

The command returns profile names and key types without revealing credentials. Use the profile the user selected; otherwise use the configured `default_profile`. If the selected profile is missing or invalid, do not fall back to another one.

If no usable credentials are configured, follow [Setup and credentials](references/setup.md). Check this early for a long task so authorization can happen before the requested notification is due. Continue independent work while waiting for the user, but do not send until authorization and local persistence are complete. If the main task finishes first, report that its notification is waiting for setup; after setup, send the truthful result originally requested.

## Compose and send

Use the user's supplied content and options. Otherwise choose a concise title naming the task and a body stating the actual outcome, with a relevant link when available. Include enough context for the notification to make sense on a phone. Keep credentials and unrelated private conversation content out of the message.

Create a JSON object containing a required nonempty `body` and any desired message fields. Do not include `key` or `keys`: the helper loads the selected credential and inserts it in memory. A single profile can address a device, a group, or an authorized application's targets.

```bash
python3 /absolute/path/to/meowpush/scripts/meowpush.py send \
  --profile default --payload /absolute/path/to/message.json
```

Use `--payload -` to read the JSON from standard input. Omit `--profile` only when intentionally using the configured default. See [Sending and command reference](references/sending.md) for payload examples, advanced fields, command syntax, and failure handling.

Run the send at the requested event, once. A completion notification should reflect verification already performed; it must not promise checks or deployment that did not happen. After the send, summarize the helper's outcome accurately.

## Interpret the result

- Full success requires a valid response with `accepted > 0` and `failed == 0`. Say how many targets were accepted when useful.
- Partial failures, zero accepted targets, and an unknown result are not full success. Preserve this distinction in the user's report.
- Acceptance means an upstream push provider accepted the message. It does not prove a device displayed it.
- Do not automatically resend after a timeout, an invalid response, or partial success. A repeated request can duplicate notifications. `collapse_id` is not an idempotency key.
- Do not repair an invalid key by silently changing profiles or creating another application. Use the setup reference for a user-requested update.

## Scheduling and safety

Use the host's scheduling capability only when the user requests a future or recurring notification. Complete interactive MeowPush setup before creating the schedule. Resolve missing trigger, time zone, and recurrence details; use the user's stated settings without asking them to repeat them. The scheduled task should retain the exact profile name, credential location if overridden, skill reference, and non-secret message settings. At runtime, use this skill and load credentials locally; never place a key in the task prompt or definition.

This skill does not provide a scheduler or background process. A remote service cannot read local profiles; do not embed a key into its URL or visible configuration. A remote integration needs explicit authorization and an appropriate secret manager.

Never read credentials with tools that print their contents. Do not ask the user to paste keys, passwords, session tokens, or authorization tokens into chat or manually edit a credentials file. Keep secrets inside the bundled helper, keep TLS verification enabled, and do not bypass its redirect or file-permission checks.
