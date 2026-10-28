# Setup and credentials

Read this when a usable profile is missing, authorization is pending, or the user explicitly asks to update an application's credentials. Use the installed helper's absolute path in the examples below.

## Existing profiles

Run `profiles` before creating an application. Reuse the user's selected profile, or the configured default when none was specified. Device and Group profiles containing only `push_key` are supported; they do not need application identifiers or reauthorization tokens.

Missing configuration can be initialized. An unreadable, malformed, or insecure existing file must not be replaced as if it were empty. Report the specific safe error and location without showing file contents. Never select another profile just to make a failed send succeed.

## Create an application

1. Choose an application name and description from the conversation, using the user's language. Use a project or purpose such as "Build Monitor" when known; for general use, a name such as "My Codex" or "My Claude" is sufficient. Do not ask for a use case just to fill these fields.
2. Select the intended profile name. Use `default` for a first configuration. For a separate application, choose a distinct descriptive name instead of replacing an existing profile.
3. Write the non-secret metadata as JSON. Include `name` and `description`; optionally include `icon_url`. Omit `website_url`.
4. Run the authorization command. The helper prepares protected local storage before making the request and stores temporary state without printing credentials.

```json
{
  "name": "Build Monitor",
  "description": "Notifications about requested build results."
}
```

```bash
python3 /absolute/path/to/meowpush/scripts/meowpush.py auth start \
  --profile build-monitor --metadata /absolute/path/to/application.json
```

5. Give the returned `authorization_url` to the current user as a clickable link. Briefly name the application and ask them to review it, choose receiving devices or groups, approve it, and reply here. The link is a private invitation: do not publish it elsewhere.
6. Keep the returned local state ID so the conversation can resume. Wait for the user's reply. Do not run result queries or background polling while waiting.
7. After the user replies that authorization is complete, run one query:

```bash
python3 /absolute/path/to/meowpush/scripts/meowpush.py auth finish \
  --state LOCAL_STATE_ID --user-confirmed
```

`--user-confirmed` records that the user has actually replied; it is not permission to skip that interaction. Their reply alone does not prove approval. Only a valid `approved` API result can complete setup.

8. Follow the result:

| Outcome | Action |
| --- | --- |
| Approved and saved | Report the application name, exact profile name, and credential file path. |
| Pending | Keep the state, explain that approval is not complete, and wait for another user reply. |
| Query too soon or rate limited | Respect the returned interval or retry time; do not loop in the background. |
| Rejected, expired, invalidated, or inaccessible request | Stop using that request. Do not silently start another one. |
| Temporary server/network failure | Keep the recovery state and report that setup remains incomplete. |
| Save or verification failure | Do not send. Keep recoverable state and retry completion only after the local problem is resolved and within the retrieval window. |

For a setup-only request, offer an optional test after successful persistence. Send it only if the user agrees. A suitable test is title `MeowPush`, body `Your AI Agent is connected to MeowPush.`, and `sound: "default"`; adapt the body to the user's language. If the user already requested a real notification, follow that request and its timing instead of adding a test.

## Application icons

When a project or service is clearly identified, prefer its publicly accessible HTTPS icon. For general-purpose integration without a project or service, a matching built-in agent icon may be used:

| Agent | Icon URL |
| --- | --- |
| OpenAI / Codex | `https://meowpush.com/res/appicon/chatgpt.png` |
| Claude | `https://meowpush.com/res/appicon/claude.png` |
| Gemini | `https://meowpush.com/res/appicon/gemini.png` |
| Cursor | `https://meowpush.com/res/appicon/cursor.png` |
| OpenCode | `https://meowpush.com/res/appicon/opencode.png` |
| OpenClaw | `https://meowpush.com/res/appicon/openclaw.png` |
| Hermes Agent | `https://meowpush.com/res/appicon/hermes-agent.png` |
| DeepSeek | `https://meowpush.com/res/appicon/deepseek.png` |
| DeepSeek (deepseek-chibi-girl) | `https://meowpush.com/res/appicon/deepseek-chibi-girl.png` |
| ZCode | `https://meowpush.com/res/appicon/zcode.png` |
| Kimi Code | `https://meowpush.com/res/appicon/kimi-code.png` |
| WorkBuddy | `https://meowpush.com/res/appicon/workbuddy.png` |

Honor the user's visual preference. Omit the icon if no suitable public HTTPS URL is available; do not guess an image URL or use one requiring credentials.

## Reauthorization and replacement

Reauthorization uses an existing application's `application_id` and `reauthorization_token`. It requests approval again; it does not itself rotate the Push Key. Use it only when the user asks to update or recover the selected application's authorization.

Confirm before replacing an existing profile's key. After that confirmation, use:

```bash
python3 /absolute/path/to/meowpush/scripts/meowpush.py auth start \
  --profile build-monitor --mode reauthorize --replace \
  --metadata /absolute/path/to/application-update.json
```

Use `{}` as metadata to retain existing application details. Then follow the same link, user reply, and `auth finish` sequence. The helper retains the old reauthorization token if the approved result does not return a replacement.

If the profile lacks a reauthorization token, do not ask for it in chat. Explain that reauthorization is unavailable for that profile. A new application under a new profile can be requested when the user chooses that approach. Replacing an existing profile with a separate newly authorized application also requires confirmation and `--replace`; a routine send failure never authorizes this replacement.

## Storage contract

The standard credential file is:

- POSIX: `${XDG_CONFIG_HOME:-$HOME/.config}/meowpush/pk-credentials.json`
- Windows: `%APPDATA%\MeowPush\pk-credentials.json`

The optional global `--config-dir DIR` selects an explicit alternate credential directory. Pass it before the subcommand and consistently reuse it for the whole authorization flow and later sends. Do not infer or search other credential locations when a selected location fails.

The version 1 format contains `default_profile` and a `profiles` object. Application profiles store only `push_key`, `application_id`, optional `reauthorization_token`, `key_version`, and `connection_version`. Existing Device/Group profiles may contain only `push_key`. Unrelated profiles and the existing default are preserved.

Only the helper should read or write these values. It uses protected directory/file creation, atomic updates, and writer exclusion. POSIX directories use `0700` and files use `0600`; Windows storage is restricted to the current user. Temporary authorization state and atomic-write staging files require the same protection.

`poll_secret` belongs only to temporary state. `result.expires_at` is the deadline for retrieving the authorization result, not the Push Key's expiration; it is not persisted as a credential expiry. Never persist the complete API response.

Do not place credentials in source code, project configuration, `.env` files, prompts, task definitions, URLs, command arguments, logs, screenshots, or summaries. Do not print raw API responses: sending responses can echo Push Keys. If the environment cannot keep credentials private and enforce permissions, stop setup and explain the limitation instead of asking for a key in chat.

## Protocol reference

The helper implements these official endpoints with TLS verification and no redirects:

- Create or reauthorize: `POST https://accounts.meowpush.com/api/v1/application-authorization-requests`
- Retrieve a result: `GET https://accounts.meowpush.com/api/v1/application-authorization-requests/<request_id>/result`

Creation needs no account credentials. Reauthorization uses its locally stored token; retrieval uses the temporary poll secret. Refer to [Request Application Authorization](https://docs.meowpush.com/en/api/#application-authorization) for new API behavior. Ordinary setup does not require downloading that page.
