# MeowPush skill

A single Agent Skill that teaches an agent to send MeowPush notifications at the right time, including requests such as "notify me when done". It includes secure local credential handling, application authorization, and a Python sender.

All skill instructions and command text are English. Notification messages follow the user's requested language. Automatic discovery depends on the host agent loading installed skills; installation alone cannot guarantee that every agent will select a skill for every phrasing.

## Requirements

- An agent that supports the [Agent Skills format](https://agentskills.io/specification) and can run local commands with network access.
- Python 3.10 or later. The helper uses only the standard library.
- To install with `npx skills add`, Node.js/npm satisfying the [Skills CLI requirements](https://github.com/vercel-labs/skills#install-a-skill). Node.js is not needed by the notification helper itself.
- A MeowPush account and receiving devices when completing first-time authorization. No key needs to be copied into chat.

## Install

This repository is the skill directory: `SKILL.md` is at its root. The skill's name is `meowpush`, even if the repository or checkout is named `meowpush-skill`.

### With the Skills CLI

Install from [azurdream/meowpush-skill](https://github.com/azurdream/meowpush-skill):

```bash
npx skills add azurdream/meowpush-skill --skill meowpush
```

By default, the CLI installs into the current project and lets you select agents. To select an agent explicitly:

```bash
npx skills add azurdream/meowpush-skill --skill meowpush -a codex
npx skills add azurdream/meowpush-skill --skill meowpush -a claude-code
npx skills add azurdream/meowpush-skill --skill meowpush -a cursor
```

Add `-g` to install for the current user across projects. Add `--copy` to copy files instead of using the CLI's default symlink-based installation. No npm package publication, custom installer, or additional `skills/` wrapper is required. See the [official CLI documentation](https://github.com/vercel-labs/skills/blob/main/docs/commands.md#skills-add).

For a local checkout, first inspect its discovery from the checkout directory:

```bash
npx skills add . --list
```

For local installation, use a clean checkout of the GitHub repository. Run installation from a separate target project, supplying the checkout's absolute path:

```bash
npx skills add /absolute/path/to/meowpush-skill --skill meowpush -a codex
```

Use the entire clean skill directory as the source so scripts, metadata, and references are installed together. Installing only a raw `SKILL.md` file is insufficient for this skill. Avoid installing directly from a development working tree containing private or ignored files: the CLI's local-directory copy is not filtered by Git ignore rules. Use the manual installation below when selecting files from such a working tree.

### Manual installation

Create a folder named `meowpush` in your agent's supported skill directory. Copy `SKILL.md`, `scripts/`, `references/`, and `agents/` into it, excluding Python caches. These are the complete runtime resources; preserve their relative paths. Follow the host's skill reload or new-session instructions.

## Use

Examples of user requests:

- "Use MeowPush to send me a message saying the report is ready."
- "Run the checks and notify me when done."
- "Alert my phone if the deployment fails."
- "Set up MeowPush for my agent."

The agent checks the chosen local profile. If setup is needed, it requests an application and gives you a private authorization link. You choose receiving devices or groups, approve the application, and reply in the conversation. The agent then securely saves the approved credentials. You do not need to paste a Push Key, password, or session token into chat.

An existing notification request is sufficient authorization for that notification. Setup-only requests do not send a test unless you agree. Future or recurring notifications use the host's scheduler, if available.

Credential storage follows the existing MeowPush convention:

- POSIX: `${XDG_CONFIG_HOME:-$HOME/.config}/meowpush/pk-credentials.json`
- Windows: `%APPDATA%\MeowPush\pk-credentials.json`

Existing Device, Group, and Application profiles are supported. Credentials stay in this per-user store and are not included in the skill or its installation directory.

## Runtime and development

- [SKILL.md](SKILL.md): agent intent, timing, and workflow.
- [Setup and credentials](references/setup.md): authorization and local storage.
- [Sending and command reference](references/sending.md): CLI, message fields, and result interpretation.

From the repository root, run the isolated automated tests with:

```bash
python3 -m unittest discover -s tests -v
```

Development tests use temporary directories, fake credentials, and simulated HTTP. They do not require a real MeowPush account. Installation checks run in disposable target projects without global installation.

The runtime was verified on macOS with Python 3.14.3. Skills CLI 1.7.4 passed discovery and default/copy installation checks for Codex, Claude Code, and Cursor, including execution from an unrelated working directory. Native Windows ACL behavior and native Linux execution have not been verified. Offline checks do not establish real push delivery or device display.
