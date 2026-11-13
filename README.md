# Folder Lock

[中文说明](README.zh.md)

Lock folders and individual notes with independent passwords, including nested (multi-layer) encryption.

- Right-click a folder or a Markdown note to add a lock.
- Each lock has its own password. A file inside a locked folder can have an additional inner password.
- A locked folder cannot be expanded until it is unlocked.
- Clicking a locked folder or note opens a password prompt immediately. A wrong password or Cancel returns you to the previous view.
- Ciphertext and key material are never shown in the editor, preview, hover popovers, or embeds.
- Optional idle auto-lock. The interface is in Chinese by default and can be switched to English.

## Install

After the plugin is listed in the community directory, install it from **Settings → Community plugins**.

To install a GitHub release manually:

1. Download `main.js`, `manifest.json`, and `styles.css` from the [latest release](https://github.com/davidwanghaoming/obsidian-folder-lock/releases).
2. Copy them into `YourVault/.obsidian/plugins/folder-lock/`.
3. If you are upgrading, keep the existing `data.json`. Do not reset or overwrite it.
4. Reload Obsidian and enable **Folder Lock**.

From source: `npm ci && npm test && npm run build`, then copy `dist/main.js`, `dist/manifest.json`, and `dist/styles.css` into that same plugin folder.

**Upgrading ciphertext from 0.1 / v1:** keep the original settings, unlock all, then lock all. Only that cycle upgrades existing files to the self-contained v2 format. Legacy files cannot be recovered if the original `data.json` is lost.

## Usage

1. Right-click a folder or a `.md` note and choose **Protect this folder** or **Lock this file**, or type a vault-relative path in the plugin settings and choose **Add protection**. Set a password of at least 8 characters.
2. Locked folders stay collapsed, and lock icons appear on protected items. Click a locked item to enter its password. Cancel or a wrong password leaves the previous view in place.
3. A note opens only after every layer is unlocked: outer first, then inner. Clicking only the folder unlocks the folder layer; inner file locks stay in place. Cancelling an inner prompt does not re-lock an already unlocked outer layer.
4. The ribbon icon locks or unlocks every item. Settings and the context menu can operate on a single item. Changing a password or removing protection requires the current password, and that layer plus any outer layers must already be unlocked.
5. **Auto-lock** in settings locks after a period of idle time. Set it to `0` to disable. Quit, crash, sleep, or background pause may not trigger it, so lock manually before you leave.

### Recovering settings

Use **Recover protection from files** in settings or the command palette. The v2 format stores each layer's id, salt, iteration count, and password verifier in an authenticated file header (these are **not** the password or the encryption key) so the lock index can be rebuilt. Unlocking still requires the original password and AES-GCM integrity verification.

Opening a v2 ciphertext file after settings were deleted also attempts recovery. If settings and a file header disagree, the plugin stops rather than overwriting ciphertext with a substituted password. Header conflicts also stop recovery; check your backups.

Recovery only works for layers that still have v2 headers. Fully unlocked layers have no header to recover from. v1 files still need the original `data.json`. **A forgotten password cannot be recovered.** Back up both the notes and `data.json`.

## Security and limitations

- Passwords and keys are not written to disk. Encryption is Web Crypto AES-GCM-256 with a random 12-byte IV, a per-lock 16-byte salt, and PBKDF2-SHA-256 at 600,000 iterations. File headers are authenticated as AAD; tampering fails verification.
- The UI shows names, types, and lock state only. Source mode, preview, hover previews, and embeds replace protected content with a locked placeholder. That placeholder is never saved over the real file. On disk, an encrypted note is a hidden comment block plus a short locked-note message.
- **This is not operating-system access control.** Anyone with disk access can delete or damage files, or disable the plugin. A malicious or incompatible plugin may bypass display hooks. The plugin cannot hide ciphertext if it is disabled, and it cannot protect plaintext while a note is unlocked.
- Only visible `.md` note content is encrypted. Attachments, hidden files, and path or file names are not. After every layer is unlocked, the note is plaintext on disk. Pause Git or sync (including Git) or add the folder to `.gitignore` first. Old Git history, backups, undelete, and caches may still contain plaintext.
- Locking saves and closes related tabs. Do not edit, or write from multiple devices, during an operation. The plugin preflights and verifies writes, then updates notes atomically, but a disk failure can still leave a partial result; it will stop and report, and will not automatically roll back.
- Renames and moves of a protected folder are tracked. Unlock before moving ciphertext across a protection boundary. If a file is moved by mistake, move it back first. Moves while the plugin is disabled cannot be tracked.
- Folder collapse in the file explorer depends on undocumented internals. If those APIs change, collapse protection may break, and the plugin falls back to prompting when you open an item. If a core display hook is incompatible, note views are hidden rather than showing ciphertext.
- If you cancel the inner-layer prompt after unlocking the outer layer, the outer layer stays unlocked.

## Development

```bash
npm ci
npm test
npm run build
```

Build output is written to `dist/`. Tests use Node's Web Crypto, an in-memory vault, and a simulated DOM. Please also test in a real Obsidian vault before protecting important notes: folder collapse and keyboard expansion, wrong-password and cancel behavior, source/preview/hover/embed views, multiple windows, and nested unlock.

## License

[GPL-3.0](LICENSE). Copyright (C) 2026 王浩铭.
