# nexvault

A cross-platform, cryptographic file vault built with Go. All files are
encrypted with XChaCha20-Poly1305 before hitting disk. nexvault ships as a
single binary that works as either a graphical app or a traditional
command-line tool.

---

## Features

| Feature | Detail |
|---|---|
| **Encryption** | XChaCha20-Poly1305 AEAD, 1 MiB chunks |
| **Key derivation** | Argon2id (memory-hard) for the vault password; HKDF-SHA256 for sub-keys |
| **Auto-encrypt** | Drop a file into the watch folder — it is encrypted and securely wiped |
| **GUI** | Native-looking Fyne window (Metal on macOS, DirectX on Windows, OpenGL on Linux) |
| **Dock / taskbar** | Proper app icon on macOS Dock, Windows taskbar, and Linux panels |
| **System tray** | Status icon with Lock / Quit quick-access menu |
| **CLI** | Full command-line interface for scripting — run any sub-command to skip the GUI |
| **Atomic writes** | All vault file operations are atomic; no partial data is ever written |
| **Key wiping** | Sensitive key material is zeroed in memory when the vault is locked |

---

## Platform support

| OS | Architecture | Rendering backend |
|---|---|---|
| **macOS 12 Monterey +** | Apple Silicon (arm64) & Intel (amd64) | Metal |
| **Windows 10 / 11** | amd64, arm64 | DirectX (ANGLE) |
| **Linux** | amd64, arm64 | OpenGL / Vulkan |

---

## Vault structure

```
vault/
├── vault.hdr          # Vault header: KDF parameters, vault ID
├── keyslot.nexk       # Encrypted vault master key (VMK)
├── index.nexi         # Encrypted file index
└── .nex/blobs/        # Encrypted file blobs
    └── xx/            # Sharded by first two hex digits of blob ID
        └── {id}.nex   # Individual encrypted blob (v2 format)
```

---

## Building

### Prerequisites

| Platform | Requirements |
|---|---|
| macOS | Xcode Command Line Tools (`xcode-select --install`) |
| Windows | TDM-GCC or MSYS2 (`pacman -S mingw-w64-ucrt-x86_64-gcc`) |
| Linux | `libgl1-mesa-dev xorg-dev` (or `libwayland-dev` for Wayland) |

All platforms require **Go 1.21 or later** and **CGO_ENABLED=1** (the default).

### macOS (Apple Silicon)

```bash
# Install Xcode CLT once
xcode-select --install

git clone https://github.com/0x4E4558/0x4E4558Vault.git && cd 0x4E4558Vault
go build -o nexvault .
./nexvault        # → runs from the terminal (see Installation below for the dock icon)
```

### Windows 10 / 11

```powershell
# Install TDM-GCC from https://jmeubank.github.io/tdm-gcc/ then:
git clone https://github.com/0x4E4558/0x4E4558Vault.git; cd 0x4E4558Vault
go build -ldflags "-H windowsgui" -o nexvault.exe .
.\nexvault.exe
```

The `-H windowsgui` flag hides the console window when double-clicking.

### Linux

```bash
# Ubuntu / Debian
sudo apt install libgl1-mesa-dev xorg-dev

git clone https://github.com/0x4E4558/0x4E4558Vault.git && cd 0x4E4558Vault
go build -o nexvault .
./nexvault
```

### Run tests

```bash
go test ./...
```

---

## Installation

`go build` produces a raw binary — fine for development, but not for everyday
use. For a properly installed application with:

- a working **Dock / taskbar icon**
- an entry in **Spotlight / the Applications launcher**
- **no spurious terminal window** on double-click

use the `fyne` packaging tool, which creates a native app bundle and installs it
in the correct system location.

### 1. Install the fyne CLI (all platforms, once)

```bash
go install fyne.io/fyne/v2/cmd/fyne@latest
```

### 2. Package and install

Run the following from the root of the cloned repository (where `FyneApp.toml`
lives). `fyne install` reads the app name, ID, icon, and version from that file
automatically.

#### macOS

```bash
fyne install
```

This creates `nexvault.app` in `/Applications` with a correct `Info.plist` and
embedded icon. Launch it from Spotlight or Finder — it appears in the Dock with
the vault icon and **never opens a Terminal window**.

#### Windows

```powershell
fyne install
```

Embeds the icon as a Windows resource, suppresses the console window
automatically, and creates a Start Menu entry.

#### Linux

```bash
fyne install
```

Installs the binary to `/usr/local/bin`, a `.desktop` file to
`/usr/share/applications`, and the icon to the correct XDG icon directory, so
`nexvault` appears in your application launcher with its icon.

---

## Starting the watcher automatically

The GUI keeps the watcher running in the background as long as the app is open:
close the window and the system-tray icon remains — the watcher keeps going.
To start `nexvault` automatically at login, choose one of the methods below.

### Auto-start the GUI (recommended for most users)

The graphical app handles unlocking interactively, then watches the drop folder
through its system-tray icon. No password file is needed.

| Platform | Steps |
|---|---|
| **macOS** | System Settings → General → Login Items → **+** → select `nexvault.app` |
| **Windows** | Press Win+R, type `shell:startup`, place a shortcut to `nexvault.exe` in the folder that opens |
| **Linux (GNOME / KDE)** | Copy the installed `.desktop` file to `~/.config/autostart/` |

```bash
# Linux: one-liner to enable autostart
cp /usr/share/applications/nexvault.desktop ~/.config/autostart/
```

### Headless watcher service (advanced)

For a fully background daemon that uses the CLI `watch` sub-command without a
GUI, follow the platform steps below.

> ⚠️ **Security note:** the `watch` sub-command reads the vault password from
> stdin when stdin is not a terminal. Storing a password in a plain file is a
> security trade-off — use `chmod 600` and keep the file on an encrypted volume.

#### macOS — launchd user agent

Create `~/Library/LaunchAgents/io.nexvault.watcher.plist`, substituting
`VAULT_PATH` and `DROP_PATH` with absolute paths:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.nexvault.watcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/nexvault.app/Contents/MacOS/nexvault</string>
        <string>watch</string>
        <string>-vault</string>
        <string>VAULT_PATH</string>
        <string>-drop</string>
        <string>DROP_PATH</string>
    </array>
    <key>StandardInputPath</key>
    <string>/Users/YOUR_USERNAME/.nexvault-pass</string>
    <key>StandardOutPath</key>
    <string>/tmp/nexvault-watcher.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/nexvault-watcher.log</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

```bash
# Store the password (one-time setup)
printf 'yourpassword\n' > ~/.nexvault-pass && chmod 600 ~/.nexvault-pass

# Load the agent
launchctl load ~/Library/LaunchAgents/io.nexvault.watcher.plist
```

#### Linux — systemd user service

Create `~/.config/systemd/user/nexvault-watcher.service`, substituting
`VAULT_PATH` and `DROP_PATH`:

```ini
[Unit]
Description=nexvault drop-folder watcher

[Service]
ExecStart=/usr/local/bin/nexvault watch -vault VAULT_PATH -drop DROP_PATH
StandardInput=file:%h/.nexvault-pass
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
# Store the password (one-time setup)
printf 'yourpassword\n' > ~/.nexvault-pass && chmod 600 ~/.nexvault-pass

# Enable and start
systemctl --user enable --now nexvault-watcher.service
```

#### Windows — Task Scheduler

```powershell
# Store the password (one-time setup)
"yourpassword" | Out-File -Encoding ascii "$env:USERPROFILE\.nexvault-pass"
icacls "$env:USERPROFILE\.nexvault-pass" /inheritance:r /grant:r "${env:USERNAME}:(R)"

# Wrapper script that pipes the password and runs the watcher
$wrapper = @"
Get-Content `"$env:USERPROFILE\.nexvault-pass`" | & `"$env:LOCALAPPDATA\nexvault\nexvault.exe`" watch -vault VAULT_PATH -drop DROP_PATH
"@
$wrapper | Out-File -Encoding utf8 "$env:USERPROFILE\.nexvault-watcher.ps1"

# Register the scheduled task
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
               -Argument "-WindowStyle Hidden -File `"$env:USERPROFILE\.nexvault-watcher.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "nexvault-watcher" `
    -Action $action -Trigger $trigger -RunLevel Limited -Force
```

---

## Usage

### Graphical interface

Launch `nexvault` without arguments (or double-click the binary / app bundle):

```
┌─────────────────────────────────────────────────────────────────┐
│  [New Vault]  [Open Vault]  │  [Lock]       [Decrypt…] [Delete] [Refresh]
├─────────────────────────────────────────────────────────────────┤
│  Vault Path                      │  Size    │  Added            │
│  documents/passport.pdf          │  1.4 MB  │  2025-01-15 09:32 │
│  photos/id_card.jpg              │  640 KB  │  2025-01-15 09:33 │
├─────────────────────────────────────────────────────────────────┤
│  Status: unlocked  •  Vault: ~/secure  •  Watching: ~/Desktop/drop
└─────────────────────────────────────────────────────────────────┘
```

1. **New Vault** — pick a vault folder, a drop folder, and set a password.
2. **Open Vault** — pick the existing vault folder, the drop folder to watch,
   and enter the password.
3. **Drop folder** — any file placed there is automatically encrypted into the
   vault and the plaintext is securely overwritten and removed.
4. **Decrypt…** — select a row, click Decrypt, and choose where to save the
   plaintext.
5. **Delete** — select a row and click Delete to permanently remove the entry.
6. **Lock** — wipes the in-memory keys and stops the watcher.

The window can be closed without quitting — a system-tray icon lets you Lock,
Show the window, or Quit from anywhere.

### Command-line interface

Passing any known sub-command runs the CLI instead of opening the GUI:

```bash
# Create a new vault
nexvault create -vault ~/secure

# Watch a drop folder and auto-encrypt every incoming file
nexvault watch -vault ~/secure -drop ~/Desktop/drop

# List all entries
nexvault list -vault ~/secure

# Decrypt one entry
nexvault decrypt -vault ~/secure -entry documents/passport.pdf -out /tmp/passport.pdf

# Delete an entry
nexvault delete -vault ~/secure -entry documents/passport.pdf
```

---

## Security design

### Encryption layers

```
Password ──Argon2id──► KPass
                         │
               keyslot.nexk  ──AEAD decrypt──► VMK (vault master key)
                                                 │
                               HKDF-SHA256 ──────┤
                                           KIndex │  KBlobRoot
                                                  │
index.nexi ◄── AEAD(KIndex) ──────────────────────┘
blobs/*.nex ◄── AEAD(KBlobRoot, per-blob sub-key)
```

### Per-blob format (v2)

Each blob is a sequence of 1 MiB chunks. Every chunk is independently
authenticated with XChaCha20-Poly1305. The AEAD additional data encodes
the vault ID, vault-relative path, generation number, and chunk index,
so a blob cannot be silently substituted for another.

### Key wiping

`Session.LockAndWipe()` zeroes `KIndex` and `KBlobRoot` in memory immediately
after the vault is locked — either manually or on application exit.

### Atomic writes

All writes to `index.nexi` and blob files go through a write-to-temp +
fsync + rename sequence so a crash mid-write never leaves the vault in a
partially-updated state.

---

## Default KDF parameters

| Parameter | Default | Argon2id constraint |
|---|---|---|
| Memory | 256 MiB | — |
| Iterations | 3 | — |
| Parallelism | min(GOMAXPROCS, 4) | — |

Minimum recommended RAM: **512 MiB**. Allow 2-4 seconds for unlock on
lower-end hardware.

---

## Dependencies

| Package | Purpose |
|---|---|
| [fyne.io/fyne/v2](https://fyne.io/) | Cross-platform GUI (macOS, Windows, Linux) |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id, HKDF, XChaCha20-Poly1305 |
| [github.com/fsnotify/fsnotify](https://github.com/fsnotify/fsnotify) | Cross-platform file-system watcher |
| [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) | Secure terminal password input (CLI mode) |

---

## License

See License File.
