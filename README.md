# RE2 BIO2 TRAINER 2026 (PC · Steam)

<img width="480" height="720" alt="Screenshot 2026-09-09 041025" src="https://github.com/user-attachments/assets/e2b853c3-9a2b-42b9-940a-7d7565627ab0" />

Infinite Health trainer for **Resident Evil 2 / BIOHAZARD RE2** - 2026 PC/Steam build.

One toggle, unlimited health. Watch that bar never drop.

## Features

- **Infinite Health** - toggle in-game via the button, **Numpad 1**, or **F1**
- **Audio feedback** - one *ding* = ON, triple *ding* = OFF
- **Live activity log** - every memory read/write is shown in the app, no secrets
- **No DLL injection** - nothing is injected into the game
- **No external framework** - works without REFramework or any launcher
- **No anticheat to worry about** - the game has none, so nothing gets flagged

## Why? (the honest part)

WeMOD used to be the place for this. Then they turned into a greedy tyrant - paywalling basics and shoving their launcher/framework in front of everything. This trainer is free, standalone, and does exactly one thing well. Enjoy.

## Requirements

- Windows 10 or Windows 11
- Resident Evil 2 / BIOHAZARD RE2 - Steam PC version, 2026 build

## Usage

1. Launch the game and load into gameplay.
2. Run `RE2-BIO2-TRAINER-2026.exe`.
3. It attaches automatically. Press the button, **Numpad 1**, or **F1** to toggle Infinite Health.

## Building from source

Requires a Rust toolchain.

```
cargo build --release
```

Output: `target/release/re2-trainer.exe`

## Disclaimer

Single-player, local memory modification only. Nothing is written outside the game process, and it only affects your own session. Use with games you own. No warranties - use at your own risk.
