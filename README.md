# xmplayer

Standalone Python desktop monitor GUI for one iCSee/XM camera.

## What this project does

- runs the self-contained cloud refresh + first/second 6611 live chain
- signs in through the iCSee/XM cloud service and establishes the camera P2P connection
- discovers the first camera on the account during initial setup
- extracts the second-flow media stream
- decodes video on desktop through a locally installed `ffmpeg`
- renders frames in a Tkinter monitor window

## System dependencies

You need these installed in the Python/runtime environment used to start the GUI:

- Python 3.11+
- `tkinter`
- `Pillow`
- `pycryptodome`
- `ffmpeg` must be available on `PATH`, or set `ffmpeg_path` in `desktop_monitor.json` to its executable

## Setup

1. Install Python packages from `requirements.txt`.
2. Start the GUI:

```powershell
python run_gui.py
```

3. On the first start, enter the username or email and password from the iCSee/XM mobile app. Do not use the camera's local network login and password.
4. The app retrieves the first camera from the cloud account and stores its ID in `desktop_monitor.local.json`. This local file and `login.txt` are ignored by Git.
5. Edit `desktop_monitor.json` if you need another window size or `ffmpeg_path`.
   You can also tune live capture with:
   - `capture_seconds`
   - `max_frames`
   - `attempts`
   - `playback_fps`
   The default values are intentionally long because the `app_reference_first_6611` profile needs a long first-6611 control window before second-flow media appears.

## Notes

- `SD` maps to `Extra1`
- `HD` maps to `Main`
- audio uses G.711 A-law frames from the camera stream
- the default config is tuned to wait longer for second-handshake media frames than the original short probe setup
- the player now rolls to the next captured live segment automatically after the current exported HEVC segment finishes
- if the backend still returns a short or partial run, the GUI keeps the monitor state and lets you reconnect

## Moving To Another Computer

- Clone this repository, then install `ffmpeg` locally or set `ffmpeg_path` to a local executable.
- On the first run, enter the iCSee/XM app credentials when prompted.
- `login.txt` and `desktop_monitor.local.json` stay on the local computer and are ignored by Git.
- Leave `agent_client_id` empty in `desktop_monitor.json` so each PC creates its own relay client id.
- Caches in `xmplayer/config/` are machine-bound. If copied to another PC, `token_cache.json`, `relay_cache.json`, and `agent_client_uuid.txt` are ignored and recreated automatically.
- To force the legacy fixed `agent_client_id` from config for a one-off test, set `XMPLAYER_USE_CONFIG_AGENT_CLIENT_ID=1` before starting the app.
- If live video, recordings, or message images do not load on another PC, run `diagnose_xmplayer.cmd`. It writes a short report to `diagnostics.txt`.
- The other PC must be able to reach the camera cloud/relay hosts and UCloud image URLs. A firewall/VPN/proxy difference can break video, recordings, and message thumbnails at the same time.
- If another PC can connect to `6611` but every first handshake times out, compare `public ip direct` in `diagnostics.txt`. Some relay paths appear sensitive to the tunnel exit IP.
- Optional network override: set `XMPLAYER_SOCKS5_PROXY=127.0.0.1:1080` before starting `diagnose_xmplayer.cmd` or `start_xmplayer.cmd` to route both control HTTPS and raw `6611` TCP through the same SOCKS5 proxy.
- First-6611 relay search can be tuned with `ICSEE_RPSCMD_MAX_ATTEMPTS` and `ICSEE_FIRST6611_HANDSHAKE_TIMEOUT`; defaults are 24 attempts and a 2 second silent-handshake cutoff.
