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

`ffmpeg` is required for live video and recording playback. The app can start and use camera Wi-Fi settings, recording lists and messages without it. Playback shows an error if FFmpeg is missing. Install it on `PATH`, or set `ffmpeg_path` in the configuration to its executable.

## Setup

1. Install Python packages from `requirements.txt`.
2. Start the GUI:

```powershell
python run_gui.py
```

3. Choose a connection method. **iCSee / XM account** uses the mobile app's username or email and account password, then retrieves the first camera on that account. **Cloud ID** uses the camera ID, its own username and its own password, without an app account. An empty camera password is supported.
4. Connection settings are saved in the ignored `desktop_monitor.local.json`. Account credentials use the existing ignored `login.txt`; Cloud ID camera credentials are kept in the local configuration. To change the method or camera later, stop playback and click **Connection...**. Existing account sign-in details are preserved when switching to Cloud ID.
5. Edit `desktop_monitor.json` if you need another window size or `ffmpeg_path`.

You can also tune live capture with `capture_seconds`, `max_frames`, `attempts`,
and `playback_fps`. The default values are intentionally long because the
`app_reference_first_6611` profile needs a long first-6611 control window before
second-flow media appears.

Cloud ID supports live SD/HD playback through the existing Python RPS transport,
with camera Wi-Fi and recording operations using the same device credentials.
Cloud messages require an app account and are disabled in Cloud ID mode. A rejected
camera password stops the connection attempt instead of retrying it automatically.

If `ffmpeg_path` is left as `ffmpeg`, the app also looks for an existing portable
executable at `ffmpeg/ffmpeg.exe` or `ffmpeg/bin/ffmpeg.exe` when it is absent from
`PATH`. It is still checked only when playback starts.

## Cloud ID diagnostics without an account

The experimental status command obtains fresh service AuthCodes directly from
`rs.xmeye.net/acquery/v3`, then queries the camera status service. It does not
read `login.txt`, sign into an account, require the camera password, or load SDK
libraries. Start it from the project folder and enter the Cloud ID when prompted:

```powershell
python -m xmplayer.core.legacy_cli cloud-id-status
```

The output distinguishes a valid `Online`/`Offline` response from a network,
authorization, or response-matching error. Cloud IDs and AuthCodes are omitted
from the output and from the optional `--out` report. `--service dss` selects DSS
instead of RPS. By default an Offline LOCALQUERY response is checked again with
MULTIQUERY: the same camera can return Offline to the former and Online with a
usable relay route to the latter. `--multi` requests MULTIQUERY directly.

To verify login with the camera's own username and password:

```powershell
python -m xmplayer.core.legacy_cli cloud-id-login-probe
```

The command prompts for Cloud ID, camera username, and camera password. It obtains
fresh service codes, finds an RPS relay, negotiates encryption and verifies the
camera's login response. It does not read the cloud account login or use a token
copied from a phone. Only a matching login acknowledgment with `Ret:100` counts
as success. Password rejections are reported without automatic retries.

The connection closes after the check; this command does not start video. Its
worker has a 60-second hard limit (`--deadline`) and reports its current stage
and elapsed time. `--out` writes a result without credentials or session keys.

If the result is `tls_verification_failed`, the optional `--insecure` flag disables
certificate verification for either command. Both diagnostics use Python without
loading FunSDK/NetSDK libraries and do not need FFmpeg.

Cloud ID password login and live video have also been verified in the GUI on the
target camera. No FunSDK/NetSDK runtime, phone, or cloud account is required for
this connection method.

## Notes

- **Fullscreen** shows only the video. Move the pointer to the bottom edge to reveal the playback controls; move it away to hide them. Press **Esc** or click **Fullscreen** again to restore the window.
- **Camera Wi-Fi** opens a network settings window. Refresh reads `NetWork.Wifi` and asks the camera to scan nearby networks with `WifiAP` (command 1020). Choose a network from the camera's list and enter its Wi-Fi password. The SSID and security type come from the selected row; there is no manual SSID input. **Connect camera** sends the new settings after confirmation and stops video while the camera changes networks. Other network configuration fields are preserved. If scanning fails or returns no networks, connecting is disabled until a fresh scan succeeds.
- Wi-Fi settings use the existing cloud/P2P connection; a connected Android phone, ADB, and Frida are not required. The password is not saved to a local file. If the camera disconnects before acknowledging the write, the program reports an unconfirmed save and requires a fresh settings read before another attempt.
- The Wi-Fi commands follow the [FunSDK network settings example](https://github.com/jlinklab/jlink-funsdk-android-demo/blob/main/app/src/main/java/demo/xm/com/xmfunsdkdemo/ui/device/config/networksetting/presenter/NetworkSettingPresenter.java). Actual network switching must be verified on the target camera; local tests do not establish that it successfully joined the new network.

- `SD` maps to `Extra1`
- The port-6611 relay handshake uses `Base64(auth:client:serial:session)` followed by literal `XXEE`. TCP relay replies without `RandomStr` use the SDK's transport without outer XOR while retaining the authenticated camera claim/login and post-login commands. Reports show `encoding=none` for this mode and `encoding=xor` when a relay key is present. Static SDK analysis and offline relay tests support this behavior; successful video still needs verification on the affected camera.
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
- AMS camera discovery automatically checks the EU, South America, North America and Asia servers. An empty camera list, or a list without the selected camera, continues the search. The working region is remembered for the account and camera and used first on later requests.
- To pin a region, add `"ams_base": "sa"` (or `eu`, `na`, `as`) to `desktop_monitor.local.json`. An official HTTPS AMS server URL is also accepted. The optional `XMPLAYER_AMS_BASE` environment variable applies when the config leaves `ams_base` empty. A pinned region disables fallback to other AMS servers.
- AMS sessions are reused for up to 15 minutes, bounded by token expiry. Session/region data is kept in the ignored, local `xmplayer/config/ams_cache.json`; it contains authentication tokens, not the login password or raw login responses. It is bound to the machine, account, credentials and region override. Camera token caches are also invalidated when those settings change. Repeated diagnostics reuse valid tokens instead of forcing another login.
- Caches in `xmplayer/config/` are machine-bound. If copied to another PC, `token_cache.json`, `relay_cache.json`, and `agent_client_uuid.txt` are ignored and recreated automatically.
- To force the legacy fixed `agent_client_id` from config for a one-off test, set `XMPLAYER_USE_CONFIG_AGENT_CLIENT_ID=1` before starting the app.
- If live video, recordings, or message images do not load on another PC, run `diagnose_xmplayer.cmd`. It writes a short report to `diagnostics.txt`.
- For errors such as `random_str_missing`, the report includes per-attempt `AgentProtocol` HTTP status, server error code/text, protocol mode, response field names and types, and the presence/type/length of `RandomStr`. An absent key, JSON `null`, and an empty string are reported separately. Key and token values are omitted, and known secrets are redacted from server error text. The final summary includes up to 32 responses plus the selected response; progress metadata is also saved as it arrives. Raw response bodies are not written to the report. The report still contains local paths and network addresses, which you can remove before sharing it publicly.
- The live control probes print their current stage and elapsed time, with waiting updates at least every 10 seconds. Each runs in a separate process with a 70-second limit, so a blocked network call cannot hold up the report indefinitely. Safe `AgentProtocol` metadata is saved as soon as a response arrives, even if a later connection step times out.
- The other PC must be able to reach the camera cloud/relay hosts and UCloud image URLs. A firewall/VPN/proxy difference can break video, recordings, and message thumbnails at the same time.
- If another PC can connect to `6611` but every first handshake times out, compare `public ip direct` in `diagnostics.txt`. Some relay paths appear sensitive to the tunnel exit IP.
- Optional network override: set `XMPLAYER_SOCKS5_PROXY=127.0.0.1:1080` before starting `diagnose_xmplayer.cmd` or `start_xmplayer.cmd` to route both control HTTPS and raw `6611` TCP through the same SOCKS5 proxy.
- First-6611 relay search can be tuned with `ICSEE_RPSCMD_MAX_ATTEMPTS` and `ICSEE_FIRST6611_HANDSHAKE_TIMEOUT`; defaults are 24 attempts and a 2 second silent-handshake cutoff.
