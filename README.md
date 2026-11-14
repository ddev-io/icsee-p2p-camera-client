# xmplayer

Desktop viewer for an iCSee / XMEye-family camera. Connect through your app account or directly by **Cloud ID + camera username and password**.

The camera protocol is implemented in Python. No FunSDK/NetSDK runtime or VMS is required. Both connection methods still use the manufacturer's cloud services; Cloud ID sign-in does not make the connection offline or LAN-only.

## Features

- Live **SD / HD** video, fullscreen and PNG screenshots.
- Camera recordings: list, playback and MP4 download with audio when available.
- PTZ controls and camera Wi-Fi network selection, where supported by the device.
- G.711 A-law audio playback on Windows.
- Cloud event messages and images when signed in to an app account, with saving of original images.
- Connection progress, automatic recovery from interrupted video and diagnostic commands.

One camera is selected at a time. Feature availability depends on the camera, firmware and access permissions.

## Platforms and requirements

| Platform | Current status |
| --- | --- |
| Windows | Live video has been verified. Audio uses Windows WinMM. |
| Linux | Python transport and Tkinter GUI are intended to be portable, but have not been verified here. Audio playback is unavailable. |
| macOS | Same portability status as Linux; audio playback is unavailable. |

Requirements: **Python 3.11+**, Tkinter, the packages in `requirements.txt`, and **FFmpeg** for video playback. Some Python distributions install Tkinter separately. Window behavior and scrolling may need adjustments on untested platforms.

FFmpeg is needed for video playback and saving recordings as MP4. Connection setup, camera Wi-Fi settings, recording lists, messages and saving message images can be used without it. Use a build with HEVC decoding, PPM/image2pipe output, MP4 muxing and AAC encoding support; a VMS-specific FFmpeg build is not required.

## Install and run

From the project folder, create a virtual environment and install the Python dependencies.

**Windows:**

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python run_gui.py
```

**Linux / macOS** (not yet verified):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run_gui.py
```

Install [FFmpeg](https://ffmpeg.org/download.html) separately and make `ffmpeg` available on `PATH`, or set `ffmpeg_path` to its executable. On Windows, an existing portable copy is also found at `ffmpeg/ffmpeg.exe` or `ffmpeg/bin/ffmpeg.exe`.

The Windows `.cmd` helpers use Python from `PATH`. When using the virtual environment above, launch it with `.venv\Scripts\python` as shown instead.

## Connect a camera

At first launch, choose a connection method:

| Method | Credentials | Camera selection |
| --- | --- | --- |
| **iCSee / XM account** | Username/email and password used in the mobile app | Retrieves the first camera on the account |
| **Cloud ID** | Camera Cloud ID, camera username and camera password | Uses the specified camera without signing in to an app account |

The camera password is separate from the app account password and the Wi-Fi password. An empty camera password is supported if that is how the device is configured. Cloud ID password login and live video have been verified on the target camera; compatibility with every XMEye-family model is not established.

Click **Play** to connect. The initial cloud/P2P negotiation can take tens of seconds; follow the progress indicator. To change the method, credentials or camera, click **Stop**, wait for playback to stop, then open **Connection...**.

Settings are saved in `desktop_monitor.local.json`; account credentials use `login.txt`. Both files are local, contain credentials in plaintext and are ignored by Git. Switching to Cloud ID preserves the saved account credentials. When moving to another computer, configure the connection there; session caches are machine-bound.

Cloud ID mode supports live video, recording operations and camera Wi-Fi settings. **Messages** requires an app account and is disabled in Cloud ID mode. A rejected camera username/password stops the connection attempt without repeated password retries.

## Video and controls

- **SD** selects the camera's `Extra1` sub-stream; **HD** selects its `Main` stream. These names select camera streams, not fixed resolutions: size, frame rate and bitrate depend on the device settings.
- The GUI decodes each stream at its **source resolution**, including HD. It scales the image only to fit the window, preserving aspect ratio. PNG screenshots use the selected layout before window scaling.
- **Horizontal / Vertical** changes the layout for cameras that combine two views into a stacked frame. Use Vertical to keep the original frame arrangement; Horizontal splits and places the two views side by side.
- **Fullscreen** displays only video. Move the pointer to the bottom edge to reveal the controls; move it away to hide them. Press **Esc** or click Fullscreen again to restore the window.
- **PTZ** opens directional controls when supported. **Voice** and **Intercom** are not implemented; receiving camera audio is separate from those buttons.
- **Camera Wi-Fi** scans networks visible to the camera. Select an SSID from the list and enter its Wi-Fi password. Applying settings stops playback and can disconnect the camera; successful joining of a new network still needs verification on the target camera.

## Save recordings and message images

In **Recordings**, click **Save** next to a clip and choose an MP4 filename. Saving stops playback and uses the camera's recording stream. Progress, **Cancel**, and the final result appear inside that recording's card; wait for saving to finish before opening another camera session. Warnings and errors are shown in the card without opening a dialog. FFmpeg copies the original compressed video without resizing or re-encoding and adds AAC audio when G.711 A-law audio is present.

Once data arrives, progress uses recording timestamps when recognized, or the received bytes and camera-reported clip size otherwise. A `~` marks an approximate percentage. If neither is available, the indicator shows activity and received megabytes. Download progress stays below 100% until MP4 creation and saving finish; a size estimate does not confirm that the whole clip arrived.

When recording timestamps are recognized, the download checks them against the selected time range and reports an error if it ends early. Other XStream header formats can still be saved: the app uses camera or encoded-video frame-rate information where available and displays a warning if it cannot verify the full time range or playback timing. It preserves the received video without forcing it to the requested duration; check the saved clip when a warning appears. The camera must remain online during downloading. Cancellation removes temporary files; an existing destination is replaced only after MP4 creation succeeds. This export path has not yet been verified on the target camera.

In **Messages**, click the download icon to the left of an image or open it and use **Save** in the viewer. The original downloaded image is saved, without thumbnail scaling or the viewer's layout changes. Keeping its original format preserves the original bytes; selecting PNG or JPEG converts the full-size image. The result or error is displayed in the messages page and the open viewer, without a popup. Messages and their images require app account sign-in.

The current GUI video decoder is configured for **H.265/HEVC**. H.264 playback is not implemented. There is no built-in RTSP/HTTP restreaming server or multi-camera grid.

## Configuration

Edit `desktop_monitor.local.json` when it exists; otherwise edit `desktop_monitor.json`. The local file takes precedence over the default file as a complete configuration.

| Setting | Purpose |
| --- | --- |
| `device_name` | Window title and camera label |
| `default_quality` | Initial `sd` or `hd` stream |
| `ffmpeg_path` | `ffmpeg` on `PATH`, or a path to the executable |
| `display_mode` | `raw` for the original frame arrangement; `stacked_split` for horizontal dual-view layout |
| `playback_fps` | GUI display rate; does not change the camera's encoded frame rate |
| `window` | Initial size and `start_fullscreen` |
| `ams_base` | Optional account-service region: `eu`, `sa`, `na` or `as`; leave unset for automatic discovery |

## Connection problems

1. Confirm that the camera is powered on, has internet access and opens in the mobile app. An offline response is different from a rejected camera password.
2. For Cloud ID sign-in, check the device credentials rather than the app account credentials. If the camera reports a locked user, wait before trying again.
3. If video fails, check the FFmpeg path and HEVC support. A successful login alone does not guarantee that media has arrived or can be decoded.
4. If the connection fails on another network or computer, check firewall, VPN and proxy differences. The client needs access to the vendor's HTTPS services and TCP relay connections, commonly port 6611.

Run diagnostics using the same Python environment as the GUI:

```sh
python diagnose_xmplayer.py
```

This writes `diagnostics.txt` with progress and response metadata. Each live connection probe has a 70-second limit. The report excludes credential and session-key values, but can contain local paths and network addresses.

For Cloud ID discovery or an isolated device-password login check:

```sh
python -m xmplayer.core.legacy_cli cloud-id-status
python -m xmplayer.core.legacy_cli cloud-id-login-probe
```

Status discovery does not need the camera username/password or an app account. The login probe prompts for the camera credentials, has a 60-second deadline, and closes the connection after checking authentication. Neither command starts video or needs FFmpeg. Use the virtual environment's Python path in place of `python` where needed.

## Related project

[xmeye_cloud_to_rtsp](https://github.com/wire67/xmeye_cloud_to_rtsp) focuses on forwarding camera video to other applications, including MediaMTX integration. It uses Windows NetSdk DLLs. Its SDK-version requirements, RTSP setup and FFmpeg network-serving instructions apply to that project; xmplayer uses its own Python transport and local GUI playback.
