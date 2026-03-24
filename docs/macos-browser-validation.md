# macOS Browser Validation

This guide gives us one repeatable way to validate experimental browser support on macOS without drifting between ad hoc commands.

## Goals

- launch the browser by its real inner executable, not `open -a`
- use a fresh profile for each validation run
- keep WrapGuard logs in a known location
- distinguish "browser never starts", "browser starts but does not browse", and "browser browses through the VPN"

## Preconditions

- run on macOS
- build the repo-root artifacts with `make build`
- use a non-SIP target application
- use a real WireGuard config file that already works with a CLI probe

Validate the tunnel path first:

```bash
./wrapguard --config=../NL-US-PA-16.conf -- /opt/homebrew/opt/curl/bin/curl https://icanhazip.com
```

If that does not return the VPN IP, stop there. Browser validation is not the next thing to debug.

## Repeatable Harness

Use the new `make smoke-macos-browser` target.

LibreWolf / Firefox-style example:

```bash
make smoke-macos-browser \
  WG_CONFIG=../NL-US-PA-16.conf \
  BROWSER_APP="/Applications/LibreWolf.app/Contents/MacOS/librewolf" \
  BROWSER_ARGS_TEMPLATE="--no-remote -profile __PROFILE__" \
  WG_LOG_FILE=/tmp/wrapguard-librewolf.log
```

Brave / Chromium-style example:

```bash
make smoke-macos-browser \
  WG_CONFIG=../NL-US-PA-16.conf \
  BROWSER_APP="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  BROWSER_ARGS_TEMPLATE="--user-data-dir=__PROFILE__ --no-first-run --no-default-browser-check --new-window" \
  WG_LOG_FILE=/tmp/wrapguard-brave.log
```

How it works:

- `__PROFILE__` is replaced with a fresh temporary profile directory unless `BROWSER_PROFILE_DIR` is provided
- WrapGuard is rebuilt first so the binary and dylib stay in sync
- WrapGuard logs go to `WG_LOG_FILE`
- the target browser is launched directly through WrapGuard with debug logging enabled

## Manual Validation Flow

After launch:

1. open `http://icanhazip.com`
2. confirm the page shows the VPN IP, not the host IP
3. refresh several times
4. open DevTools and confirm the browser remains stable
5. compare the browser result against a direct CLI probe if anything looks wrong

## Result Buckets

Record each run in one of these buckets:

- `startup-failed`
  - browser never reaches a usable window
  - log focus: handshake, helper startup, GPU/compositor failures
- `startup-only`
  - browser window opens, but pages do not load
  - log focus: intercepted `CONNECT` traffic versus local IPC-only noise
- `tunneled`
  - browser reaches a page and the public IP is the VPN IP
  - keep notes on refresh behavior and DevTools stability
- `regressed`
  - browser used to work in the same setup but no longer does
  - capture the exact command, app version, and log path

## What To Watch For

- repeated `AF_UNIX` / local IPC logs are expected and are not proof of a network leak
- GPU/helper warnings may still appear even when browsing works
- browser-visible host IP after a soft refresh can still indicate cache, service-worker, or QUIC / HTTP3 behavior rather than a total loss of TCP interception
- on macOS today, UDP is not a supported tunneled transport; WrapGuard only tries to suppress likely browser QUIC traffic enough to push browsers back toward the proven TCP path

## Current Known-Good Result

Current experimental known-good validation on Apple Silicon:

- LibreWolf launches via its inner executable
- `http://icanhazip.com` shows VPN IP `146.70.156.18`
- repeated refreshes keep showing the VPN IP
- DevTools opens without the earlier recursion crash

That is a real breakthrough, but it is still not the final product bar for all GUI apps. Broader app coverage and automated regression checks are still open.
