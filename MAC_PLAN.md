# macOS Production Plan

This document is a full checklist for taking WrapGuard from "claims macOS support" to a production-ready macOS implementation.

Current shipping stance:

- Linux remains the production target.
- macOS direct-launch support is experimental but now has platform-specific launcher validation, packaging, and CI coverage.
- GUI support is limited to experimental launches where WrapGuard can target the real inner executable; `.app` bundle paths are now resolved to `Contents/MacOS/...` when unambiguous, but `open -a` remains unsupported.

## Implementation Findings

This section captures the macOS debugging work that got WrapGuard from "the dylib loads" to "real child traffic exits through the VPN".

### What We Observed First

The initial macOS runs showed that Homebrew `curl` was being wrapped and the interceptor was loading, but public IP checks still returned the host IP `217.169.19.26`.

The important debug sequence was:

- `DYLD_INSERT_LIBRARIES` was active
- the interceptor constructor fired
- `connect()` to `icanhazip.com` was intercepted
- the child socket was redirected to the local SOCKS5 server
- WrapGuard logged that the destination should be routed through the WireGuard peer
- the request still exited with the host IP

That told us the problem was no longer "macOS injection is broken". The failure had moved deeper into the forwarding path.

### What We Tried That Did Not Solve It

These were important dead ends or partial wins:

- Fixing the macOS launcher and dylib naming mismatch:
  This was necessary, but it only got us to the point where interception actually happened. It did not make tunneled traffic work.
- Adding the interceptor readiness handshake and debug logs:
  This proved the dylib was loading correctly, but it did not address the actual egress path.
- Suspecting Little Snitch or generic macOS socket interception issues:
  Once we saw real intercepted `connect()` calls and successful SOCKS5 handshakes, this was no longer the primary blocker.
- Relying on the old `DialWireGuard` implementation:
  This was the real architectural problem. The code selected a peer, logged that it would route through WireGuard, and then for most real destinations fell back to a normal host-side `net.Dialer`. That direct fallback preserved the host public IP, so the VPN was never actually carrying the outbound TCP connection.

### What Finally Worked

The fix that made the real macOS public-IP test pass was replacing the stubbed direct-dial path with WireGuard's userspace netstack.

Specifically:

- `NewTunnel(...)` now creates a `tun/netstack` device from the upstream WireGuard module instead of relying on the old placeholder memory-only dial path.
- Routed outbound TCP now uses the netstack-backed tunnel dialer.
- Routed inbound TCP listeners also use the netstack-backed listener path.
- The old "hostname mapping" fallback for demo targets was removed from the real routing path, so routed traffic no longer escapes through a normal host socket.

Why this worked:

- The interceptor and SOCKS server were already doing the right thing conceptually.
- The missing piece was a real TCP/IP transport bound to the WireGuard device.
- The upstream WireGuard userspace netstack provides exactly that: a userspace TCP/IP stack whose dials and listeners are carried over the WireGuard tunnel rather than the host network stack.

### Additional Bug Found Along The Way

Once real tunneled traffic started working, a second bug showed up in the interceptor's SOCKS5 response handling:

- HTTPS to `icanhazip.com` worked reliably after the netstack change.
- Plain HTTP could still fail because the interceptor assumed the SOCKS5 `CONNECT` response would arrive as a single fixed-size `recv()`.

That was too brittle. The final fix was to make the interceptor read the SOCKS5 reply incrementally and correctly handle variable-length address payloads. After that change, both HTTP and HTTPS requests worked through the tunnel on macOS.

### Bind-Path Follow-Up

As the smoke coverage expanded beyond outbound `connect()`, another macOS-specific interposition issue showed up around `bind()`:

- smoke probes that exercised loopback listeners under DYLD injection could still crash when the interceptor tried to hand `bind()` back through the generic symbol-resolution path
- that means outbound TCP is now proven and reasonably covered, but inbound listener handling on macOS should still be treated as a separate stability item rather than assumed solved
- the current smoke suite continues to verify the safer outbound pieces:
  - the interceptor announces readiness
  - loopback `connect()` bypass works without recursive interception
  - real outbound `connect()` calls are intercepted and reported

That does not block the proven CLI outbound path, but it means `bind()` behavior should stay in the "needs more macOS-specific validation" bucket.

### Final Verified Result

Using the real macOS config `../NL-US-PA-16.conf`:

- Host IP before WrapGuard: `217.169.19.26`
- Wrapped Homebrew `curl https://icanhazip.com`: `146.70.156.18`

So the concept is now proven on macOS:

- the child process is injected successfully
- outbound `connect()` calls are intercepted
- the SOCKS handoff works
- the WireGuard tunnel carries real outbound TCP traffic
- the observed public IP differs from the host IP

### Current GUI App State

GUI apps are still experimental on macOS, but LibreWolf is no longer stuck in the earlier "starts badly or not at all" state.

Latest confirmed LibreWolf result:

- launching the inner executable injects the WrapGuard dylib successfully
- the browser can start, stay up, and open DevTools without hitting the earlier recursive crash
- `http://icanhazip.com` returns the VPN IP `146.70.156.18` in the wrapped browser
- repeated refreshes in the same validation run also continue returning the VPN IP instead of the host IP
- expected browser-local `AF_UNIX` traffic is still bypassed correctly
- helper / GPU warning noise still appears in stderr, but it no longer prevents real browsing in the latest validated run

The key fixes that unlocked that state were:

- making macOS passthrough helper processes more inert during startup
- using raw Darwin syscall fallback for non-intercepted `connect()` paths instead of re-entering the generic hook chain
- suppressing per-call debug noise for high-volume `AF_UNIX` `SOCK_DGRAM` browser IPC
- removing Darwin `getpeername()` interposition after live browser sampling showed Firefox socket-thread time disappearing into that hook before useful requests completed

Important clarification from the more recent regression history:

- the older "near miss" was real:
  - LibreWolf could start
  - the first browser-visible IP check could show the VPN IP
  - later softer refresh behavior could show the host IP instead
  - HAR comparison strongly suggested that the good result was `HTTP/2` and the bad result was `HTTP/3`
- the later browser regression was real:
  - some LibreWolf runs hung for about 20 seconds during startup, then only opened after GPU timeout and software-render fallback
  - some runs did not reach a usable browser window at all
- so there are now two distinct browser problems to track:
  - the older browser leak path, where startup succeeded but later browser-visible traffic could escape the tunnel
  - the later startup-stability regression, where helper-process injection was breaking the browser before network correctness could be evaluated again

Additional concrete evidence from the latest working LibreWolf run:

- the browser launched normally enough to load `http://icanhazip.com`
- the rendered page showed the VPN IP `146.70.156.18`
- repeated refreshes kept returning the VPN IP in that same run
- opening DevTools no longer triggered the earlier recursive `wrapguard_connect` crash
- residual stderr noise still appeared, including:
  - `LibreWolf GPU Helper ... Connection Invalid error for service com.apple.hiservices-xpcservice`
  - `UNSUPPORTED (log once): POSSIBLE ISSUE: unit 1 GLD_TEXTURE_INDEX_2D is unloadable...`
  - occasional SOCKS-side teardown noise such as `connection reset by peer`
- those remaining warnings are worth tracking, but they did not prevent successful tunneled browsing in the latest validation

Additional concrete evidence from a later LibreWolf run:

- the long stream of `AF_UNIX` `connect()` calls followed by `NOT intercepting` is expected and is not, by itself, evidence of a networking bug
- multiple injected helper processes announced readiness, confirming that DYLD injection is propagating into the browser's process tree rather than only the initially launched binary
- real outbound HTTPS destinations such as `151.101.61.91:443`, `34.107.243.93:443`, and `185.199.109.153:443` were intercepted and completed the SOCKS5 handshake successfully
- the browser still failed afterward with macOS/browser-process errors such as:
  - `Failed as lost WebRenderBridgeChild`
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`
  - `child bootstrap_look_up failed`
  - `LibreWolf GPU Helper ... Connection Invalid error for service com.apple.hiservices-xpcservice`
  - `Exiting due to channel error.`

Additional concrete evidence from the later fresh-profile run:

- launching the inner executable with a fresh profile and `--new-instance --no-remote -profile ...` gets materially farther than launching the app against the default running profile
- that makes it much less likely that the remaining failure is just "LibreWolf handed off to another already-running instance"
- the very long `AF_UNIX` stream is still expected browser-local IPC traffic and is still being bypassed correctly by WrapGuard
- after those `AF_UNIX` calls, real outbound TCP connections such as `34.107.243.93:443` and `151.101.61.91:443` were again intercepted and completed the SOCKS5 handshake successfully
- those successful browser-originated TCP interceptions happened even after compositor and GPU helper instability had already started appearing in the logs
- the browser still failed afterward with macOS helper-process and graphics/process-channel errors such as:
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`
  - `Failed as lost WebRenderBridgeChild`
  - `LibreWolf GPU Helper ... Connection Invalid error for service com.apple.hiservices-xpcservice`
  - `Exiting due to channel error.`
- the fresh-profile run also showed intercepted browser sockets using non-blocking connect semantics before the SOCKS handshake completed, for example:
  - `Non-blocking connect in progress, waiting...`

Additional concrete evidence from the later "did not crash, but only the first IP check tunneled" run:

- LibreWolf stayed up long enough to complete an initial public-IP request through the VPN instead of crashing immediately
- after that first apparent success, later browser-visible IP checks still showed the host IP rather than the VPN IP
- during the same run, WrapGuard continued logging many real outbound `AF_INET` `SOCK_STREAM` connections from injected LibreWolf processes
- those later browser-originated TCP connections still completed the SOCKS5 handshake successfully, including repeated successful connections to real remote `:443` destinations such as:
  - `151.101.61.91:443`
  - `34.107.243.93:443`
  - `34.160.144.191:443`
  - `172.65.251.78:443`
  - `185.199.109.153:443`
  - `104.16.185.241:443`
- the very large volume of `AF_UNIX` `SOCK_DGRAM` `connect()` calls remained visible and remained correctly bypassed, which is still expected browser-local IPC rather than proof of a network leak

Additional concrete evidence from the later "hard refresh shows VPN IP, soft refresh falls back to host IP" run:

- LibreWolf again emitted a very large stream of `AF_UNIX` `SOCK_DGRAM` `connect()` calls followed by `NOT intercepting`, which is still expected browser-local IPC noise rather than direct evidence of a network leak
- multiple browser helper processes still announced interceptor readiness, so DYLD injection was continuing to propagate into the browser process tree
- real outbound browser TCP traffic continued to be intercepted and successfully handed through SOCKS, including repeated successful handshakes to destinations such as:
  - `34.107.243.93:443`
  - `151.101.61.91:443`
  - `172.65.251.78:443`
  - `34.160.144.191:443`
  - `185.199.109.153:443`
  - `104.18.12.93:443`
  - `104.16.175.226:443`
  - `82.165.93.184:443`
- those intercepted browser sockets again showed non-blocking connect behavior before the SOCKS handshake completed, for example:
  - `Non-blocking connect in progress, waiting...`
- browser-visible behavior was more specific than before:
  - the first request could show the VPN IP
  - a normal in-page refresh could later show the host IP
  - a hard refresh of the same page could then show the VPN IP again
- the run still produced browser/helper instability signals such as:
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`
  - `Failed as lost WebRenderBridgeChild`
  - `LibreWolf GPU Helper ... Connection Invalid error for service com.apple.hiservices-xpcservice`
  - `Exiting due to channel error.`
- the SOCKS server also logged `broken pipe` write failures while servicing some intercepted browser TCP flows, which is consistent with the browser canceling or tearing down some requests mid-flight and is worth tracking, but does not by itself prove the tunneled path is wrong

Additional concrete evidence from the latest follow-up LibreWolf run:

- the same high-level pattern still holds: hard refreshes can show the VPN IP while softer refresh behavior can still fall back to the host IP
- the very large stream of `AF_UNIX` `SOCK_DGRAM` `connect()` calls followed by `NOT intercepting` is still present and still looks like expected browser-local IPC noise rather than direct evidence of the leak path
- during that same run, WrapGuard continued intercepting and successfully completing SOCKS5 handshakes for real outbound browser TCP connections to additional remote `:443` destinations such as:
  - `172.66.45.19:443`
  - `35.185.44.232:443`
- the existing repeated successful browser TCP interceptions to destinations such as `34.107.243.93:443`, `151.101.61.91:443`, `172.65.251.78:443`, `34.160.144.191:443`, `185.199.109.133:443`, `185.199.109.153:443`, `104.18.12.93:443`, `104.16.175.226:443`, and `82.165.93.184:443` were also still visible in the same run
- those intercepted sockets again showed `Non-blocking connect in progress, waiting...`, which keeps the non-blocking-socket compatibility item open
- the helper-process instability signal also remained very consistent, including:
  - `LibreWolf GPU Helper ... Connection Invalid error for service com.apple.hiservices-xpcservice`
  - `Failure on line 688 in function id scheduleApplicationNotification(...)`
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`

Additional concrete evidence from the later non-blocking follow-up run:

- the browser again emitted a very large stream of `AF_UNIX` `SOCK_DGRAM` `connect()` calls followed by `NOT intercepting`, which still looks like expected browser-local IPC traffic rather than the direct leak path
- during the same run, the browser also continued making real outbound `AF_INET` `SOCK_STREAM` connections that WrapGuard intercepted successfully, including repeated successful SOCKS5 handshakes for destinations such as:
  - `151.101.61.91:443`
  - `34.107.243.93:443`
  - `34.160.144.191:443`
  - `185.199.109.153:443`
  - `185.199.109.133:443`
  - `35.185.44.232:443`
  - `82.165.93.184:443`
  - `104.18.12.93:443`
  - `104.16.175.226:443`
  - `172.66.47.179:443`
  - `104.20.35.99:443`
- those intercepted browser sockets now explicitly logged:
  - `Preserving non-blocking connect semantics after SOCKS5 handshake`
- that is important because it shows the interceptor is no longer simply forcing a synchronous-success story for those browser sockets; the wrapped socket path is now at least attempting to preserve the caller's non-blocking expectations
- despite that, the browser could still show the host IP on softer refresh behavior while hard-refresh-style requests and other raw browser TCP connections still visibly traversed the intercepted SOCKS path in the same run
- the SOCKS server also logged transient request teardown errors such as:
  - `connection reset by peer`
  - `broken pipe`
- those SOCKS-side teardown errors are consistent with browser request cancellation or mid-flight socket teardown and do not, by themselves, prove that the tunnel path is wrong
- the helper/GPU/compositor instability signal still remained present in the same run, including:
  - `LibreWolf GPU Helper ... Connection Invalid error for service com.apple.hiservices-xpcservice`
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`
  - `Fallback WR to SW-WR`

Follow-up implementation finding after the same browser leak investigation:

- the current macOS path still only interposes fresh socket operations and still only tunnels `SOCK_STREAM`, so browser-visible paths that reuse existing sessions or leave the fresh TCP `connect()` model can still bypass the proven path
- the most actionable short-term mitigation in code was to suppress likely QUIC traffic on macOS by rejecting outbound non-loopback UDP `connect()` calls to port `443` for wrapped children
- that mitigation is intentionally narrow:
  - it does not claim to tunnel UDP
  - it exists to push browser traffic back toward the already-proven tunneled TCP path
  - host-side DNS behavior remains unchanged
- an attempt to also interpose broader UDP `sendto()` traffic was backed out because it destabilized the smoke suite; if another agent revisits UDP suppression, start from the narrower `connect()` mitigation rather than the broader `sendto()` hook
- a separate code-level gap remained around socket-state virtualization:
  - after SOCKS handoff, the kernel still sees the fd as connected to loopback
  - WrapGuard now virtualizes `getpeername()` for successfully wrapped TCP sockets so callers no longer immediately observe the loopback SOCKS peer
  - broader browser/socket-state compatibility is still not fully solved, so this remains an active validation area rather than a closed browser-support item
- follow-up implementation finding after the HAR comparison:
  - the current macOS QUIC mitigation is too narrow for browser-grade correctness
  - rejecting only outbound UDP `connect()` to remote `:443` is not enough, because the browser can still produce a bad HTTP/3 result by reusing or continuing a QUIC path that does not present as a fresh intercepted TCP connect
  - a proper solution therefore needs to treat QUIC / HTTP/3 as a first-class transport problem rather than assuming that successful TCP interception is sufficient
- follow-up implementation finding after the HAR-export crash:
  - the current debug logging mechanism is too recursive for safe browser diagnostics on macOS
  - any serious browser-support work needs a non-recursive observability path before deeper browser debugging is considered production-worthy

That latest run does not really support the theory that "WrapGuard stopped intercepting later browser TCP". It instead strengthens the existing conclusion that:

- real intercepted browser TCP can continue succeeding in the same session where the browser later reports the host IP
- the host-IP soft-refresh result is therefore more likely coming from a different browser-visible path such as cache/service-worker reuse, alternate transport selection, browser-side UDP behavior, or another non-equivalent helper/process path

That combination tightens the current browser hypothesis further:

- this is no longer well-described as "only the first request used the tunnel"
- successful hard-refresh results strongly suggest that real end-to-end browser TCP requests can still use the tunnel after the browser is already running
- the softer-refresh host-IP result makes cache reuse, service-worker behavior, connection reuse, alternate transport selection, or another non-intercepted browser networking path more plausible than a simple failure of all later TCP interception
- in other words, some browser-visible fetch paths appear to differ materially from the successfully intercepted `AF_INET` `SOCK_STREAM` path already visible in the logs
- the newer non-blocking follow-up run strengthens that further: even after explicitly preserving non-blocking socket semantics, real browser TCP interception still continued in the same session where softer refresh behavior could still show the host IP
- that makes the remaining leak look even less like "non-blocking `connect()` broke all later browser TCP" and more like "some browser-visible paths are bypassing the intercepted fresh TCP `connect()` model entirely"

Additional concrete evidence from the latest hard-refresh-versus-soft-refresh follow-up:

- the very large stream of `AF_UNIX` `SOCK_DGRAM` `connect()` calls followed by `NOT intercepting` is still present and still looks like expected browser-local IPC traffic rather than direct evidence of the leak path
- the higher-signal part of the run remained the same:
  - fresh requests tunneled
  - hard refreshes tunneled
  - softer refresh behavior could still show host egress
- during that same run, WrapGuard continued intercepting real outbound browser TCP connections to remote `:443` destinations such as:
  - `151.101.61.91:443`
  - `34.107.243.93:443`
  - `185.199.111.153:443`
  - `172.66.147.148:443`
  - `104.16.185.241:443`
- those intercepted browser TCP sockets again completed the SOCKS5 handshake successfully and again logged:
  - `Preserving non-blocking connect semantics after SOCKS5 handshake`
- the run also continued to show browser/helper instability and request teardown noise, including:
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`
  - `Fallback WR to SW-WR`
  - `connection reset by peer`
- taken together, this run still does not really support the theory that the browser's later TCP traffic is no longer being intercepted
- it instead strengthens the narrower current hypothesis:
  - WrapGuard's proven path is still fresh outbound browser TCP `connect()`
  - some softer-refresh browser-visible result is likely being served through another browser path such as connection reuse, cache or service-worker behavior, alternate transport selection, or another helper/process path that does not map cleanly onto a fresh intercepted TCP `connect()`

Additional concrete evidence from the later HAR-backed protocol comparison:

- side-by-side HAR captures of the same browser/IP-check workflow finally exposed a concrete protocol difference between the "good" and "bad" outcomes
- the good request to `https://ifconfig.me/ip` returned the VPN IP `146.70.156.18` and the HAR recorded it as:
  - `HTTP/2`
  - with non-zero `dns`, `connect`, and `ssl` timings
- the bad request to the same URL returned the host IP `217.169.19.26` and the HAR recorded it as:
  - `HTTP/3`
  - with `dns = 0`, `connect = 0`, and `ssl = 0`
  - `Alt-Used: ifconfig.me`
- that is the strongest evidence so far that the bad browser-visible result is not coming from a fresh TCP path at all
- instead, the bad refresh is consistent with browser reuse of an already-established QUIC / HTTP/3 path, which bypasses the fresh TCP `connect()` interception path that WrapGuard currently proves
- the same high-level result is visible across the logs and the HARs together:
  - fresh tunneled TCP continues to work
  - the bad browser-visible IP is associated with HTTP/3 rather than HTTP/2

Additional concrete evidence from the later HAR-export crash:

- exporting the HAR from the bad browser state crashed LibreWolf under DYLD injection
- the macOS crash report showed:
  - `EXC_BAD_ACCESS (SIGSEGV)`
  - `Thread stack size exceeded due to excessive recursion`
  - thousands of recursive frames through `libwrapguard.dylib ... wrapguard_connect`
- the crashing stack ran through `fprintf` and Apple logging / sandbox / graphics paths before re-entering `wrapguard_connect`
- that means the current verbose debug logging path is itself unsafe for some GUI/browser code paths on macOS
- this does not explain the wrong-IP result directly, but it does mean the current `fprintf`-style browser debug logging is not a viable production-grade observability path

Additional concrete evidence from the most recent browser regression:

- recent LibreWolf runs now commonly stall for about twenty seconds before a window appears
- those runs emit startup-failure signals such as:
  - `Killing GPU process due to IPC reply timeout`
  - `Failed as lost WebRenderBridgeChild`
  - `Fallback WR to SW-WR`
  - `CompositorBridgeChild receives IPC close with reason=AbnormalShutdown`
- in those latest runs, multiple helper processes still announce `READY`, which means DYLD injection is propagating into the browser process tree
- however, those same runs often show little or no useful browser `CONNECT` activity before the startup timeout fires
- that makes the current blocker meaningfully earlier than the old `HTTP/3` leak path:
  - the current browser is frequently failing during helper / GPU / compositor startup
  - the old "first request tunneled, later request leaked" problem can only be retested after startup stability is restored

Additional concrete evidence from the Chromium-family check:

- launching Brave against an isolated temporary profile avoids the trivial "existing session" handoff case
- in that isolated-profile run, Brave can briefly appear and then exit
- the WrapGuard launcher log for those runs times out waiting for the injected-library `READY` handshake
- so Chromium-family apps are currently not in a meaningfully better state than LibreWolf on macOS; they are simply failing earlier in a different way

What we tried recently that did not solve the browser regression:

- a macOS GUI compatibility mode that stripped the DYLD environment from descendants after the first injected process initialized:
  - this did not restore LibreWolf startup correctness
  - it is not acceptable as a product-level substitute for transparent app support
- process-role passthrough for Mozilla helper roles:
  - this improved one failure mode enough that LibreWolf could sometimes limp open after timeout
  - it did not restore a clean, stable browser startup
- a macOS `posix_spawn` / `posix_spawnp` reinjection attempt:
  - this caused a recursive launch crash
  - the crash report showed thousands of recursive frames through `wrapguard_posix_spawnp`
  - that entire slice was backed out and should not be treated as an active solution path

That combination matters because it suggests the remaining browser issue is no longer well-described as "only the first request was intercepted" or "TCP stopped using the tunnel". A better framing is:

- intercepted TCP traffic can continue succeeding even while the browser later reports the host IP
- some browser-observed egress is therefore likely taking place outside the currently intercepted TCP `connect()` model
- the highest-priority suspects for the remaining leak are:
  - UDP-based traffic such as QUIC/HTTP3
  - WebRTC/STUN or other browser-side UDP address discovery
  - host-side DNS behavior influencing which path later requests take
  - helper-process-specific networking paths that are not equivalent to the successful TCP path already seen in the logs
- a focused smoke regression now keeps browser-style `AF_UNIX` helper connects in the bypass bucket, so local IPC noise stays distinguishable from real leak traffic

Future browser debugging should explicitly include:

- rerunning with QUIC/HTTP3 disabled
- rerunning with WebRTC disabled
- comparing soft refresh versus hard refresh behavior against the WrapGuard TCP interception log in the same window
- checking for service-worker, cache-mode, or keepalive/connection-reuse differences between the host-IP refresh and the VPN-IP hard refresh
- comparing browser-visible IP checks against raw WrapGuard TCP interception logs in the same window
- checking whether later "host IP" observations correlate with missing TCP intercepts or with traffic classes WrapGuard does not yet tunnel
- checking whether the host-IP soft refresh can still reproduce after a fully fresh browser profile with cache disabled and service workers cleared
- separating "browser stayed stable" from "all browser networking paths are tunneled", because those are now clearly different milestones

That last point is especially important:

- it confirms that some real browser sockets are non-blocking on macOS
- WrapGuard still has to perform a SOCKS handshake synchronously inside the interposition path, even though it now restores `EINPROGRESS` semantics to the caller afterward
- browser traffic can still get through in some cases, but the combination of synchronous handshake work plus browser/helper instability means non-blocking compatibility should still stay on the macOS validation list rather than being treated as fully closed

That combination is important because it narrows the current GUI problem:

- this is not just "the interceptor never loaded"
- this is not just "outbound TCP never reached the SOCKS proxy"
- this looks more like helper-process injection incompatibility, Mach/bootstrap IPC breakage, GPU/compositor helper instability, or browser sandbox/process-architecture issues after injection has already succeeded

This strongly suggests that the remaining GUI problem is not "the tunnel does not work". It is more likely one or more of:

- helper subprocesses inheriting DYLD injection in a way the app does not tolerate
- browser sandboxing or hardened-runtime restrictions
- GPU or compositor helper processes crashing under injection
- process-tree behavior where the directly launched executable is not the only process that matters
- non-blocking browser socket behavior still interacting poorly with the current synchronous-in-the-hook SOCKS handshake path, even though the post-handshake return semantics are now closer to what the caller expects

So the plan below should treat CLI support and GUI/browser support as separate tracks. Real TCP tunneling is now proven for CLI targets, and LibreWolf now has a working experimental path on macOS, but broader GUI compatibility still needs dedicated validation before it can be called supported.

## Current State

Observed gaps in the current source:

- [x] Platform-specific injection config is in place (`LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on macOS).
- [x] The launcher validates macOS targets before launch, resolves unambiguous `.app` bundles to their inner executable, and rejects unsupported SIP-protected paths.
- [x] The Makefile and release workflow package `libwrapguard.dylib` for macOS archives.
- [x] CI runs tests on macOS and includes a macOS smoke-packaging step.
- [x] Real macOS smoke coverage exists for injected `connect()`, localhost bypass, bind reporting, non-blocking `connect()` handling, and likely QUIC UDP/443 suppression.
- [x] Regression coverage now protects wrapped-socket peer-state cleanup across file-descriptor reuse after a wrapped socket closes, so stale virtual peer metadata does not leak into later loopback connections.
  Current status: the interceptor now clears virtual peer state on `close()`, and the smoke suite exercises the close-and-fd-reuse path directly.
- [ ] End-to-end tests proving real child traffic is tunneled on macOS are still limited.
- [ ] GUI inner-executable support remains experimental and should not be treated as production-ready.
- [ ] Browser-style helper-process trees, QUIC / HTTP3 behavior, and non-blocking socket behavior still need broader macOS regression coverage.
- [x] Browser startup stability has been restored enough for current experimental LibreWolf validation on macOS.
  Current status: the latest manual validation loaded LibreWolf, kept it running, allowed DevTools to open, and showed repeated VPN-IP results during refreshes. Broader app-class coverage and regression automation are still open.

## Definition Of Done

macOS support should only be called production-ready when all of the following are true:

- [ ] A wrapped child process actually sends traffic through the WireGuard tunnel on supported macOS versions and architectures.
- [ ] Any GUI targets we decide to support can be launched through their inner executable without destabilizing helper processes.
- [ ] Build, package, sign, and release flows produce consistent macOS artifacts.
- [ ] Automated macOS tests catch regressions in injection, routing, and packaging.
- [x] Documentation clearly explains supported and unsupported macOS cases, including the narrow `.app` support and `open -a` limitations.

## 1. Platform Strategy

- [x] Decide the supported macOS versions.
- [x] Decide the supported CPU architectures: `arm64`, `amd64`, or universal binaries.
- [x] Decide whether GUI app wrapping is in scope or whether support is CLI-only for the first production release.
- [x] Decide whether system binaries protected by SIP are officially unsupported.
- [x] Write an explicit support matrix in the README and release notes.
  Current status: the README now includes the support matrix and the repo now carries checked-in macOS release-note boilerplate.

## 2. Runtime Launcher Abstraction

Files: `main.go`

- [x] Introduce a platform abstraction for dynamic library injection.
- [x] On Linux, keep using `LD_PRELOAD` and `.so`.
- [x] On macOS, use `DYLD_INSERT_LIBRARIES` instead of `LD_PRELOAD`.
- [x] On macOS, decide whether `DYLD_FORCE_FLAT_NAMESPACE` is required for the interposition strategy being used.
  Current status: it is no longer forced for the DYLD path because WrapGuard uses `DYLD_INTERPOSE`; keeping flat-namespace linking enabled was broader and riskier for GUI apps than the hook mechanism requires.
- [x] Build the environment setup through a helper like `buildChildEnv(...)` instead of hardcoding Linux behavior inline.
- [x] Stop hardcoding `libwrapguard.so` in `main.go`.
- [x] Resolve the injected library path by platform: `.so` on Linux, `.dylib` on macOS.
- [x] Fail fast with a clear error if the expected platform library is missing.
- [x] Add debug logging that prints the resolved injection mechanism and library path on startup.

## 3. Dynamic Library Naming And Packaging

Files: `Makefile`, `.github/workflows/release.yml`

- [x] Unify naming between build output and runtime lookup.
- [x] Choose one macOS library name convention and use it everywhere.
- [x] Update the default `build` target so it produces the correct platform-specific library on macOS.
- [x] Ensure release archives contain the exact files the runtime expects.
- [x] Add a packaging validation step that unpacks the release tarball and verifies runtime file names.
- [x] Add a smoke test in release CI that runs the packaged binary, not just the build workspace binary.

## 4. Injection Mechanism On macOS

Files: `lib/intercept.c`, `main.go`

- [x] Verify the current intercept library actually loads on macOS through `DYLD_INSERT_LIBRARIES`.
- [x] Add a constructor or another positive startup signal so tests can prove the library loaded.
- [x] Log an unmistakable "interceptor loaded" message in debug mode.
- [ ] Confirm `dlsym(RTLD_NEXT, ...)` behavior is correct on macOS for `connect` and `bind`.
  Current status: source-level regression checks now pin the intended macOS contract (`DYLD_INTERPOSE`, `RTLD_NEXT` symbol lookup for `connect`, and the raw `bind()` fallback), but `bind()` listener behavior under DYLD interposition still needs a cleaner runtime validation story.
- [x] Confirm the interceptor compiles cleanly under Apple Clang with warnings enabled.
- [x] Add macOS-specific compiler flags if needed.
- [x] macOS smoke tests now cover the injected `connect()` path and bind reporting under DYLD interposition.
- [ ] If `DYLD_INSERT_LIBRARIES` is not sufficient for target processes, switch to a macOS-native interposition approach and document the tradeoff.

## 5. Child Process Launch Semantics

Files: `main.go`

- [x] Verify environment propagation works for subprocesses launched through shells.
- [x] Verify environment propagation works for direct binary exec.
- [x] Decide whether `.app` bundle launching is supported.
- [x] If `.app` support is needed, add a macOS launcher path that targets the inner executable or a purpose-built wrapper app.
- [x] Document that `open -a AppName` is not equivalent to launching the app binary directly.
- [x] Test child signal forwarding on macOS.
- [x] Test child shutdown and cleanup behavior when the parent receives `SIGINT` or `SIGTERM`.

## 6. SIP, Hardened Runtime, And Security Restrictions

- [x] Document how System Integrity Protection affects injected libraries.
- [x] Define whether Apple-protected binaries are unsupported.
- [ ] Test unsigned child binaries versus signed child binaries.
- [ ] Test third-party signed GUI apps that are not SIP-protected but may still reject DYLD injection in helpers.
- [ ] Test hardened runtime apps if GUI support is in scope.
- [ ] Decide whether WrapGuard itself will be codesigned.
- [ ] Decide whether the dylib must be signed with the same identity as the main binary.
- [ ] Decide whether notarization is required for distribution.
- [x] Add a preflight check that detects unsupported launch targets and explains why they cannot be wrapped.

## 7. Network Correctness

Files: `lib/intercept.c`, `socks.go`, `tunnel.go`, `routing.go`

- [x] Prove that outbound TCP traffic is tunneled on macOS.
- [ ] Prove that outbound UDP traffic is tunneled on macOS.
  Current status: still open. As a short-term browser mitigation, macOS now suppresses likely QUIC by rejecting outbound non-loopback UDP `connect()` calls to port `443` for wrapped children, which is intended to force fallback to tunneled TCP rather than claim UDP support.
- [x] The narrow macOS QUIC suppression mitigation is implemented and smoke-covered.
- [ ] Replace the narrow macOS QUIC mitigation with a browser-correct solution.
  Current status: the mitigation now covers both fresh UDP `connect():443` and browser-style UDP `sendto()` / `sendmsg()` activity to remote `:443`, with macOS smoke coverage and safe IPC observability. Full browser-grade correctness is still open because reused `HTTP/3` session behavior and end-to-end browser validation remain unproven.
- [x] Add IPv6 support or clearly mark IPv6 as unsupported on macOS.
- [x] Verify localhost bypass behavior still works correctly on macOS.
- [x] Verify SOCKS self-connections are never recursively intercepted.
- [ ] Verify non-blocking sockets behave correctly on macOS.
  Current status: improved but still open. The interceptor now restores `EINPROGRESS` after successful SOCKS setup for non-blocking TCP sockets and clears stale wrapped-socket peer metadata on `close()` so fd reuse does not leak old state into later connections. Darwin `getpeername()` interposition was removed after live browser sampling showed it stalling Firefox's socket thread; Linux keeps the wrapped-peer virtualization path.
- [x] Add regression coverage for non-blocking `connect()` interception on macOS.
- [x] Add regression coverage for wrapped peer-state cleanup across `close()` and fd reuse.
- [x] Verify DNS resolution behavior on macOS.
- [x] Decide whether DNS should go through the tunnel, through the SOCKS layer, or be left to the host.
  Current status: DNS is intentionally left to the host network stack. Tests now pin that behavior by keeping hostnames on the base dialer, rejecting hostnames inside `DialWireGuard`, and only parsing interface DNS values as configuration data.
- [ ] Add leak tests for public IP, DNS, and IPv6.
- [ ] Add leak tests that explicitly distinguish `HTTP/2` versus `HTTP/3` behavior on macOS.
- [ ] Add regression coverage for browser-style QUIC / reused-session behavior on macOS.
- [ ] Add tests for partial failures: tunnel up but proxy unreachable, proxy up but peer unreachable, etc.
  Current status: automated tests now cover closed SOCKS listeners, missing IPC sockets, no-route failures, base-dial failure propagation, tunnel-dial error propagation, and self-test failure when the SOCKS listener disappears before launch. Full peer-unreachable end-to-end cases are still open.

## 8. GUI App Compatibility

- [ ] Define the expected behavior for browser apps and `.app` bundles.
- [ ] Test a non-SIP third-party GUI app launched by its inner executable.
- [x] Test Firefox/LibreWolf-style multi-process browsers where GPU, content, and networking helpers may inherit DYLD injection separately from the main app process.
  Current status: manual LibreWolf validation now proves the injected multi-process browser can launch and browse through the tunnel on macOS, though broader automated coverage is still missing.
- [x] Test whether a browser like LibreWolf actually routes through the tunnel on macOS.
  Current status: validated manually with `http://icanhazip.com`, which returned the VPN IP `146.70.156.18`.
- [x] Test whether a browser like LibreWolf remains stable after helper processes start and real pages load.
  Current status: the latest LibreWolf run stayed up long enough to load pages and open DevTools, but residual GPU/helper warnings remain and other GUI apps still need validation.
- [x] Test whether a browser like LibreWolf keeps using the tunnel across refreshes when the site advertises `alt-svc` / `HTTP/3`.
  Current status: the latest manual refresh validation kept returning the VPN IP. Broader repeatability and explicit HTTP/3-specific regression coverage still remain open in the QUIC track below.
- [x] Determine whether helper subprocesses need their own injection exclusions, launch strategy, or compatibility mode.
  Current status: the investigation has now confirmed that helper subprocesses do need special handling on macOS, but the attempted fixes are not yet acceptable:
  - the explicit macOS GUI compatibility mode did not restore LibreWolf startup correctness and is not an acceptable end-state by itself
  - Mozilla helper-role passthrough reduced some failures but still left the browser hanging for roughly twenty seconds before software-render fallback
  - the later `posix_spawn` reinjection attempt regressed into recursive crashes and was fully backed out
  - so the requirement is understood, but the actual supported launch strategy remains open
- [ ] Decide whether to support only child processes directly launched by WrapGuard, not processes spawned later by helper daemons.
- [ ] Document app classes that are unsupported because of launch architecture, sandboxing, or hardened runtime.

## 8A. Browser QUIC / HTTP3 Correctness Track

The HAR comparison makes this a separate workstream rather than a vague browser note.

What the evidence now says:

- WrapGuard's proven macOS browser path today is fresh outbound TCP interception
- the good browser-visible IP result is associated with `HTTP/2`
- the bad browser-visible IP result is associated with `HTTP/3`
- that means the remaining leak is best described as a QUIC / HTTP/3 browser-path problem, not as a generic failure of the proven tunneled TCP path

What a proper solution should look like:

- [ ] Decide whether macOS browser support will include real UDP / QUIC tunneling or explicit browser-grade QUIC suppression.
- [ ] If real UDP / QUIC tunneling is in scope, design and implement a correct UDP transport path through the userspace tunnel instead of forcing browser traffic back to TCP as a side effect.
- [x] If browser-grade QUIC suppression is the near-term production target, implement it at the actual UDP send path used by browsers, not only at fresh UDP `connect()`.
- [x] Add transport-aware instrumentation for remote UDP `:443` activity on macOS, including `sendmsg` / `sendto`-style paths if needed.
- [ ] Confirm whether a reused `HTTP/3` session can occur without a fresh intercepted UDP `connect()` event in the current instrumentation model.
- [ ] Add repeatable test cases that distinguish:
  - fresh `HTTP/2` request over tunneled TCP
  - fresh `HTTP/3` request
  - reused `HTTP/3` request / refresh
- [ ] Add an explicit product decision and document it:
  - "WrapGuard supports browser traffic on macOS only when HTTP/3 is disabled"
  - or
  - "WrapGuard supports browser traffic on macOS with HTTP/3 enabled because QUIC is tunneled or robustly suppressed"
- [ ] Do not call browser support production-ready until one of those paths is fully validated.

Why this track matters:

- the current narrow mitigation is a useful debugging measure, but not a viable long-term browser solution by itself
- the HAR evidence means a proper implementation must own browser QUIC behavior deliberately instead of assuming successful TCP interception covers the full browser networking model

## 9. Build System Hardening

Files: `Makefile`

- [x] Split Linux and macOS build logic instead of relying on Linux defaults.
- [x] Add a dedicated `build-macos` target that produces the exact runtime artifact names.
- [x] Add `build-macos-arm64` and `build-macos-amd64` targets.
- [x] Optionally add a universal binary build path.
- [x] Turn on strict compiler warnings for the intercept library.
- [x] Ensure the macOS build does not reference Linux-only linker behavior.
- [x] Add a `make smoke-macos` target that validates a local package end-to-end.

## 10. Automated Testing

Files: `main_test.go`, new integration test files, CI workflows

- [x] Add unit tests for platform-specific library path resolution.
- [x] Add unit tests for platform-specific environment variable selection.
- [x] Add macOS-focused tests for missing dylib detection.
- [x] Add a small helper test binary that can report whether the interposition library actually loaded.
- [x] Add regression tests for `--doctor` preflight behavior covering missing runtime libraries, missing launch targets, direct-launch success, SIP-protected shell rejections, and `.app` bundle path resolution on macOS.
- [ ] Remaining integration test gaps:
- [x] launch a wrapped child on macOS
- [x] confirm the interceptor loaded
- [x] confirm at least one `connect` call was intercepted
- [x] confirm the observed public IP differs from the host when using a real tunnel in a manual test lane
- [x] Add regression tests for localhost bypass, shell-launched env propagation, SOCKS recursion prevention, and routing protocol normalization.
- [x] Add regression tests for bind interception smoke coverage on macOS.
- [x] Add regression tests for likely QUIC UDP/443 suppression on macOS.
- [x] Add regression tests for wrapped-socket peer-state cleanup after `close()` and descriptor reuse.
- [x] Add regression tests for dialer/listener guardrails and closed-SOCKS self-test failure handling.
- [x] Add regression tests for release archive contents on macOS.
- [x] Add CI jobs on `macos-latest`.
- [x] Run both unit tests and packaging smoke tests on macOS in CI.

## 11. Observability And Debuggability

Files: `logger.go`, `main.go`, `lib/intercept.c`

- [x] Log the selected injection mode on startup.
- [x] Log the resolved library path on startup.
- [x] Log whether the child environment included the expected macOS variables.
- [x] Add a startup handshake between the injected library and the main process so the parent can confirm the library loaded.
- [x] Fail with a clear error if the child starts but the injected library never announces itself.
- [x] Add a `--doctor` or `--self-test` command for macOS diagnostics.
- [x] Improve low-level interceptor logging so `sa_family` values are printed symbolically, for example `AF_UNIX`, `AF_INET`, and `AF_INET6`.
- [x] Add optional logging that records which subprocesses announced the interceptor handshake, so GUI helper-process behavior is visible.
- [x] Include checks for: library present, injection mode selected, IPC socket reachable, SOCKS server reachable, interceptor loaded.
- [x] Replace recursive `fprintf`-style interceptor logging on macOS with a non-recursive observability path suitable for GUI/browser debugging.
  Current status: macOS debug launches now route interceptor diagnostics through the IPC channel instead of stdio inside the hot socket hooks, and the interceptor now guards its IPC path against recursive re-entry.
- [x] Add transport-specific debug output for browser investigations without routing logs through code paths that can themselves trigger socket interception.
- [x] Add a safe debug mode that can record wrapped TCP state transitions and remote UDP / QUIC activity on macOS.

## 12. Release Engineering

Files: `.github/workflows/release.yml`

- [x] Build macOS artifacts in a way that matches runtime expectations.
- [x] Add archive verification tests before upload.
- [x] Add checksums for release assets.
- [ ] Sign macOS binaries if distribution requires it.
- [ ] Notarize macOS artifacts if distribution requires it.
- [x] Verify downloaded release archives on a clean macOS runner before publishing.
- [x] Add release notes that list supported macOS versions, known limitations, and example commands.

## 13. Documentation

Files: `README.md`, release notes, new docs

- [x] Replace the current blanket macOS claim with a precise support statement until production readiness is complete.
- [x] Add a dedicated macOS setup guide.
- [x] Document the differences between Linux and macOS injection behavior.
- [x] Document unsupported cases caused by SIP, hardened runtime, or protected system binaries.
- [ ] Document how to launch third-party GUI apps on macOS when supported.
- [x] Add a troubleshooting section for "tunnel up but traffic unchanged".
- [x] Add a troubleshooting section for missing injected library loads.
- [x] Add a troubleshooting section for codesigning or notarization issues.
- [x] Document that browser-style GUI apps may still crash even when TCP interception works, because helper-process compatibility is still under active development.

## 14. Manual QA Matrix

- [x] Apple Silicon machine, latest supported macOS.
  Current status: manually validated during the LibreWolf breakthrough run on `darwin/arm64`.
- [ ] Intel machine, latest supported macOS.
- [ ] Fresh release archive install, not just local build output.
- [x] CLI target launched directly.
- [ ] CLI target launched through a shell.
  Automated coverage now verifies shell-launched environment propagation for non-SIP shells, but the manual QA checklist item remains open.
- [x] Third-party GUI app target launched directly by inner binary.
  Current status: LibreWolf inner-executable launch is now manually validated on Apple Silicon.
- [x] Network verification with public IP check.
- [x] Network verification with both `HTTP/2` and `HTTP/3` capable IP-check sites.
  Current status: earlier HAR-backed validation captured the `HTTP/2` good path versus `HTTP/3` bad path, and the latest manual LibreWolf run now keeps the VPN IP across refreshes. Automated regression coverage is still open.
- [ ] DNS leak verification.
- [ ] Repeated launch and shutdown cycles.
- [ ] Child crash scenarios.
- [ ] Parent crash scenarios.
- [ ] Missing library and malformed config scenarios.

## 15. Rollout Plan

- [x] Ship behind an "experimental macOS support" label first.
- [ ] Gather logs from real macOS users.
- [ ] Fix issues found in the experimental phase before broadening the support claim.
- [ ] Promote to stable only after macOS CI, release validation, and manual QA are all green.

## Current Browser Root Cause Summary

Based on all currently collected evidence, the best current explanation is:

- the browser investigation exposed two distinct issues:
  - the historical near-miss:
    - fresh browser TCP traffic was clearly being intercepted and tunneled correctly on macOS
    - hard-refresh-style requests could show the VPN IP
    - the bad soft-refresh result was associated with `HTTP/3` in the HAR, while the good result was associated with `HTTP/2`
    - that still points strongly at QUIC / HTTP/3 transport reuse or another UDP-based browser path outside the fresh TCP `connect()` model that WrapGuard currently proves
  - the later startup regression:
    - injected helper-process trees began stalling or breaking GPU / compositor / browser IPC before useful page loads happened
    - that regression was severe enough to mask the older network-correctness question for a while
- the latest LibreWolf validation shows that startup regression is no longer the primary blocker:
  - the browser can now launch, load pages, refresh successfully, and show the VPN IP
  - opening DevTools no longer crashes the process
- the most plausible explanation for that recovery is the combination of:
  - safer macOS fallback behavior for non-intercepted `connect()` paths
  - reduced AF_UNIX logging churn in hot browser IPC paths
  - removal of Darwin `getpeername()` interposition, which live sampling showed on Firefox's socket-thread hot path during the blank-page failure
- the browser crash observed during HAR export was a separate observability/debugging bug caused by recursive interceptor logging, and that specific logging path has already been replaced
- the highest-priority browser task is therefore no longer "restore any browser startup at all"; it is:
  - keep the restored LibreWolf path stable
  - validate whether the old `HTTP/3` leak is still reproducible after the current fixes
  - broaden the same approach to more GUI apps without regressing Linux or the already-proven CLI tunnel path

## Suggested First Implementation Slice

If work starts immediately, the highest-value first slice is:

- [x] Fix `main.go` to choose the correct macOS injection variable and library name.
- [x] Add a positive startup handshake from the injected library.
- [x] Add a macOS smoke test proving the interceptor loaded.
- [x] Add a macOS CI lane.
- [x] Correct the README to match reality until the full test matrix passes.

If work resumes from the current state, the next implementation slice should instead be:

- [x] restore stable browser startup on macOS before revalidating the older leak path
- [x] reduce or defer browser-process interposition so helper / GPU / compositor startup is no longer destabilized
- [ ] add a repeatable browser-startup regression test lane or at least a documented manual harness that distinguishes:
  - browser never reaches `READY`
  - browser reaches `READY` but hangs before first page load
  - browser loads and first request tunnels
  - browser later leaks via `HTTP/3` or another path
- [ ] revisit the older `HTTP/2` versus `HTTP/3` leak evidence and validate whether the existing QUIC suppression still behaves as intended after the current browser-stability fixes
