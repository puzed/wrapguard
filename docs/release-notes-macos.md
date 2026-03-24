# WrapGuard macOS Release Notes

Use this template when cutting a macOS release. Fill in the version-specific details before publishing.

## Release Summary

- Version: `vX.Y.Z`
- Release date: `YYYY-MM-DD`
- Supported architectures: `arm64`, `amd64`
- Packaging: `wrapguard-<tag>-darwin-arm64.tar.gz` and `wrapguard-<tag>-darwin-amd64.tar.gz`

## Support Matrix

- macOS 14 Sonoma: experimental direct-launch support for targets that can be launched as an executable path.
- macOS 15 Sequoia: experimental direct-launch support for targets that can be launched as an executable path.
- `.app` bundle launching: supported only when WrapGuard can resolve a single clear executable in `Contents/MacOS`; otherwise launch the inner executable directly.
- `open -a` launch paths: unsupported.
- System binaries under `/bin`, `/sbin`, `/System`, `/usr/bin`, and `/usr/libexec`: unsupported.
- Browser-style GUI apps: experimental and not considered production-supported.

## Example Commands

```bash
# Preflight a launch target
wrapguard --doctor /usr/local/bin/curl

# Run a direct CLI command through WrapGuard
wrapguard --config=wg0.conf -- curl https://icanhazip.com

# Inspect the packaged build locally
tar -tzf wrapguard-vX.Y.Z-darwin-arm64.tar.gz
```

## Known Limitations

- macOS support is CLI-oriented and relies on direct launching of the target executable.
- SIP-protected system binaries are rejected before launch.
- GUI applications may load when launched via their inner executable, but they can still become unstable if helper processes are not compatible with DYLD injection.
- TCP routing is the documented macOS path; UDP and IPv6 remain outside the production support statement unless explicitly validated for a release.
- On current macOS builds, WrapGuard may deliberately suppress likely QUIC `UDP/443` connect attempts to encourage TCP fallback rather than claim full UDP tunneling support.
- Non-blocking socket behavior is improved but still under active validation; WrapGuard now virtualizes `getpeername()` for successfully wrapped TCP sockets, but broader browser/socket-state compatibility still needs more regression coverage.

## Validation Notes

- Confirm the packaged archive contains `wrapguard`, `libwrapguard.dylib`, `README.md`, and `example-wg0.conf`.
- Confirm `wrapguard --version` and `wrapguard --help` succeed from the unpacked archive on a clean macOS runner.
- If a GUI app was used for validation, record the inner executable path that was launched and note any helper-process instability.
- Record any manual CLI validation performed against a real WireGuard configuration.
- Record whether browser-style validation was performed with hard refresh and soft refresh comparisons, and note any QUIC, cache, or helper-process behavior that affected the result.
