# Terminator Passive Burp Extension

This directory is reserved for the Java Montoya extension that forwards scoped passive metadata to `integrations/burp_bridge_server.py`.

Current integration phase:

- Bridge server is implemented and tested.
- Extension behavior is specified here.
- The extension must remain passive-only.

Required extension behavior:

1. Use PortSwigger's Montoya API.
2. Register an HTTP handler.
3. For in-scope traffic only, collect metadata:
   - method
   - URL
   - status code
   - redacted request headers
   - redacted response headers
   - body length
   - content type
   - timestamp
4. POST metadata to `http://127.0.0.1:8765/burp/observe`.
5. Add a passive annotation/highlight in Burp.
6. Continue requests and responses unchanged.

Prohibited behavior:

- Do not modify requests.
- Do not modify responses.
- Do not replay traffic.
- Do not send active scan requests.
- Do not send request or response bodies by default.
- Do not store raw auth secrets.

Build notes:

- Keep Gradle/Maven files isolated in this directory.
- Do not make the main Terminator Python test suite depend on Java tooling.
- Add extension build smoke checks separately once the Java skeleton is introduced.
