"""Plain notes for open ports that the common-port check already recorded.

This does not scan, guess software versions, or look for weaknesses. It only
describes what a known home port usually is, and whether that is normal for
the kind of device already identified.
"""

from __future__ import annotations

_WEB = {80, 81, 443, 8000, 8080, 8081, 8443, 8888}
_PRINTER = {515, 631, 9100}
_APPLE = {548, 62078}
_CAST = {8008, 8009}
_MAIL = {25, 26, 110, 143, 465, 587, 993, 995}
_DATABASE = {1433, 1434, 1521, 3306, 5432}
_FILE_SHARING = {139, 445}
_REMOTE_SCREEN = {5800, 5900}


def explain_port(port: int, kind: str) -> tuple[str, str]:
    """Return a label and one sentence. Label is expected, review, or close."""

    if port in {20, 21}:
        return "close", "This is an old way to transfer files. Turn it off in the device settings if you do not use it."
    if port == 23:
        return "close", "This is an old remote login. Turn it off in the device settings if you do not use it."
    if port == 22:
        return "review", "This is a remote login. Leave it only if you meant to turn that on."
    if port == 53:
        if kind == "router":
            return "expected", "This answers name lookups for your home network. That is normal for the router."
        return "review", "This answers name lookups. That is unusual away from the router."
    if port in _WEB:
        if kind in {"router", "camera", "printer"}:
            return "expected", "This is a web page. That is normal for this device."
        return "review", "This is a web page. Open it in a browser only if you know this device."
    if port in _FILE_SHARING:
        if kind == "computer":
            return "expected", "This is Windows file sharing. That is normal for a Windows computer."
        if kind == "router":
            return "review", "This is file sharing. Routers sometimes use it for a plugged-in USB disk."
        return "review", "This is Windows file sharing. Check whether this device should share files."
    if port in _PRINTER:
        if kind == "printer":
            return "expected", "This is how a printer receives a document."
        return "review", "This is usually a printer. Check that this device is supposed to print."
    if port == 554:
        if kind in {"camera", "tv"}:
            return "expected", "This is a video stream. That is normal for a camera or a television."
        return "review", "This is a video stream. Check whether this device is a camera or a recorder."
    if port == 3389 or port in _REMOTE_SCREEN:
        return "close", "This lets another screen control the device. Turn it off if you do not use that."
    if port == 5357:
        if kind == "computer":
            return "expected", "This is how a Windows computer announces itself on the home network."
        return "review", "This is usually a Windows computer announcing itself."
    if port in _APPLE:
        if kind == "apple":
            return "expected", "This is a service used by an Apple phone or computer."
        return "review", "This is usually an Apple phone or computer."
    if port in _CAST:
        if kind == "tv":
            return "expected", "This is how a television or Chromecast receives a cast."
        return "review", "This is usually a television or a Chromecast."
    if port in _MAIL:
        return "review", "This is email. Home devices rarely need it unless you run a mail server on purpose."
    if port in _DATABASE:
        return "review", "This is a database. It is unusual on a home device unless you run one on purpose."
    return "review", "This port is open. HomeGuard has no usual meaning for it on a home network."
