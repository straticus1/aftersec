#!/usr/bin/env python3
"""AfterSec bootstrap.

Threats: an http URL, a bad signature, a hash or size mismatch, an unexpected
artifact name, or a path that is a symlink is fatal. The manifest cannot
choose a command. The enrollment code is an argument and is not written into
the config or the log. This does not prove the script itself was the one the
operator meant to run; compare its SHA-256 with the value shown by the server.
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import ssl
import stat
import subprocess
import sys
import urllib.request

EMBEDDED_PUBLIC_KEY = """AFTERSEC_BOOTSTRAP_PUBLIC_KEY"""

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
ALLOWED = {"aftersec", "aftersecd", "aftersec-display", "aftersec-windows", "management-ca"}
EXECUTABLES = {"aftersec", "aftersecd", "aftersec-display", "aftersec-windows"}
MAX_MANIFEST = 64 * 1024
MAX_ARTIFACT = 64 * 1024 * 1024


def _bit(data, index):
    return (data[index // 8] >> (index % 8)) & 1


def _inv(value):
    return pow(value, P - 2, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


def _isoncurve(point):
    x, y, z, t = point
    return (
        z % P != 0
        and (x * y - z * t) % P == 0
        and (y * y - x * x - z * z - D * t * t) % P == 0
    )


def _decode_int(data):
    return sum(2**i * _bit(data, i) for i in range(len(data) * 8))


def _decode_point(data):
    if len(data) != 32:
        return None
    y = sum(2**i * _bit(data, i) for i in range(255))
    if y >= P:
        return None
    x = _xrecover(y)
    if x & 1 != _bit(data, 255):
        x = P - x
    point = (x, y, 1, (x * y) % P)
    if not _isoncurve(point):
        return None
    return point


def _encode_point(point):
    x, y, z, _t = point
    zi = _inv(z)
    x, y = (x * zi) % P, (y * zi) % P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _edwards(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = (b - a) % P, (d - c) % P, (d + c) % P, (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point, scalar):
    result = (0, 1, 1, 0)
    base = point
    while scalar:
        if scalar & 1:
            result = _edwards(result, base)
        base = _edwards(base, base)
        scalar >>= 1
    return result


def _b_point():
    y = (4 * _inv(5)) % P
    x = _xrecover(y)
    return (x, y, 1, (x * y) % P)


B_POINT = _b_point()


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    scalar = _decode_int(signature[32:])
    if scalar >= L:
        return False
    point_r = _decode_point(signature[:32])
    point_a = _decode_point(public)
    if point_r is None or point_a is None:
        return False
    digest = hashlib.sha512(_encode_point(point_r) + public + message).digest()
    k = _decode_int(digest)
    left = _scalarmult(B_POINT, scalar)
    right = _edwards(point_r, _scalarmult(point_a, k))
    return _encode_point(left) == _encode_point(right)


def _pem_public_key(pem):
    text = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
    raw = __import__("base64").b64decode("".join(text.split()))
    if len(raw) < 32:
        raise SystemExit("bootstrap public key is invalid")
    # PKIX Ed25519 SPKI ends with the 32-byte point.
    return raw[-32:]


def _https_url(base, suffix):
    if not base.startswith("https://"):
        raise SystemExit("bootstrap server must be https")
    if "\n" in base or "\r" in base or " " in base:
        raise SystemExit("bootstrap server url is invalid")
    return base.rstrip("/") + suffix


def _fetch(url):
    context = ssl.create_default_context()
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_ARTIFACT:
            raise SystemExit("bootstrap download exceeds limit")
        data = response.read(MAX_ARTIFACT + 1)
    if len(data) > MAX_ARTIFACT:
        raise SystemExit("bootstrap download exceeds limit")
    return data


def _load_manifest(raw, public):
    if len(raw) > MAX_MANIFEST:
        raise SystemExit("bootstrap manifest exceeds limit")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise SystemExit("bootstrap manifest is invalid")
    if set(envelope) != {"payload", "signature"}:
        raise SystemExit("bootstrap manifest is invalid")
    import base64
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
    except Exception:
        raise SystemExit("bootstrap manifest is invalid")
    if not ed25519_verify(public, payload, signature):
        raise SystemExit("bootstrap manifest signature rejected")
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise SystemExit("bootstrap manifest is invalid")
    return manifest


def _select(manifest, system, arch):
    found = {}
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit("bootstrap manifest has no artifacts")
    for item in artifacts:
        if not isinstance(item, dict):
            raise SystemExit("bootstrap artifact is invalid")
        if item.get("os") != system or item.get("arch") != arch:
            continue
        name = item.get("name")
        if name not in ALLOWED or name in found:
            raise SystemExit("bootstrap artifact name rejected")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SystemExit("bootstrap artifact hash is invalid")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > MAX_ARTIFACT:
            raise SystemExit("bootstrap artifact size is invalid")
        found[name] = item
    if system == "windows":
        if arch != "amd64" or "aftersec-windows" not in found or "management-ca" not in found:
            raise SystemExit("bootstrap manifest is missing the Windows reporter or management CA")
    elif "aftersec" not in found or "management-ca" not in found:
        raise SystemExit("bootstrap manifest is missing the agent or management CA")
    return found


def _artifact_bytes(item, server, artifact_dir):
    digest = item["sha256"]
    if artifact_dir:
        path = os.path.join(artifact_dir, digest)
        if os.path.dirname(os.path.abspath(path)) != os.path.abspath(artifact_dir):
            raise SystemExit("bootstrap artifact path escaped")
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("bootstrap artifact is not a regular file")
        with open(path, "rb") as handle:
            data = handle.read(MAX_ARTIFACT + 1)
    else:
        data = _fetch(_https_url(server, "/api/v1/bootstrap/artifacts/" + digest))
    if len(data) != item["size"]:
        raise SystemExit("bootstrap artifact size mismatch")
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, digest):
        raise SystemExit("bootstrap artifact hash mismatch")
    return data


def _write_file(directory, name, data, mode):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    final = os.path.join(directory, name)
    if os.path.lexists(final):
        info = os.lstat(final)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SystemExit("bootstrap destination is not a regular file")
    temporary = final + ".partial"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(temporary, mode)
    os.replace(temporary, final)


def _safe_label(value, label):
    if not value or len(value) > 128 or any(c in value for c in "\r\n\t /\\"):
        raise SystemExit(label + " is invalid")
    return value


def _write_config(home, tenant, grpc_address, ca_path):
    config_dir = os.path.join(home, ".aftersec")
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    data_dir = os.path.join(config_dir, "data")
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    text = (
        "mode: enterprise\n"
        "tenant_id: " + tenant + "\n"
        "storage:\n"
        "  type: local\n"
        "  path: " + data_dir + "\n"
        "server:\n"
        "  address: " + grpc_address + "\n"
        "  tls:\n"
        "    ca: " + ca_path + "\n"
    )
    _write_file(config_dir, "config.yaml", text.encode("utf-8"), 0o600)


def _load_public_key(value):
    if value and os.path.isfile(value):
        with open(value, "r", encoding="utf-8") as handle:
            value = handle.read()
    return _pem_public_key(value)


def install(args):
    public = _load_public_key(args.public_key or EMBEDDED_PUBLIC_KEY)
    if args.manifest:
        with open(args.manifest, "rb") as handle:
            raw = handle.read(MAX_MANIFEST + 1)
    else:
        raw = _fetch(_https_url(args.server, "/api/v1/bootstrap/manifest"))
    manifest = _load_manifest(raw, public)
    system = args.os or ("darwin" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "windows" if sys.platform == "win32" else "")
    machine = args.arch or {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64", "AMD64": "amd64"}.get(platform.machine(), "")
    if system not in {"darwin", "linux", "windows"} or machine not in {"arm64", "amd64"}:
        raise SystemExit("bootstrap platform is unsupported")
    if system == "windows" and machine != "amd64":
        raise SystemExit("bootstrap platform is unsupported")
    chosen = _select(manifest, system, machine)
    home = os.path.expanduser("~")
    if system == "windows":
        binary_dir = args.dest or os.path.join(home, ".aftersec", "bin")
    else:
        binary_dir = args.dest or ("/usr/local/bin" if os.geteuid() == 0 else os.path.join(home, ".aftersec", "bin"))
    ca_path = os.path.join(home, ".aftersec", "management-ca.pem")
    for name, item in chosen.items():
        data = _artifact_bytes(item, args.server, args.artifact_dir)
        installed = "aftersec-windows.exe" if system == "windows" and name == "aftersec-windows" else name
        if name == "management-ca":
            _write_file(os.path.dirname(ca_path), os.path.basename(ca_path), data, 0o644)
        else:
            _write_file(binary_dir, installed, data, 0o755)
    if system == "windows":
        if args.code:
            if not args.tenant or not args.server:
                raise SystemExit("tenant and https server are required to report")
            binary = os.path.join(binary_dir, "aftersec-windows.exe")
            completed = subprocess.run(
                [binary, "report", "--server", args.server, "--tenant", _safe_label(args.tenant, "tenant"), "--ca", ca_path, "--code", args.code],
                check=False,
            )
            if completed.returncode != 0:
                raise SystemExit(completed.returncode)
    else:
        if args.tenant and args.grpc:
            _write_config(home, _safe_label(args.tenant, "tenant"), _safe_label(args.grpc, "grpc address"), ca_path)
        if args.code:
            if not args.tenant or not args.grpc:
                raise SystemExit("tenant and grpc address are required to enroll")
            binary = os.path.join(binary_dir, "aftersec")
            completed = subprocess.run([binary, "--config", os.path.join(home, ".aftersec", "config.yaml"), "enroll", args.code], check=False)
            if completed.returncode != 0:
                raise SystemExit(completed.returncode)
    print("bootstrap installed")


def self_test():
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    if not ed25519_verify(public, b"", signature):
        raise SystemExit("rfc vector rejected")
    bad = bytearray(signature)
    bad[0] ^= 1
    if ed25519_verify(public, b"", bytes(bad)):
        raise SystemExit("tampered rfc vector accepted")
    print("bootstrap self-test ok")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    parser = argparse.ArgumentParser(description="Install a signed AfterSec release")
    parser.add_argument("--server", default="")
    parser.add_argument("--manifest", default="")
    parser.add_argument("--artifact-dir", default="")
    parser.add_argument("--public-key", default="")
    parser.add_argument("--dest", default="")
    parser.add_argument("--tenant", default="")
    parser.add_argument("--grpc", default="")
    parser.add_argument("--code", default="")
    parser.add_argument("--os", default="")
    parser.add_argument("--arch", default="")
    args = parser.parse_args()
    if not args.manifest and not args.server:
        raise SystemExit("a manifest path or https server is required")
    if args.code and any(c in args.code for c in "\r\n\t"):
        raise SystemExit("enrollment code is invalid")
    install(args)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit("bootstrap failed: " + exc.__class__.__name__)
