#!/usr/bin/env python3
"""Serve one reviewed archive over TLS to the selected private Windows peer.

This is an operator deployment channel, separate from the job submission API.
The operator or signed maintenance request pins the archive and TLS certificate.
No directory listing, upload, command execution, or global trust-store change.
"""

import argparse
import base64
import hashlib
import http.server
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    bind, peer = plan["clientAddress"], plan["listenAddress"]
    for address in (bind, peer):
        parsed = ipaddress.ip_address(address)
        if parsed.version != 4 or not parsed.is_link_local:
            raise ValueError("Deployment is limited to the reviewed IPv4 link-local path")
    if bind == peer:
        raise ValueError("The deployment endpoints must be distinct")
    # Snapshot content before publication; concurrent local edits cannot change it.
    content = args.archive.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    request_path = "/" + secrets.token_hex(24) + "/deployment.zip"
    server_name = "d3d11-validation-deployment.invalid"
    completed = False

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal completed
            if self.path != request_path or completed:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)
            self.wfile.flush()
            completed = True

        def log_message(self, *_):
            pass

    class Server(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            if address[0] != peer:
                connection.close()
                raise OSError("Unapproved deployment peer")
            connection.settimeout(10)
            try:
                return context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise

    # Short-lived certificate/key are private temporary files, never repository data.
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="d3d11-deploy-") as temporary:
            directory = Path(temporary)
            certificate, key = directory / "certificate.pem", directory / "private.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                "-days", "2", "-nodes", "-subj", "/CN=d3d11-validation-deployment",
                "-addext", "subjectAltName=DNS:" + server_name + ",IP:" + bind,
                "-keyout", str(key), "-out", str(certificate),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certificate, key)
            with Server((bind, 0), Handler) as server:
                server.timeout = 1
                print(json.dumps({
                    "url": f"https://{server_name}:{server.server_port}{request_path}",
                    "curlResolve": f"{server_name}:{server.server_port}:{bind}",
                    "archiveSha256": digest,
                    "archiveBytes": len(content),
                    "ticket": request_path.split("/")[1],
                    "port": server.server_port,
                    "certificateSha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest(),
                    "certificateBase64": base64.b64encode(certificate.read_bytes()).decode(),
                    "expiresAfterSeconds": 300,
                }), flush=True)
                deadline = time.monotonic() + 300
                while not completed and time.monotonic() < deadline:
                    server.handle_request()
                if not completed:
                    raise TimeoutError("No completed deployment download before expiry")
                print("PASS: one TLS deployment transfer completed; listener closed", flush=True)
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    main()
