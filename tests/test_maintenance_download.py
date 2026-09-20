#!/usr/bin/env python3
"""Exercise the actual pinned TLS downloader against a local test listener.

Supply the Mac's already configured link-local address. This never connects to or
changes the Windows host. Certificates and raw test output remain in .local/.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-address', required=True)
    args = parser.parse_args()
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='maintenance-tls-', dir=ROOT / '.local') as directory:
            work = Path(directory)
            cert, key = work / 'cert.pem', work / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=d3d11-validation-deployment.invalid', '-keyout', str(key), '-out', str(cert)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            cert_sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            content = b'bounded deployment data'
            digest = hashlib.sha256(content).hexdigest()
            script = work / 'download.ps1'
            script.write_text('''param($Module,$Address,$Port,$Certificate,$Size,$Digest,$Output)
$ErrorActionPreference='Stop'
Import-Module $Module
try { [ValidationMaintenance]::Download($Address,[int]$Port,('a'*48),$Certificate,[long]$Size,$Digest,$Output); exit 0 }
catch { exit 1 }
''')
            cases = (
                ('valid', f'Content-Length: {len(content)}\r\n', content, cert_sha, digest, True),
                ('wrong-certificate', f'Content-Length: {len(content)}\r\n', content, '0' * 64, digest, False),
                ('wrong-hash', f'Content-Length: {len(content)}\r\n', content, cert_sha, '0' * 64, False),
                ('truncated', f'Content-Length: {len(content)}\r\n', content[:-1], cert_sha, digest, False),
                ('trailing', f'Content-Length: {len(content)}\r\n', content + b'x', cert_sha, digest, False),
                ('missing-length', '', content, cert_sha, digest, False),
                ('duplicate-length', f'Content-Length: {len(content)}\r\nContent-Length: {len(content)}\r\n', content, cert_sha, digest, False),
                ('transfer-encoding', f'Content-Length: {len(content)}\r\nTransfer-Encoding: chunked\r\n', content, cert_sha, digest, False),
                ('content-encoding', f'Content-Length: {len(content)}\r\nContent-Encoding: gzip\r\n', content, cert_sha, digest, False),
            )
            for name, headers, body, pin, sha, expected in cases:
                listener = socket.socket()
                listener.bind((args.local_address, 0))
                listener.listen(1)
                listener.settimeout(15)
                port = listener.getsockname()[1]
                failures = []

                def serve():
                    try:
                        connection, peer = listener.accept()
                        if peer[0] != args.local_address:
                            raise RuntimeError('Test listener reached by an unexpected peer')
                        with context.wrap_socket(connection, server_side=True) as stream:
                            stream.settimeout(10)
                            request = b''
                            while not request.endswith(b'\r\n\r\n') and len(request) < 8192:
                                part = stream.recv(1)
                                if not part:
                                    return
                                request += part
                            stream.sendall(b'HTTP/1.1 200 OK\r\n' + headers.encode() + b'\r\n' + body)
                    except (ssl.SSLError, BrokenPipeError, ConnectionResetError):
                        pass  # Expected when the client rejects a bad pin/header.
                    except Exception as error:
                        failures.append(type(error).__name__)
                    finally:
                        listener.close()

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                output = work / (name + '.bin')
                result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-File', str(script),
                                         str(ROOT / 'windows/Validation.Maintenance.psm1'), args.local_address,
                                         str(port), pin, str(len(content)), sha, str(output)],
                                        capture_output=True, timeout=20)
                thread.join(timeout=5)
                if thread.is_alive() or failures or (result.returncode == 0) != expected:
                    raise RuntimeError('Pinned download check failed: ' + name)
                if expected and output.read_bytes() != content:
                    raise RuntimeError('Downloaded data differs')
            print(json.dumps(dict(schema='d3d11-maintenance-tls-tests/v1', checksPassed=len(cases),
                                  remoteHostChanged=False, certificateTrustStoreChanged=False)))
    finally:
        os.umask(previous)


if __name__ == '__main__':
    main()
