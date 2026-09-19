#!/usr/bin/env python3
"""Exercise the installed gateway using an already pinned SSH host."""

import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--host", default="d3d11-validation")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--phase", choices=("bootstrap", "worker"), default="bootstrap")
    args = parser.parse_args()
    base = ["ssh", "-F", str(args.config), "-o", "ConnectTimeout=5"]
    observations = []

    def run(label, options, command, check, config=None):
        invocation = base if config is None else ["ssh", "-F", str(config), "-o", "ConnectTimeout=5"]
        completed = subprocess.run(
            invocation + options + [args.host] + command,
            input="", capture_output=True, text=True, timeout=20,
        )
        passed = bool(check(completed))
        observations.append({"test": label, "passed": passed,
                             "exitCode": completed.returncode})
        if not passed:
            raise RuntimeError(f"SSH boundary check failed: {label}")
        return completed

    status = run("status", [], ["status"], lambda r: r.returncode == 0)
    document = json.loads(status.stdout)
    if args.phase == "bootstrap":
        inventory = document["inventory"]
        if (document["allowedOperations"] != ["status"] or
                document["testExecutionEnabled"] is not False or
                inventory["session"]["elevated"] is not False or
                inventory["hardwareD3D11Qualified"] is not False):
            raise RuntimeError("Status expanded the bootstrap boundary")
        service = inventory["openSsh"]
        if service["serviceQueryAvailable"]:
            if service["servicePresent"] is not True:
                raise RuntimeError("The installed SSH service was incorrectly reported absent")
        elif service["servicePresent"] is not None or service["serviceStatus"] is not None:
            raise RuntimeError("An unavailable service query reported a definitive result")
        session = inventory["session"]
    else:
        if (document["allowedOperations"] != ["submit", "start", "status", "results", "cancel"] or
                document["testExecutionEnabled"] is not True or document["worker"]["elevated"] is not False):
            raise RuntimeError("Unexpected worker boundary")
        session = {key: document["worker"][key] for key in ("sessionId", "elevated", "dedicatedAccount")}

    commands = json.loads(Path(__file__).with_name("rejected-commands.json").read_text())
    if args.phase == "worker":
        commands = [command for command in commands if command not in ("submit", "start", "results", "cancel")]
    for index, command in enumerate(commands):
        run(f"unsupported-command-{index}", ["-T"], [command] if command else [],
            lambda r: r.returncode == 64 and not r.stdout.strip() and
            r.stderr.strip() == '{"error":"unsupported_operation"}')

    run("sftp-subsystem", ["-s"], ["sftp"],
        lambda r: r.returncode in (64, 255) and not r.stdout.strip())
    run("direct-tcp-forward", ["-W", "127.0.0.1:9"], [],
        lambda r: r.returncode == 255 and "administratively prohibited" in r.stderr)
    run("remote-tcp-forward", ["-o", "ClearAllForwardings=no", "-o",
        "ExitOnForwardFailure=yes", "-R", "127.0.0.1:0:127.0.0.1:9", "-N"], [],
        lambda r: r.returncode == 255 and "remote port forwarding failed" in r.stderr)
    run("password-authentication", ["-o", "PubkeyAuthentication=no", "-o",
        "PasswordAuthentication=yes", "-o", "PreferredAuthentications=password"],
        ["status"], lambda r: r.returncode == 255 and "Permission denied (publickey)" in r.stderr)
    run("unapproved-account", ["-l", "d3d11-validation-rejected-account"], ["status"],
        lambda r: r.returncode == 255 and "Permission denied" in r.stderr)
    run("pty", ["-tt"], ["status"],
        lambda r: "PTY allocation request failed" in r.stderr)

    with tempfile.TemporaryDirectory(prefix="d3d11-ssh-negative-") as temporary:
        directory = Path(temporary)
        key = directory / "rejected-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                        "validation-negative-control", "-f", str(key)], check=True)
        original = args.config.read_text()

        def altered_config(setting, value):
            text, count = re.subn(r"(?m)^\s*" + setting + r"\s+.*$",
                                  "    " + setting + ' "' + str(value) + '"', original)
            if count != 1:
                raise RuntimeError("The test requires one explicit client setting: " + setting)
            output = directory / (setting + ".config")
            output.write_text(text)
            return output

        run("unapproved-key", ["-o", "IdentityAgent=none"], ["status"],
            lambda r: r.returncode == 255 and "Permission denied (publickey)" in r.stderr,
            config=altered_config("IdentityFile", key))
        public_key = key.with_suffix(".pub").read_text().split()
        known_hosts = directory / "wrong-known-hosts"
        known_hosts.write_text(args.host + " " + " ".join(public_key[:2]) + "\n")
        run("changed-host-key", [], ["status"],
            lambda r: r.returncode == 255 and "Host key verification failed" in r.stderr,
            config=altered_config("UserKnownHostsFile", known_hosts))

    report = {
        "schema": "d3d11-ssh-boundary/v1", "phase": args.phase,
        "testedUtc": datetime.now(timezone.utc).isoformat(),
        "checks": observations, "checksPassed": len(observations),
        "session": session, "testExecutionEnabled": args.phase == "worker",
        "hardwareD3D11Qualified": False,
        "scope": "SSH transport restrictions; job and graphics acceptance are recorded separately",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"PASS: {len(observations)} live SSH checks; non-elevated status session")


if __name__ == "__main__":
    main()
