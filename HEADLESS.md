# Headless operation

The worker runs native GPU tests in Session 0 without an RDP connection. A fixed
startup task and signed maintenance support deployment, queue rotation and worker
recovery without an operator desktop. Reboot acceptance passed on an existing
installation; clean-host installation and full lifecycle fault acceptance remain
open. Each new deployment must be qualified against its own private baseline.

## One-time local bootstrap

Use an elevated Windows PowerShell console on the physical PC. No administrator
SSH login, WinRM endpoint, automatic desktop login, or remote-control agent is
installed. Build a private bootstrap archive with
`client/build_headless_bootstrap.py`, transfer that exact hash-pinned archive,
extract it to a new directory, and run `./Install-Headless.ps1`. The generated
entry contains the selected deployment, policy, prior gateway, SSH configuration,
source manifest and public publisher key pins. A mismatch stops setup.

The installer asks for the dedicated validation account's password in the
console once to register the fixed S4U task. It is never written to a command
line, package, log, task XML or credential file. The task stores no password.
Future worker updates change the protected deployment selection; they do not
register the account's task again.

The bootstrap adopts the existing qualified installation. It preserves its
account, SSH key, host key, listener address, firewall rules, approved packages
and completed evidence. It makes the owned SSH service automatic, adds a boot
trigger to the standard-account worker, and installs one SYSTEM maintenance task.
The latter runs only protected bootstrap code, every minute and at startup.
Setup records its original gateway and task, and attempts targeted rollback if
installation fails. Inspect `setup/headless-v1/installation.json` after an
interruption; incomplete bootstrap recovery still requires local review.

## Access and release authority

The five test operations remain `submit`, `start`, `status`, `results`, and
`cancel`. The stable forced command also recognizes a separate `maintenance`
request and `maintenance-status`. It continues to reject shells, PTYs, arbitrary
commands, user-selected executable paths, task names and destination paths.

Maintenance mutations require a separate RSA-3072 publisher signature, in
addition to the existing SSH authentication. Keep that private key only on the
operator client in ignored, owner-readable storage. Its public key is installed by the
reviewed bootstrap. This key authorizes worker code and Unity package updates
under the standard account; it does not authorize changes to the privileged
bootstrap, SSH settings, account, firewall, publisher key, or arbitrary tasks.
Those require a new local operator review.

Each signed request binds the current generation and policy, a unique request
identity, a short expiry, and one of three actions:

- `activate`: fetch a hash-pinned release from the configured Mac address over
  TLS with the exact certificate pin in the signed request. Reject unsafe ZIP
  names, duplicate files, file/directory conflicts, links, oversized archives,
  and existing destination directories. Stop the worker, acquire an exclusive
  activation guard, switch the protected selection atomically, and restart the
  same fixed task.
- `repair`: verify the selected deployment and restart the fixed worker. An
  interrupted job becomes stale; it is never automatically rerun.
- `archive`: stop the worker and block job dispatch while preserving completed
  evidence and submission tombstones, then start with a fresh bounded queue.

The SYSTEM task never imports or executes modules from an uploaded deployment.
It uses only the immutable bootstrap modules. Releases can contain new
`worker-vN`, `unity-draw-vN`, and `unity-unhooked-vN` directories. They cannot
replace `headless-v1` or other host files. Existing release folders are immutable;
rollback requires repackaging a known release under a new versioned name.

The transport binds the existing link-local addresses. If the network is late
at boot, the fixed maintenance task waits for the configured address, then makes
at most three SSH start attempts per boot. It never changes network or firewall
configuration. The worker task has three restart attempts. Exhaustion, corrupt
state and failed maintenance remain visible failures needing explicit repair.

## Mac commands

Use `python3 client/headless_client.py status` after bootstrap. For a repair:

```sh
python3 client/headless_client.py repair \
  --publisher-key .local/headless-bootstrap-v1/publisher-private.pem \
  --request-file .local/repair-001.json
```

`archive` uses the same arguments. Save each signed request before sending it;
retry the exact file with `retry --request-file …`. Do not invent a new request
because the connection dropped. The receipt binds the exact signed bytes and
reports a durable phase. A successful maintenance receipt means the maintenance
action finished; it never certifies GPU execution or a shader comparison.

For activation, publish the reviewed archive with `client/serve_deployment.py`
and save its private JSON metadata, augmented with `deployment` and
`policySha256`. Pass that file with `activate --publication …`, the publisher
key, and a new request file. The temporary TLS listener serves only the chosen
Windows peer and closes after one transfer or five minutes.

The local Windows lifecycle entry is
`program/headless-v1/Manage-ValidationHeadless.ps1` with `Install`, `Reinstall`,
`Repair`, `Status`, and `Remove` modes. On a completed installation, repeat
Install is status-only; Reinstall and Repair preserve all identity and evidence
and re-enable the owned components. Remove verifies the owned task definitions,
removes both startup tasks, restores the previous gateway, and disables the
validation SSH service. It preserves the account, keys, deployment files and
evidence. This is scoped adoption/removal of the current installation, not a
qualified clean-host installer.

## Acceptance status

The installed bootstrap has passed eight physical maintenance checks, 22 SSH
boundary checks, 13 job checks, signed worker activation, signed queue rotation,
archived-request replay rejection, four native GPU/rejection jobs, and the full
41-job Unity comparison campaign. See [VALIDATION.md](VALIDATION.md) for the public acceptance scope. Maintenance requests are
independently signed; retries preserve the exact request and return its existing
receipt. A lost response does not authorize a new execution.

The worker/package contract selects one unique GPU from a fresh pinned
native inventory for each launch. Permanent policy pins hardware fields, while
the current LUID and ordinal are recorded as execution evidence and checked
against the actual device. It fails on duplicate hardware identities, unexpected
adapters or driver hashes, and includes the Windows boot time in the environment.
The Unity package uses this explicit selection contract. It also verifies the
loaded player executable, UnityPlayer, Mono runtime, and managed harness against
four exact package members; this is not a complete loaded-module closure claim.

Fresh-reboot acceptance included transport and worker startup, native/Unity GPU
jobs, SSH/job boundaries and signed repair before manual login. The current
inventory and actual device agreed after the boot-time adapter identity changed.
Maintenance receipts and status do not compute GPU qualification; campaign
evidence is the authority for that result.

Full fault recovery, restart during a job, and clean-host install/reinstall/remove
remain separate roadmap gates. The existing-host lifecycle entry is not a
qualified clean-host installer.

See [Microsoft's Task Scheduler security documentation](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
for the one-time cross-account S4U registration requirement.
