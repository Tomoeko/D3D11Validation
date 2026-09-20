# Working agreement

## Scope and sequencing

- This repository owns the Windows connection, constrained execution,
  host qualification, and evidence transport for native D3D11 validation.
- Preserve the physical-host gates in ROADMAP.md. Do not quietly narrow a gate
  to Wine or software rendering.
- Use an operator session only for authorized inspection and setup. Run recurring
  tests under a dedicated standard account.
- Do not browse unrelated files, change the personal account, reuse its secrets,
  install broad remote-control agents, or grant administrator rights to the runner.
- Follow applicable approval requirements for creating remote access. Prepare an
  exact, reviewable change first. Enter an existing account credential in the local
  registration prompt only with explicit owner authorization; never hardcode it.

## Code quality

- Write readable, small functions with explicit inputs, outputs, and failures.
- Share validation and serialization code instead of duplicating implementations.
- Prefer native Windows APIs and small scripts over unnecessary dependencies.
- Keep deployment, connection, job validation, GPU capture, and comparison separate.
- Delete obsolete code and document actual supported behavior without speculation.
- Test trust boundaries and behavior, especially rejected requests, timeouts,
  cancellation, file replacement, reparse points, and stale evidence.
- Do not spawn agents unless the user explicitly requests delegation.

## Installation and unattended operation

- Keep one lifecycle entry point for installation, reinstallation, repair, status,
  and removal. Reuse implementation modules; do not maintain separate setup recipes.
- Preserve existing host configuration, identities, keys, and completed evidence.
  Record component ownership and recover interrupted changes transactionally.
- Normal operation must require neither RDP nor desktop screenshots or capture.
  Test startup after a real reboot before any manual login or RDP connection.
- Qualify the actual native and Unity execution context. A disconnected interactive
  session is not boot-time qualification; do not use Unity's `-nographics` for GPU tests.
- Bound recovery attempts. Never silently rerun interrupted comparisons, replace
  hardware with software rendering, or accept old evidence after environment drift.
- Keep credentials out of command lines, logs, packages, and Git. Prefer Windows
  managed identities or protected credential storage over automatic desktop logon.

## Access boundary

- The Mac may submit approved fixture data, request a fixed test, inspect status,
  cancel that job, and retrieve that job's results. No arbitrary command execution.
- Never evaluate a client-provided shell string, script, executable path, task name,
  or destination path. Use bounded typed requests and server-generated job IDs.
- Installed worker code and approved executable hashes must not be writable through
  the submission interface. Runner updates are separate reviewed deployments.
- Keep host credentials on the host and client private keys on the client. Do not
  copy GitHub credentials or the user's personal credentials to the worker.
- Restrict account ACLs and network access. A dedicated account or forced command
  alone is not a complete sandbox; prove the effective restrictions before use.
- Preserve pre-existing services, firewall rules, SSH settings, and user sessions.
  Provide targeted rollback; never weaken security globally to make a test pass.

## Privacy and Git

- Track this file and ROADMAP.md. Publication requires a completed history audit;
  never change repository visibility as a side effect of ordinary development.
- Never commit passwords, private keys, tokens, host IPs, machine names, personal
  account names/paths, license material, private Unity binaries, or raw RDP images.
- Use aliases in documentation and ignored local files for connection details.
- Keep real host baselines, deployment fingerprints and captured evidence outside
  Git, including hashes that identify private packages. Publish only synthetic
  fixtures and aggregate acceptance scope. Private visibility is not a substitute
  for privacy review. Never publish personal desktop material.
- Review the staged diff and tracked filenames before every checkpoint. Attribute
  commits to Tomoeko using the existing public noreply identity.

## Evidence and completion

- Distinguish observed inventory from the actual device used by each test process.
- Require native Microsoft D3D11/DXGI and the intended hardware adapter. Software
  fallback, a translation layer, missing identity, or changed environment fails
  qualification; it must never become a passing result.
- Preserve private Unity provenance by identifying the selected binaries. Do not
  compare them with stock Unity or assume equal versions imply equal binaries.
- Compare full bound DXBC and raw render-target data independently. Define any
  numerical tolerances before tests. RDP screenshots are not comparison inputs.
- Include repeat runs and deliberately incorrect shader controls. Bind results to
  exact inputs, binaries, Git revision, adapter/driver, session, and capture mode.
- Record unavailable or failed checks honestly. One GPU/driver and a finite corpus
  establish only that scope; no claim of universal semantic equivalence.
- Verify locally, checkpoint, push, then verify the remote commit and intended
  visibility. Never mark an unchecked roadmap item complete to end a turn.
