# Validation and evidence scope

An existing physical Windows installation completed a finite campaign containing
41 Unity jobs, four native GPU/rejection jobs, 22 SSH boundary checks and 13 job
checks. Signed maintenance and the native/Unity campaign also passed after a real
reboot while the machine remained at sign-in, before manual login or RDP.
Private manifests and raw artifacts are retained by the operator, not published.
These totals summarize that campaign; they are not current-host attestation or a
claim that every platform/configuration passes.

Native qualification verifies the actual device, expected runtime identities and
signatures, process token/session, boot identity and raw readbacks. Permanent
policy pins hardware fields; each launch obtains a fresh LUID and ordinal from
an unambiguous inventory and checks the resulting device against that selection.

Unity tests independently compare complete shader containers and raw pixels,
including repeat launches and incorrect-shader controls. Capture-disabled runs
retain draw observation. A separately unhooked package checks whether the
instrumentation affects outputs for the fixed corpus. Four specific loaded
package members are verified; this is not complete loaded-module closure.

`client/unity_evidence.py` retrieves existing jobs through authenticated SSH and
binds observations to captured consumer bundle digests and pinned packages. It
rejects changed worker epochs and changed local policy files. Retrieval does not
submit or rerun jobs. `client/capture_unity.py` writes twelve positive traced
case observations into a bounded binary stream containing complete DXBC, pixels
and player records. The stream carries no certification flags.

A separately reviewed, image-bound selector profile permits five snapshots of
two shader-extension counters around bundle loading and direct draws. Invalid
profiles, unreadable state or nonzero counters fail that observation contract.
Snapshots do not establish absence between observations, identify a selected
alias, or certify logical runtime selection. Profile offsets and image hashes
remain private inputs.

## Local checks

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
pwsh -NoProfile -File tests/Test-RuntimeIdentity.ps1
pwsh -NoProfile -File tests/Test-AdapterSelection.ps1
pwsh -NoProfile -File tests/Test-UnityStartupPrivacy.ps1
```

The unit fixtures use synthetic hardware identities, signatures and addresses.
Other `tests/Test-*.ps1` files cover protocol, archive, task and parsing boundaries;
`Test-JobRuntime.ps1` and `Test-WorkerTaskPlan.ps1` require Windows. The
`test_*_worker.py`, SSH and job boundary
scripts are explicit physical-host campaigns requiring private configuration.
Do not run them against an unreviewed installation or treat portable unit tests
as physical qualification. See [ROADMAP.md](ROADMAP.md) for unqualified scenarios.
