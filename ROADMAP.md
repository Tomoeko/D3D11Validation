# Roadmap

This roadmap separates implemented behavior from qualification on a particular
installation. Private host records are maintained outside Git. Public acceptance
summaries and their limits are in [VALIDATION.md](VALIDATION.md).

## Implemented and exercised on an existing installation

- [x] Dedicated standard account and restricted authenticated SSH gateway.
- [x] Typed, bounded jobs with cancellation, expiry and explicit stale states.
- [x] Protected executable policies and native runtime/signature verification.
- [x] Unique current adapter selection and actual-device identity checks.
- [x] Native D3D11 raw readbacks, repeat runs and adapter rejection controls.
- [x] Unity full-DXBC and raw-pixel comparison across a finite keyword/tier corpus.
- [x] Capture-disabled and separately unhooked package controls.
- [x] Session 0 startup and successful GPU work after reboot before manual login.
- [x] Separately signed activation, repair and evidence-preserving queue rotation.
- [x] Replay rejection, immutable deployment directories and bounded boot recovery.
- [x] Authenticated retrieval bound to captured consumer inputs and package identity.
- [x] Image-bound shader-extension snapshots with explicit finite-observation limits.

## Remaining qualification gates

- [ ] Qualify clean-host install, reinstall and removal, including interrupted setup.
- [ ] Exercise the full lifecycle fault matrix: restart during GPU work, delayed
      networking, corrupted state, exhausted recovery and interrupted activation.
- [ ] Requalify each changed executable/package and every new OS, GPU or driver
      baseline on physical hardware; previous results do not transfer implicitly.
- [ ] Expand hardware and shader coverage with declared comparison tolerances and
      independent negative controls.

## Release discipline

- [x] Prepare a new, independent repository containing only audited history; keep
      the former repository private and archived. Original commit IDs and the
      private baseline blob are not retrievable from the replacement repository.
- [x] Audit hosted pull requests, forks, release attachments and workflow artifacts
      as well as Git objects. The replacement has none of those hosted artifacts.

The replacement remains private pending an explicit publication decision. Repeat
the privacy review for subsequent changes before changing visibility.

Source-only tests are useful checks, but they do not close physical-host gates.
Never infer completion from a disconnected desktop session, a maintenance status,
a matching version string, or a startup log mentioning a GPU.
