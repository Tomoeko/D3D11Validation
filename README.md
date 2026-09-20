# D3D11Validation

D3D11Validation runs bounded shader-validation jobs on physical Windows hardware
through authenticated SSH. A dedicated standard-account worker uses native
Microsoft D3D11/DXGI, an explicitly pinned GPU and driver, and raw render-target
readbacks. Normal operation requires no Remote Desktop GUI or manual login.

This is experimental infrastructure developed with substantial assistance from
Codex and ChatGPT. It is designed for reviewed fixtures and operator-managed
machines, not arbitrary remote workloads.

## What it does

- Accepts typed `submit`, `start`, `status`, `results`, and `cancel` requests.
- Rejects arbitrary commands, executables, paths, shells, PTYs and forwarding.
- Pins deployed code, native runtime signatures, hardware identity and packages.
- Captures complete bound DXBC and raw pixels as independent comparison inputs.
- Runs a standard-account Session 0 worker at boot and supports separately signed
  activation, repair and queue archival through protected maintenance code.
- Rejects stale environments, ambiguous adapters, software rendering and Wine.

See [HEADLESS.md](HEADLESS.md) for setup and maintenance,
[VALIDATION.md](VALIDATION.md) for evidence scope and local checks, and
[ROADMAP.md](ROADMAP.md) for remaining qualification work. Headless reboot
acceptance passed on an existing installation. Clean-host installation and the
complete lifecycle fault matrix remain unqualified.

## Build and configure

Native components require a Windows SDK and a C++17 compiler, or a Windows cross
compiler providing the corresponding headers and libraries. Clients require
Python 3 and OpenSSH; Windows scripts use Windows PowerShell. Local portable
script tests can also run with PowerShell 7.

Run `windows/Get-ValidationInventory.ps1` locally to collect a preliminary host
inventory. Inventory alone does not qualify a rendering device. Review the actual
adapter, runtime hashes and signatures before authoring the private baseline.
The baseline schema is illustrated by `tests/fixtures/native-baseline.json`,
which contains deliberately invented values and must never be deployed.

Keep configuration in ignored `.local/` storage. Both native compilation and
worker packaging must use the same reviewed host baseline:

```sh
cmake -S . -B build -DD3D11_VALIDATION_BASELINE="$PWD/.local/native-baseline.json"
cmake --build build --config Release
python3 client/build_deployment.py --help
python3 client/validation_client.py --help
```

Pass `--native-baseline .local/native-baseline.json` when packaging a worker.
The generated native policy header and executables contain private hardware
selection data; keep build directories and deployment archives private. This
repository distributes source and synthetic fixtures, not a prequalified runtime.
Private Unity players, bundles, licenses and image-bound profiles are supplied
separately by their operator and are not distributed here.

## Privacy and evidence

Host addresses, account details, machine inventories, deployment fingerprints,
raw logs, job capabilities, publisher keys and captured artifacts stay outside
Git. See [PRIVACY.md](PRIVACY.md) for the publication review. Never upload `.local/`, build output or private evidence to issues, releases
or CI artifacts. A passing maintenance receipt reports an operation, not GPU
qualification or shader equivalence. Finite observations do not prove universal
semantic equivalence or runtime winner selection.

## License

Source is licensed under [GPL-3.0-only](LICENSE). Operator-supplied Windows and
Unity components retain their own licenses and are not included.
