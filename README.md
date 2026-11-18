# PatchProbe

PatchProbe evaluates security patches for native programs by comparing a vulnerable base revision with a candidate revision. It builds both versions, runs the same inputs against them, collects runtime evidence, checks functional behavior and binary hardening, and produces a verdict suitable for CI/CD.

The project includes two C targets: **jsoncheck**, a JSON validator built around cJSON, and **imginfo**, an image inspection program built around stb_image. Each includes reference inputs and candidate revisions demonstrating correct fixes, incomplete fixes, functional regressions, and build failures.

PatchProbe is a Data and Network Security course project at Sharif University of Technology. The Python package reports version **1.1.0**. Console messages and generated report explanations are primarily in Persian; machine-readable field names and status identifiers are in English.

**A successful result means the patch passed the configured checks on the available inputs. It does not prove that the program is free of vulnerabilities.**

## Contents

- [Quick start](#quick-start)
- [Requirements and installation](#requirements-and-installation)
- [Running with Docker](#running-with-docker)
- [Targets and test inputs](#targets-and-test-inputs)
- [Validation theory and workflow](#validation-theory-and-workflow)
- [Verdicts and exit codes](#verdicts-and-exit-codes)
- [Command-line reference](#command-line-reference)
- [Reports and reproduction bundles](#reports-and-reproduction-bundles)
- [Regression suites](#regression-suites)
- [Testing the project](#testing-the-project)
- [Evaluating an external patch](#evaluating-an-external-patch)
- [Adding a target](#adding-a-target)
- [CI/CD](#cicd)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Scope and limitations](#scope-and-limitations)
- [Further reading](#further-reading)

## Quick start

Run these commands from the project root on Linux after installing the dependencies below:

```bash
bash scripts/setup_targets.sh
python3 -m pytest tests/ -q

python3 -m patchprobe \
  --config targets/jsoncheck/config.json \
  --base-ref main \
  --patched-ref patch-correct \
  --out-json reports/jsoncheck/quickstart/report.json \
  --out-md reports/jsoncheck/quickstart/report.md \
  --bundles-dir bundles/jsoncheck/quickstart \
  --no-regression-add
```

The expected PatchProbe exit code is `0` (`PASS`). Open `reports/jsoncheck/quickstart/report.md` for the readable result, or inspect the JSON:

```bash
python3 -m json.tool reports/jsoncheck/quickstart/report.json
```

`--no-regression-add` keeps this example from updating the stored regression inputs and metadata. Existing regression entries are still checked.

To evaluate the image target:

```bash
python3 -m patchprobe \
  --config targets/imginfo/config.json \
  --base-ref main \
  --patched-ref patch-correct \
  --reports-dir reports/imginfo/quickstart \
  --no-regression-add
```

With `--reports-dir`, output filenames use a generated run ID: `<run_id>.json` and `<run_id>.md`. Use `--out-json` and `--out-md` when you need fixed filenames.

The `--base-ref` and `--patched-ref` arguments refer to the **target repository** selected by the configuration, such as `targets/jsoncheck/repo`. They accept branches, tags, or commit hashes that exist in that target repository.

## Requirements and installation

### Supported environment

Use a Linux environment with ELF binaries and POSIX resource limits. The supplied container uses Debian 12 and Python 3.11; the GitHub workflow selects Python 3.12. Windows users can use a Linux VM, WSL2, or Docker with Linux containers. Native Windows and macOS execution is not the intended environment.

| Dependency | Purpose |
| --- | --- |
| Python 3.11 or 3.12 | Run the tool and test helpers |
| GCC with ASan/UBSan runtimes, libc development headers, Make | Compile target programs and instrumented binaries |
| Git | Restore target repositories, resolve revisions, export source trees, and calculate diffs |
| GNU binutils, especially `readelf` | Inspect instrumentation and ELF hardening |
| Bash and standard Unix tools | Setup, scenario, and reproducer scripts |
| pytest | Run the automated unit tests |
| Pillow, optional | Regenerate image fixtures and their independent reference data |
| Docker Engine and Compose, optional | Run the supplied container environment |

The PatchProbe runtime uses the Python standard library. There is no package installation step or `requirements.txt` for running `python3 -m patchprobe` from the project root. pytest is a testing dependency; Pillow is unnecessary when using the included image files.

### Debian or Ubuntu installation

```bash
sudo apt-get update
sudo apt-get install -y \
  python3 python3-venv python3-pytest \
  gcc libc6-dev make git binutils ca-certificates

git clone https://github.com/Keyhan-Hodaei/Security-Course-Project.git
cd Security-Course-Project
bash scripts/setup_targets.sh
```

If a Python version manager selects a different interpreter from the one used by the system package manager, either run `/usr/bin/python3 -m pytest` or create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest
# Optional, only for regenerating image fixtures:
python -m pip install Pillow
```

Keep local virtual environments out of version control. Check the tools with:

```bash
python3 --version
gcc --version
git --version
readelf --version
python3 -m patchprobe --version
python3 -m patchprobe --help
```

### Restoring the target repositories

Each target ships as `targets/<target>/repo.bundle`. The setup script restores it into `targets/<target>/repo/` and creates its local scenario branches. It skips repositories that are already present. Configuration loading can also restore a missing repository from its adjacent bundle.

```bash
bash scripts/setup_targets.sh
git -C targets/jsoncheck/repo branch --list
git -C targets/imginfo/repo branch --list
```

Once dependencies are installed, the included scenarios do not require a network connection. Target source and input data are included in the repository.

## Running with Docker

Build and run the unit tests followed by the full standard scenario matrix:

```bash
docker compose up --build --abort-on-container-exit --exit-code-from validate
```

The image build installs dependencies and restores the target repositories. The validation container runs as the non-root `tester` user. Compose configures:

- No runtime network access.
- A 2 GiB memory limit, a 2 CPU allocation limit, and a 256-process limit.
- A 1 GiB executable temporary filesystem at `/tmp`.
- All Linux capabilities dropped and `no-new-privileges` enabled.

Image construction requires access to the base image and Debian package repositories. `network_mode: none` applies to the validation service at runtime.

There are no host output mounts in the supplied Compose file. Copy the results out before removing the container:

```bash
mkdir -p artifacts
docker compose cp validate:/workspace/reports ./artifacts/reports
docker compose cp validate:/workspace/bundles ./artifacts/bundles
docker compose cp validate:/workspace/regression ./artifacts/regression
docker compose down
```

To run only the unit tests or the unseen-patch suite inside the same service configuration:

```bash
docker compose run --rm validate python3 -m pytest tests/ -q
docker compose run --rm validate python3 defense/run_unseen.py
```

The `--rm` examples remove their containers and generated outputs afterward. Use the persistent service workflow when you want to export artifacts.

Native execution applies process resource limits but does not isolate the target from the host filesystem or network. Build commands and target programs execute code; use an appropriate isolated environment for unfamiliar inputs or patches.

## Targets and test inputs

| Target | Library | Input interface | Valid / boundary / invalid cases | Reference behavior |
| --- | --- | --- | --- | --- |
| `jsoncheck` | cJSON | Standard input | 6 / 7 / 6 = 19 | Python's `json` module and the wrapper's documented output contract |
| `imginfo` | stb_image | A single filename argument | 5 / 3 / 6 = 14 | Pillow decoding and image properties |

For `jsoncheck`, valid documents produce output such as `PARSE_OK type=object n=4`. Invalid documents are expected to exit with code `1`. The supplied vulnerable source has string-parsing bounds errors exercised by malformed JSON, including unterminated strings. The incomplete candidate adds a superficial input guard that leaves other malformed inputs able to trigger the error.

For `imginfo`, valid images produce output such as `IMG_OK w=32 h=32 c=3 sum=8100`; invalid images should produce `IMG_ERR` and exit with code `1`. The security cases exercise JPEG Huffman-table bounds checking. One crafted DHT contains 654 symbols, while another contains 257 and exposes an off-by-one check. A guard that blocks only the larger example is insufficient.

The reference checks are independent of the vulnerable parser. PNG and BMP fixtures use exact pixel checksums. JPEG cases check dimensions, channels, and the numeric form of the checksum because decoded pixel values can differ between implementations.

The configuration files are the authoritative list of executed tests and expected outputs. The generators and fixture manifests support preparation of that list; they are not invoked automatically during validation.

### Included target revisions

Both targets include `main`, `patch-correct`, `patch-incomplete`, `patch-regression`, and `build-broken`. jsoncheck also includes `patch-newissue` and `patch-mixed`.

| Candidate | Purpose |
| --- | --- |
| `patch-correct` | Fix the tested vulnerability while preserving the reference behavior |
| `patch-incomplete` | Block some failing inputs while leaving a bypass |
| `patch-regression` | Fix the vulnerability but impose a restriction that rejects valid input |
| `patch-newissue` | Introduce another confirmed memory error in jsoncheck |
| `patch-mixed` | Combine an incomplete fix and a functional regression in jsoncheck |
| `build-broken` | Exercise compilation failure handling |

These names describe the fixtures. The evaluator resolves revisions to hashes and computes its verdict from builds and execution evidence; it does not select a verdict from a branch name.

## Validation theory and workflow

### 1. Compare two versions using two build modes

A patch must address the tested security failure and preserve required functionality. PatchProbe separates those questions using four builds:

| | Base revision | Candidate revision |
| --- | --- | --- |
| Normal build | `base_release` | `patched_release` |
| Instrumented build | `base_sanitized` | `patched_sanitized` |

Every version/build combination gets a separate exported source tree. This prevents an existing Make output from accidentally being reused as a different build mode.

The default normal flags are `-O2 -pipe -g`. The instrumented flags are:

```text
-O1 -g -fsanitize=address,undefined
-fno-sanitize-recover=undefined -fno-omit-frame-pointer -U_FORTIFY_SOURCE
```

Debug information and preserved frame pointers help associate runtime diagnostics with source functions. Undefining `_FORTIFY_SOURCE` in the instrumented build helps avoid an earlier library abort obscuring sanitizer evidence. The normal build retains its toolchain's ordinary protection behavior.

PatchProbe adds `-ffile-prefix-map=<source-directory>=.` and builds with `SOURCE_DATE_EPOCH=0` to reduce path- and timestamp-dependent binary differences. It records SHA-256 hashes and checks symbol tables: instrumented binaries must contain ASan or UBSan runtime symbols, and normal binaries must not.

### 2. Distinguish a diagnostic from a termination

AddressSanitizer instruments memory accesses and can detect errors such as buffer overflows and use-after-free. UndefinedBehaviorSanitizer checks selected undefined operations, including invalid indexing, null-pointer use, and integer division by zero. These checks provide evidence about operations that actually execute. See the official [ASan documentation](https://clang.llvm.org/docs/AddressSanitizer.html) and [UBSan documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).

PatchProbe records three separate concepts:

| Concept | Examples |
| --- | --- |
| Observed error type | `HEAP_BUFFER_OVERFLOW`, `USE_AFTER_FREE`, `INDEX_OUT_OF_BOUNDS`, `DIV_BY_ZERO` |
| Detection mechanism | `sanitizer:ASan`, `sanitizer:UBSan`, `protection:stack-canary`, `protection:fortify-source` |
| Process outcome | Exit code, operating-system signal, timeout, or failure to start |

A nonzero exit code may be a normal rejection of invalid input. A segmentation fault without a usable diagnostic is an unclassified termination. Neither alone identifies a confirmed memory error. A protection abort in the normal build is reported separately from the sanitizer finding.

The runner uses a separate process group, wall-clock timeout, CPU limits, address-space limits where applicable, file-size and descriptor limits, and disabled core dumps. On timeout it attempts to terminate the process group.

### 3. Match findings by signature

Findings are grouped using:

```text
ERROR_TYPE[/READ_OR_WRITE]@TOP_APPLICATION_FUNCTION
```

For example, `HEAP_BUFFER_OVERFLOW/READ@parse_string` identifies a read overflow at the selected application frame. Sanitizer and common runtime frames are filtered where possible. If no function is available, the location falls back to a filename or detection mechanism.

The signature excludes raw memory addresses and line numbers so that address randomization and shifted source lines do not automatically create different findings. Read and write failures remain distinct. This is a heuristic identity, not proof that two observations have the same root cause.

### 4. Classify the security effect

Let `B` be the set of confirmed signatures in the base and `P` the set in the candidate:

| Set relation | Finding status | Meaning within the executed inputs |
| --- | --- | --- |
| `B − P` | `FIXED` | Observed in the base and no longer observed in the candidate |
| `B ∩ P` | `INCOMPLETE_FIX` | Still observed in the candidate |
| `P − B` | `NEW_ISSUE` | Observed only in the candidate |

For incomplete fixes, PatchProbe records a bypass input that still triggers the candidate. When available, it also selects a distinct base input that the patch successfully blocks. This shows why passing one original reproducer is insufficient.

### 5. Link execution evidence to the patch

The tool extracts changed line ranges, scans both versions for overlapping C functions, and compares those functions with the runtime stack:

| Correlation | Evidence |
| --- | --- |
| `STRONG` | The selected top application frame is a changed function |
| `MODERATE` | A changed function appears elsewhere in the stack |
| `SAME_FILE` | The error's file changed, without a matching changed function |
| `NONE` | No matching changed function or file was found |

The same input is also compared across corresponding builds of both versions. Function overlap and differential execution offer complementary evidence. `NONE` means the patch relationship is uncertain; it does not discard a confirmed candidate-side error or automatically force the overall verdict to `INCONCLUSIVE`.

### 6. Check functional behavior independently

Functional comparison uses the **normal builds** and configured reference expectations. A case participates when it has `expect_exit`; it can additionally specify exact stdout or a full-match regular expression. Surrounding whitespace is stripped before stdout comparison.

A functional regression is a test that met its reference expectation in the base and violates it in the candidate. Base failures are recorded separately. This prevents expected rejection of malformed input from being mistaken for a security finding and avoids treating already-broken base behavior as a newly introduced regression.

### 7. Replay and minimize

Each representative confirmed finding is replayed at least three times on its instrumented version. Stable replay requires the same nonempty signature across all replay attempts. Instability contributes an inconclusive condition to the verdict.

The minimizer uses byte deletion inspired by delta debugging: split the input, try removing chunks, keep a smaller candidate only when it preserves the required signature, and refine the chunk size. This follows the approach described by Zeller and Hildebrandt in [Simplifying and Isolating Failure-Inducing Input](https://www.st.cs.uni-saarland.de/papers/tse2002/tse2002.pdf).

The default candidate-execution budget is 120 per minimization. A final signature check runs outside that budget. If verification fails, the original input is retained. The implementation does not test an empty candidate, and a budget-limited run does not guarantee a globally smallest or fully 1-minimal input.

### 8. Inspect binary hardening

Hardening checks inspect the two normal ELF binaries using `readelf`:

| Property | Interpretation and evidence |
| --- | --- |
| PIE | Position-independent executable classification from ELF type `DYN` |
| NX | Stack execute permissions from `GNU_STACK` |
| RELRO | `GNU_RELRO` segment; immediate binding distinguishes full from partial RELRO |
| Stack canary | Presence of `__stack_chk_fail` |
| FORTIFY, supplementary | Recognized `__*_chk` symbols |

These protections can make some forms of exploitation harder, but they do not fix the underlying invalid operation. PIE does not establish that ASLR is enabled, and a canary symbol does not prove every function is protected. Missing or unusual ELF metadata requires cautious interpretation.

PatchProbe reports weakening of PIE, NX, RELRO, or canary protection as warnings. Hardening warnings alone do not change the verdict code.

## Verdicts and exit codes

| Exit | Name | Meaning |
| --- | --- | --- |
| `0` | `PASS` | The base finding reproduced, candidate checks found no remaining/new confirmed error, and no higher-priority condition was raised |
| `10` | `VULN_REMAINS` | An incomplete fix, new confirmed issue, or known regression signature is present in the candidate |
| `20` | `FUNC_REGRESSION` | At least one reference test that passed on the base fails on the candidate |
| `30` | `BUILD_OR_CONFIG_ERROR` | Configuration, revision resolution, compilation, instrumentation, or tool/environment failure prevents evaluation |
| `40` | `INCONCLUSIVE` | Evidence is insufficient or checks are incomplete: for example, no confirmed base finding, unstable replay, an unclassified termination, or a resource-limit event |

When conditions coexist, priority is **30 → 10 → 20 → 40 → 0**. The JSON `verdict.flags` retains independent conditions even when a higher-priority code wins.

Examples:

- A remaining vulnerability plus changed output returns `10`, while also recording the functional regression.
- A hang on a case that passed in the base can return `20`, with an inconclusive flag for the timeout.
- A base revision with no reproduced confirmed finding cannot establish that the candidate fixed the targeted problem; absent higher-priority failures, the result is `40`.

Capture expected nonzero results without losing them to shell error handling:

```bash
rc=0
python3 -m patchprobe \
  --config targets/jsoncheck/config.json \
  --base-ref main --patched-ref patch-incomplete \
  --no-regression-add || rc=$?
printf 'PatchProbe exit code: %s\n' "$rc"
test "$rc" -eq 10
```

The target program's own exit code and PatchProbe's final exit code are different layers. For example, a target returning `1` for invalid JSON can be correct behavior within a PatchProbe run that returns `0`.

## Command-line reference

```text
python3 -m patchprobe --config CONFIG --base-ref REF --patched-ref REF [OPTIONS]
```

| Option | Default / behavior |
| --- | --- |
| `--config PATH` | Required target JSON configuration |
| `--base-ref REF` | Required base revision in the target repository |
| `--patched-ref REF` | Required candidate revision in the target repository |
| `--reports-dir DIR` | `reports/<target>/`; contains run-ID-named JSON and Markdown files |
| `--out-json PATH` | Explicit JSON filename; overrides its directory-derived default |
| `--out-md PATH` | Explicit Markdown filename; overrides its directory-derived default |
| `--bundles-dir DIR` | `bundles/<target>/<run_id>/` |
| `--work-dir DIR` | Otherwise creates a temporary work directory |
| `--keep-work` | Preserve exported source trees and compiled binaries |
| `--replays N` | Default `3`; values below `3` are rejected |
| `--jobs N` | `0` selects `min(8, CPU count)`; use a positive value to override |
| `--no-minimize` | Skip input minimization |
| `--minimize-budget N` | Default `120` candidate executions per finding/witness minimization |
| `--regression-dir DIR` | Parent directory for per-target suites; default `regression/` |
| `--no-regression-add` | Disable adding/updating stored regression entries |
| `--no-regression-verify` | Skip checks of stored regression entries |
| `--quiet` | Suppress the ordinary console summary; files are still written |
| `--version` | Print the tool version |
| `-h`, `--help` | Print usage |

Use a dedicated disposable directory with `--work-dir`: **the tool removes the entire work directory on completion unless `--keep-work` is specified**, including a directory supplied explicitly.

For investigation, retain all four build trees:

```bash
python3 -m patchprobe \
  --config targets/jsoncheck/config.json \
  --base-ref main --patched-ref patch-correct \
  --work-dir /tmp/patchprobe-inspect --keep-work \
  --jobs 1 --no-regression-add
```

The retained directories are `base-release`, `base-sanitized`, `patched-release`, and `patched-sanitized`. Use a fresh work directory for a new investigation.

## Reports and reproduction bundles

A completed evaluation writes JSON and Markdown. The normal JSON result includes:

| Field | Contents |
| --- | --- |
| `run_id`, `tool_version`, `target` | Run identity |
| `refs`, `commits`, `subjects` | Requested and resolved target revisions |
| `builds`, `build_flags`, `build_commands`, `binaries` | Build metadata, instrumentation evidence, and hashes |
| `environment`, `limits` | Runtime settings, parallelism, replay count, and limits |
| `hardening` | Base/candidate protection evidence and changes |
| `diff_stat`, `diff_files` | Changed files, ranges, and mapped functions |
| `findings` | Signatures, classification, replay/minimization results, correlation, and four-build behavior |
| `func_results`, `tests` | Reference comparisons and per-test outcomes |
| `anomalies` | Resource events, unclassified terminations, and instability |
| `regression_suite`, `bundles` | Stored-suite checks and reproduction artifacts |
| `summary`, `verdict`, `duration_sec` | Counts, decision, reasons, flags, and elapsed time |

`summary.runs_total` counts the initial four-build test matrix; it does not count every replay, minimization attempt, regression check, or sanitizer retry. Early build/configuration failures have a smaller report and do not contain all fields above. Argument-parser errors and unexpected internal exceptions may return `30` without a complete report.

A finding's bundle normally contains:

```text
bundles/<target>/<run_id>/B01/
├── manifest.json
├── input.original
├── input.minimized       # when minimization produced an artifact
└── reproduce.sh
```

Base findings use `B...` identifiers, candidate findings use `P...`, and incomplete-fix witnesses can have a separate `B...-bypass` bundle. The manifest records the source revision, binary hash, build flags, environment, limits, signature, replay results, and counterpart observations. Bundles contain inputs and instructions; they do not embed the whole source repository or compiler.

After the jsoncheck quick-start example:

```bash
bash bundles/jsoncheck/quickstart/B01/reproduce.sh

# If the bundle was moved, explicitly supply the target repository:
bash bundles/jsoncheck/quickstart/B01/reproduce.sh \
  "$PWD/targets/jsoncheck/repo"

# Replay the original input instead of the minimized one:
INPUT_KIND=input.original bash bundles/jsoncheck/quickstart/B01/reproduce.sh
```

The script rebuilds the recorded revision, compares the binary hash, and performs three replays. A compiler/environment difference can produce a hash mismatch warning without immediately failing reproduction. Its final success check uses error-type and function patterns in the diagnostics; it is less strict than the Python signature matcher. It also does not reapply the full Python runner's resource limits, so run it in the same isolated environment used for validation.

The script needs the recorded target revision to remain available. In particular, bundles produced by the external-patch helper refer to its temporary patched repository, which is deleted afterward. To replay those bundles later, retain or recreate the patched source revision and pass that repository explicitly.

## Regression suites

Stored regression tests live under:

```text
regression/<target>/
├── suite.json
└── inputs/R-<signature-hash>.input
```

Stable base findings are eligible for automatic addition. A verified smaller input is preferred; otherwise the original reproducer is stored. IDs derive from the signature, with a separate variant for bypass witnesses. Entries include the expected signature and the base revisions where it was observed.

Each verification checks that the signature appears on the appropriate base and disappears on the candidate:

- The known signature returning on the candidate contributes `VULN_REMAINS`.
- Failure to reproduce on the same recorded base makes the entry stale or unstable and contributes `INCONCLUSIVE`.
- If the current base is a different revision, a missing base signature can be marked not applicable; the candidate check still runs.

Normal runs can update input files and suite metadata, including `last_seen_run`. Use `--no-regression-add` for read-only use of the existing suite. To experiment with a separate copy:

```bash
regression_copy=$(mktemp -d /tmp/patchprobe-regression.XXXXXX)
cp -a regression/. "$regression_copy/"
python3 -m patchprobe \
  --config targets/jsoncheck/config.json \
  --base-ref main --patched-ref patch-correct \
  --regression-dir "$regression_copy"
```

Keep the suite and its inputs together. Avoid concurrent writers to the same suite directory; use a separate copy per independent job.

## Testing the project

### Unit tests

```bash
python3 -m pytest tests/ -q
```

The current suite contains **16 tests** covering evidence parsing, sanitizer startup failures, C-function scanning, diff parsing, finding classification, correlation, verdict precedence, minimization, configuration validation, regression IDs, process behavior, and hardening inspection.

Some tests compile small real binaries and invoke `readelf`, so pytest alone is insufficient: GCC, libc headers, and binutils must also be available. The hardening test expects the default GCC toolchain to produce PIE, as in the supplied Debian/Ubuntu environment.

### Standard scenario matrix

```bash
bash scenarios/run_all.sh

# Or select a target:
bash scenarios/run_all.sh jsoncheck
bash scenarios/run_all.sh imginfo

# Choose an explicit Python interpreter:
PYTHON=/usr/bin/python3 bash scenarios/run_all.sh
```

The full matrix contains **16 scenarios**. The script checks each PatchProbe exit code against the expected result and exits `0` only when all comparisons match. A successful scenario test can therefore deliberately exercise a PatchProbe result of `10`, `20`, `30`, or `40`.

| Scenario | Base → candidate | jsoncheck | imginfo |
| --- | --- | --- | --- |
| Correct | `main` → `patch-correct` | `0` | `0` |
| Incomplete | `main` → `patch-incomplete` | `10` | `10` |
| Functional regression | `main` → `patch-regression` | `20` | `20` |
| New issue | `main` → `patch-newissue` | `10` | — |
| Mixed priority | `main` → `patch-mixed` | `10` | — |
| Fixed-base regression | `patch-correct` → `patch-regression` | `20` | `20` |
| No reproduced base issue | `patch-regression` → `patch-correct` | `40` | `40` |
| Broken build | `main` → `build-broken` | `30` | `30` |
| Invalid ref | `main` → `no-such-ref` | `30` | — |
| Hash-only comparison | Hashes of `main` → `patch-incomplete` | `10` | — |

Results are written to `reports/<target>/<scenario>/{report.json,report.md,console.log}` and `bundles/<target>/<scenario>/`. Rerunning a scenario replaces those generated directories. The matrix uses and updates the project's shared regression suites; run in a disposable checkout or container when you want to preserve the original suite metadata.

### Unseen-patch suite

```bash
python3 defense/run_unseen.py
python3 defense/run_unseen.py --only u03-alloc-off-by-one
python3 defense/run_unseen.py --fresh-regression
```

The suite applies additional patches to temporary target clones and evaluates them. It uses a temporary copy of the regression data unless `--fresh-regression` requests an initially empty suite. `--only` selects names containing the supplied substring.

| Fixture | Expected code | Purpose |
| --- | --- | --- |
| `u01-alt-correct-fix` | `0` | Alternative jsoncheck fix |
| `u02-uaf-in-main` | `10` | Use-after-free |
| `u03-alloc-off-by-one` | `10` | Allocation missing space for a terminator |
| `u04-null-deref` | `10` | Null-pointer access |
| `u05-output-format` | `20` | Changed successful-output contract |
| `u06-hang-on-whitespace` | `20` | Functional regression through a timeout |
| `u07-hardening-off` | `0` | Correct fix with hardening warnings |
| `u08-ignores-cflags` | `30` | Build system ignores requested instrumentation |
| `u09-memory-leak-only` | `0` | Leak detection is disabled in this project's scope |
| `v01-alt-correct-fix` | `0` | Alternative imginfo fix |
| `v02-div-by-zero` | `10` | Division by zero on a 1×1 image |
| `v03-forced-rgb` | `20` | Incorrect channel count for grayscale images |
| `v04-incomplete-threshold300` | `10` | A different incomplete Huffman-table bound |

Outputs are stored in `defense/results/<name>/`, with an aggregate `defense/results/summary.json`. These are runtime artifacts. They are not required as repository inputs. Expected results are defined in `defense/unseen/manifest.json`.

### Regenerating input fixtures

The repository already contains the input data. Regeneration is only needed when developing fixtures:

```bash
python3 targets/jsoncheck/tests/gen_tests.py
python3 targets/imginfo/tests/gen_tests.py
```

The image generator requires Pillow. Generators write fixture files and print reference values; review those values against each `config.json`. They do not automatically rewrite the target configuration. Image encoder differences can change generated JPEG bytes, so review fixture changes before adopting them.

## Evaluating an external patch

The helper accepts an email-format patch through `git am`, with a fallback to `git apply --index` for a raw diff:

```bash
python3 defense/run_unseen.py \
  --target jsoncheck \
  --base main \
  --patch /absolute/path/to/candidate.patch \
  --expect 0
```

Choose a base to which the patch applies. Additional unrecognized helper arguments are passed through to PatchProbe, for example `--jobs 1` or `--no-minimize`.

The helper prints the actual PatchProbe result and records it in the output JSON. **Its own exit code is an expectation-check result:** with `--expect`, a mismatch returns `1`; without `--expect`, a failed candidate can still leave the helper exiting `0`. Use an explicit expectation when calling this helper from CI. For an existing candidate revision in a persistent target repository, call `python3 -m patchprobe` directly to obtain the PatchProbe verdict as the process exit code.

## Adding a target

Create a target repository containing the base and candidate revisions, prepare independent reference inputs, and add a configuration under `targets/<name>/config.json`. The tool does not require changes to its Python modules for a compatible target.

This example describes a program that reads stdin and accepts `CFLAGS` through Make:

```json
{
  "target": "myparser",
  "repo": "targets/myparser/repo",
  "build": {
    "command": "make -C {src} myparser CFLAGS='{cflags}'",
    "binary": "myparser"
  },
  "input": {"method": "stdin"},
  "tests_dir": "targets/myparser/tests",
  "tests": {
    "valid": [
      {"name": "valid.input", "expect_exit": 0, "expect_stdout": "OK"}
    ],
    "boundary": [
      {"name": "empty.input", "expect_exit": 1}
    ],
    "invalid": [
      {"name": "reproducer.input", "expect_exit": 1}
    ]
  }
}
```

Create every referenced file before loading the configuration. Names must be unique across the three lists, all three lists must exist, and the total test set must be nonempty. Use `"method": "file"` when the binary takes one input filename argument. Arbitrary extra command-line arguments are not supported by the current input interface.

Relative repository and test-directory paths are resolved against the detected project root. Root discovery searches upward from the configuration for a directory containing `targets/` or `patchprobe/`. For configurations elsewhere, use absolute paths to avoid ambiguity.

### Build configuration

| Placeholder | Value |
| --- | --- |
| `{src}` | Exported source directory for this version/build mode |
| `{cflags}` | Selected compiler flags plus the file-prefix mapping; required in the command |
| `{mode}` | `release` or `sanitized` |
| `{out}` | Run work directory |

Substitution is textual and the build command executes through a shell. Quote paths where needed. The example assumes a Makefile that honors external `CFLAGS`; merely accepting a placeholder in JSON is insufficient if the Makefile discards the flags.

`build.binary` is the path to the executable relative to the exported source tree. `build.flags.release` and `build.flags.sanitized` can override defaults. Release flags must not contain `-fsanitize=`, and sanitized flags must contain it. Builds have a 600-second subprocess timeout.

### Runtime limits

An optional `limits` object overrides these defaults:

| Key | Default | Meaning |
| --- | --- | --- |
| `timeout_sec` | `5.0` | Wall-clock timeout per target invocation |
| `cpu_sec` | `10` | CPU soft limit in seconds; hard limit is one second higher |
| `rlimit_as_mb` | `512` | Normal-build address-space limit |
| `rlimit_as_mb_sanitized` | `0` | Instrumented-build address-space limit; zero disables this limit |
| `rlimit_fsize_mb` | `64` | Limit on files written by the target |
| `rlimit_nofile` | `64` | Open file-descriptor limit |
| `sanitizer_retries` | `12` | Maximum attempts when the runner detects a sanitizer startup failure |

ASan requires a large virtual address space for its shadow memory, so it has a separate address-space policy. The container memory limit supplies a distinct bound on actual container memory use. See [ASan's documented limitations](https://clang.llvm.org/docs/AddressSanitizer.html#limitations).

The runner sets `LC_ALL=C`, uses controlled ASan/UBSan options, and removes inherited sanitizer-option variables before applying its settings. Leak detection is disabled through `detect_leaks=0`; UBSan is configured to halt on the first error and print a stack trace.

### Distributing the target

After preparing and verifying a local target repository, package its refs into a bundle:

```bash
git -C targets/myparser/repo bundle create ../repo.bundle --all
git -C targets/myparser/repo bundle verify ../repo.bundle
```

`bash scripts/setup_targets.sh --pack` performs packaging for all restored target repositories. Use it deliberately when updating the supplied target artifacts. For the new target, run:

```bash
python3 -m patchprobe \
  --config targets/myparser/config.json \
  --base-ref vulnerable --patched-ref candidate
```

Provide at least one input that reproduces a confirmed issue in the base, plus valid and boundary inputs with independent behavioral expectations. Otherwise a clean-looking candidate can still produce `INCONCLUSIVE` because the base problem was never demonstrated.

## CI/CD

The repository includes two pipeline definitions:

- [GitHub Actions](.github/workflows/validate.yml): unit tests, a 14-case target/scenario matrix, generated artifacts, and an example release gate.
- [GitLab CI](.gitlab-ci.yml): unit tests, a release gate, expected-verdict jobs, and the full 16-case scenario script.

A release gate runs a candidate and allows continuation only on exit `0`. A test of the evaluator instead compares the returned code with the expected code for a known scenario. Keep these two uses distinct: an incomplete-fix fixture returning `10` is a successful evaluator test but a rejected release candidate.

For a direct release gate:

```bash
python3 -m patchprobe \
  --config targets/jsoncheck/config.json \
  --base-ref main --patched-ref patch-correct \
  --reports-dir reports/jsoncheck/ci-gate \
  --bundles-dir bundles/jsoncheck/ci-gate
```

Archive `reports/`, `bundles/`, and the resulting `regression/` data even when a candidate fails. The supplied workflows upload artifacts; they do not automatically persist newly learned regression entries into a future checkout. Reuse those entries through an explicit artifact or suite-maintenance process.

## Project structure

```text
patchprobe/
  __main__.py       Python module entry point
  cli.py            Evaluation orchestration and output assembly
  config.py         Configuration validation and target restoration
  gitops.py         Revision resolution, source export, and diff extraction
  builder.py        Separate builds, instrumentation checks, and hashes
  runner.py         Process execution, limits, and sanitizer retry handling
  evidence.py       Diagnostic parsing and finding signatures
  cparse.py         Lightweight source-function scanner
  correlate.py      Finding classification and patch correlation
  harden.py         ELF protection inspection
  minimize.py       Signature-preserving byte reduction
  repro.py          Stability replay and reproduction bundle generation
  regress.py        Persistent regression inputs and verification
  verdict.py        Decision priority and exit-code selection
  report.py         Markdown and console formatting
targets/
  jsoncheck/        Target bundle, configuration, and fixtures
  imginfo/          Target bundle, configuration, and fixtures
regression/        Stored regression suites and inputs
tests/             Automated tests
scenarios/         Standard scenario matrix runner
defense/
  run_unseen.py     External and unseen-patch evaluation helper
  unseen/          Additional patches and expected-result manifest
scripts/           Target repository setup and packaging
.github/workflows/ GitHub Actions pipeline
.gitlab-ci.yml     GitLab pipeline
Dockerfile         Validation image
docker-compose.yml Runtime isolation and default validation command
```

Generated reports, evidence bundles, unseen-patch results, restored target working repositories, and Python caches are excluded from version control. The regression fixtures are retained as reusable test inputs.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `No module named pytest` | Install pytest for the interpreter you are invoking. With distribution packages, try `/usr/bin/python3 -m pytest tests/ -q`. |
| `No module named patchprobe` | Run from the project root, with the `patchprobe/` directory visible to Python. |
| Missing target repository or unknown target ref | Run `bash scripts/setup_targets.sh`, then inspect branches in the configured target repository. |
| `BUILD_OR_CONFIG_ERROR` / code `30` | Inspect the console and JSON reasons for invalid configuration, unavailable tools, failed compilation, or instrumentation checks. |
| Sanitized build reported as uninstrumented | Ensure the Makefile honors `{cflags}` and links the sanitizer runtime into the final executable. |
| Repeated bare `AddressSanitizer:DEADLYSIGNAL` | The runner treats diagnostics without a detailed ASan/UBSan report as possible runtime startup failures and retries. Inspect the environment and toolchain if all attempts fail; this heuristic is not a confirmed target finding. |
| `INCONCLUSIVE` / code `40` | Read `verdict.reasons` and `anomalies`; check base reproduction, symbols, resource limits, replay stability, and regression provenance. |
| Hardening unit test fails on PIE | The test assumes a toolchain with default PIE. Use the supplied Debian container or inspect the local compiler defaults. |
| Expected `20` but received `10` | A security condition has higher priority. Check `verdict.flags` for simultaneous regression evidence. |
| Reports disappeared after a container run | Copy them out before removing the container; the default Compose service has no host output mounts. |
| Binary hash differs during reproduction | Compare compiler, linker, libraries, flags, and environment; the script warns and continues its replay checks. |
| Regression JSON changed after a run | Automatic updates are enabled by default. Use `--no-regression-add` or a copied suite. |
| Image generator cannot import `PIL` | Install Pillow in that interpreter's environment; it is not needed to use existing images. |

On some hosts, container packaging or security policy can prevent process execution. Inspect the Docker/host error and use a supported Docker Engine configuration; avoid broadly disabling host protections to make a test pass.

## Scope and limitations

- **Finite input coverage:** validation covers the configured cases and stored regression inputs. There is no coverage-guided fuzzer, symbolic execution engine, or proof of absence of bugs.
- **Observed identity:** signatures can merge distinct root causes or split one root cause after a function or diagnostic changes. Runtime evidence identifies an observed error category, not exploitability.
- **Heuristic source correlation:** the function scanner is not a complete C/C++ parser, and correlation uses function names and file basenames. Macros, complex formatting, or repeated names can reduce accuracy. Overlap alone is not a proof of causation.
- **Instrumentation scope:** only executed, instrumented paths can provide sanitizer evidence. Instrumentation checks establish the presence of runtime symbols, not comprehensive instrumentation of every linked component.
- **Functional scope:** the implementation detects base-pass/candidate-fail transitions. A test already failing its reference in the base does not by itself cause `FUNC_REGRESSION`. Stderr content is not a configured functional oracle.
- **Disabled leak detection:** a leak-only candidate can pass the configured checks. No ThreadSanitizer or MemorySanitizer analysis is configured.
- **Environment dependence:** compiler versions, runtime startup failures, platform defaults, and resource settings affect results. Reproduction hashes are most meaningful with the same toolchain and environment.
- **Reproducer differences:** generated shell scripts use simpler diagnostic matching and do not reproduce all runner limits. They require access to the recorded source revision.
- **Regression verification scope:** stored checks ask whether a particular signature is present; absence alone is weaker than a full successful execution. In particular, a timeout or unrelated failure during a suite-only input is not a proof of correctness. Inspect recorded outcomes along with the verdict.
- **Isolation scope:** process limits are not a security sandbox, and failure to apply an individual resource limit can be ignored by the runner. Build commands execute through a shell. Use container or VM isolation appropriate to the code being evaluated.

## Further reading

- [AddressSanitizer documentation](https://clang.llvm.org/docs/AddressSanitizer.html) — memory-error instrumentation and diagnostic behavior.
- [UndefinedBehaviorSanitizer documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) — available runtime checks and their scope.
- [Simplifying and Isolating Failure-Inducing Input](https://www.st.cs.uni-saarland.de/papers/tse2002/tse2002.pdf), Andreas Zeller and Ralf Hildebrandt — the delta-debugging approach behind input reduction.
