# Gemini Antigravity — Execution Prompt

Copy the block below into a fresh Gemini Antigravity session. Make sure the four docs (`GEMINI.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ROADMAP.md`) and `WINDOWS_BUILD.md` are committed at the repo root before starting.

---

## Prompt to paste into Gemini Antigravity

> You are operating in **Cloak**, a Windows-native C++ encrypted-messenger project. Read these files in full before writing anything. They are the source of truth:
>
> 1. `GEMINI.md`
> 2. `ARCHITECTURE.md`
> 3. `THREAT_MODEL.md`
> 4. `ROADMAP.md`
> 5. `WINDOWS_BUILD.md`
>
> If a requirement in this prompt conflicts with those documents, STOP and ask. The documents win.
>
> ## Your task
>
> Execute milestone **M1.1 — Scaffold & core types** from `ROADMAP.md`. The goal is a green-CI Windows-native repository with the full class skeleton in place and no business logic. After M1.1, the next milestone (M1.2: Crypto facade) must be able to start without any further scaffolding.
>
> ## Deliverables
>
> 1. **Top-level build system.**
>    - `CMakeLists.txt` at repo root, CMake ≥ 3.25.
>    - `CMakePresets.json` exposing: `debug`, `release`, `asan`, `analyze`.
>    - Generator: Ninja.
>    - Compiler requirement: MSVC v143. Fatal error if compiler is not MSVC on Windows — with a message pointing to `WINDOWS_BUILD.md`.
>    - C++ standard: `/std:c++latest`.
>
> 2. **Shared CMake modules under `cmake/`:**
>    - `warnings.cmake` — function `cloak_target_warnings(tgt)` applying `/W4 /WX /permissive- /Zc:__cplusplus /Zc:preprocessor`. Apply to every `ev_*` library.
>    - `msvc_options.cmake` — shared MSVC options (UTF-8 source `/utf-8`, conformance mode, etc.).
>    - `cloak_add_library.cmake` — function `cloak_add_library(NAME ... SOURCES ... HEADERS ... DEPS ...)` that creates a static lib target `ev_<name>` aliased as `cloak::<name>`, applies warnings, applies msvc_options, sets include dirs, links deps, and optionally wires a `tests/` subdirectory.
>
> 3. **vcpkg manifest.**
>    - `vcpkg.json` with Phase 1 dependencies: `libsodium`, `boost-asio`, `boost-program-options`, `protobuf`, `sqlite3`, `spdlog`, `fmt`, `catch2`, `ftxui`, `wil`.
>    - `vcpkg-configuration.json` with a pinned baseline SHA. After you create it, STOP and ask the user to run `vcpkg x-update-baseline --add-initial-baseline` locally and commit the result before CI will work.
>
> 4. **Class skeletons for every class in `ARCHITECTURE.md`.**
>
>    For each subsystem in `src/` (`core`, `crypto`, `identity`, `wire`, `discovery`, `transport`, `session`, `store`, `ui`, `app`):
>
>    - Header in `src/<sub>/<classname>.h` with `#pragma once`, namespace `cloak::<sub>`, full class declaration including all public methods from ARCHITECTURE.md, private members as `TODO` comments, move-only or copyable discipline correct, virtual methods where applicable.
>    - Source in `src/<sub>/<classname>.cpp` with method bodies that return `Error{ErrorCode::NotImplemented, "M1.1 skeleton"}` or equivalent. No real logic.
>    - `src/<sub>/CMakeLists.txt` using `cloak_add_library`.
>    - `tests/unit/<sub>/test_<classname>.cpp` with a Catch2 `TEST_CASE` that only verifies linkage (`SUCCEED("M1.1 skeleton")`). Real tests arrive with the implementing milestone.
>
>    The `core` subsystem includes: `Error`, `ErrorCode` enum, `Result<T>` alias for `std::expected<T, Error>`, `PeerId`, `SessionId`, `MessageId`, `PublicKey`, `Nonce`, `Signature`, `SafetyNumber`, `Timestamp`, `Endpoint`, `Path`.
>
>    The `crypto` subsystem includes: `Crypto` (static facade), `SecureBuffer`, `KeyPair`, `SharedSecret`, `AeadCiphertext`.
>
>    Abstract base classes (`Transport`, `DiscoveryService`) have all virtual methods declared with `= 0` and a virtual destructor.
>
> 5. **Application skeletons.**
>    - `src/app/main.cpp` with a `main()` that prints the version `cloak 0.1.0 (M1.1 skeleton)` and exits.
>    - `src/app/ChatApplication.{h,cpp}` with constructor/destructor stubs.
>
> 6. **Protobuf placeholder.** `proto/.gitkeep`. Do NOT write schemas yet — that's M1.4.
>
> 7. **Installer placeholder.** `installer/README.md` noting the WiX project arrives in M1.11. Do NOT write the `.wxs` yet.
>
> 8. **Code-quality config at repo root:**
>    - `.clang-format` — LLVM base, 100-column limit, 4-space indent, pointer-left, always-brace single statements, include-blocks regrouped.
>    - `.clang-tidy` — enable `bugprone-*`, `cert-*`, `cppcoreguidelines-*`, `modernize-*`, `performance-*`, `readability-*`. WarningsAsErrors on `bugprone-exception-escape`, all `cert-*`, `bugprone-unchecked-optional-access`. Disable `modernize-use-trailing-return-type`, `readability-magic-numbers`, `cppcoreguidelines-avoid-magic-numbers`, `fuchsia-*`, `google-*`, `llvm-*`, `altera-*`, `abseil-*`.
>    - `.editorconfig` — LF line endings, 4-space indent, utf-8, trim trailing whitespace.
>    - `.gitignore` — CMake build dirs, vcpkg artifacts, `compile_commands.json`, `.clangd/`, `.vs/`, `.vscode/` user settings, `.idea/`, `*.user`, `*.suo`, `CMakeUserPresets.json`, sanitizer logs.
>    - `.gitattributes` — `* text=auto eol=lf`, explicit `*.h *.cpp *.cmake *.md *.json text eol=lf`, `*.sln *.vcxproj text eol=crlf`, `*.wxs text eol=lf`.
>
> 9. **GitHub Actions CI** under `.github/workflows/`:
>    - `ci.yml` — matrix: `windows-latest` × `[debug, release]`. Steps: checkout, setup vcpkg with binary caching keyed on `vcpkg.json` + baseline SHA, configure with chosen preset, build, run tests.
>    - `asan.yml` — `windows-latest`, `asan` preset, run tests under ASan. Separate job because ASan slows things down.
>    - `analyze.yml` — `windows-latest`, runs MSVC `/analyze` and fails on analyzer warnings.
>    - `lint.yml` — clang-format dry-run check across all source files. Install LLVM via Chocolatey.
>
>    All jobs use `windows-latest`. Cache vcpkg's binary cache between runs.
>
> 10. **Repo docs** (in addition to the four source-of-truth files, which already exist):
>     - `README.md` — one-screen overview; pointer to the four docs and `WINDOWS_BUILD.md`; quickstart.
>     - `SECURITY.md` — disclosure placeholder, contact `SECURITY-CONTACT-TBD`, the explicit-non-claims list from `THREAT_MODEL.md`.
>     - `DEPENDENCIES.md` — table of every dep in `vcpkg.json` with version, license, purpose, and rationale for inclusion.
>     - `CONTRIBUTING.md` — workflow; PR conventions; the "things you must NOT do" list from `GEMINI.md`.
>
> 11. **ADRs.** Under `docs/adr/`:
>     - `README.md` — explains the Nygard format, lists the ADRs below.
>     - `0001-oop-cpp-not-c-abi.md` — why this project uses idiomatic C++ OOP rather than the C-ABI-for-Rust-portability approach from the archived v1 docs.
>     - `0002-windows-native-msvc.md` — why MSVC 2022 native, not WSL, not MinGW.
>     - `0003-noise-xx-for-phase-1.md` — why Noise XX over Signal's X3DH+Double-Ratchet for Phase 1, with upgrade path in Phase 2.
>     - `0004-sqlite-column-aead-over-sqlcipher.md` — why SQLite + libsodium column AEAD rather than SQLCipher (Windows packaging + dependency reduction).
>     - `0005-mdns-for-discovery.md` — why mDNS/DNS-SD via Win32 `DnsServiceRegister`.
>
>     Use Nygard format: Title, Status, Context, Decision, Consequences, Related.
>
> 12. **Archive old docs.** If `ARCHITECTURE.md`, `CLAUDE.md`, `ROADMAP.md`, `THREAT_MODEL.md`, or any `docs/adr/0001-c-abi-boundaries.md` / `0002-no-exceptions-across-modules.md` exist from the previous planning, move them into `docs/archive/v1-signal-inspired/` preserving their names. Do NOT delete them. They are history.
>
> ## Constraints
>
> - NO business logic. Every method returns `Error{ErrorCode::NotImplemented, ...}` or a safe sentinel.
> - NO dependencies beyond the list in item 3. If you think one is needed, STOP and ask.
> - NO Phase 2+ classes. Only classes listed in `ARCHITECTURE.md` for Phase 1.
> - NO protobuf schemas, no WiX files — those are later milestones.
> - KEEP each commit focused — one logical change per commit. Conventional commit messages: `scope: imperative description`.
>
> ## Success criteria for M1.1
>
> All must pass locally on Windows and in CI:
>
> - `cmake --preset debug` configures cleanly.
> - `cmake --build --preset debug` succeeds with MSVC v143.
> - `cmake --build --preset release` succeeds.
> - `cmake --build --preset asan` succeeds and tests run clean under ASan.
> - `ctest --preset debug --output-on-failure` passes (all placeholder tests).
> - `cmake --build --preset analyze` passes with zero MSVC analyzer warnings.
> - `clang-format --dry-run --Werror` passes on every source file.
> - All four CI workflows green on the first PR.
> - The repo tree matches `ARCHITECTURE.md` §"Repo layout".
>
> ## Workflow — follow this exactly
>
> 1. **Confirm.** Read the five source-of-truth docs. Summarize in 6–10 bullets the constraints most relevant to M1.1. STOP and wait for approval.
> 2. **Plan.** After approval, produce a complete file-by-file plan — every file you will create, one sentence each. Group them into logical commits. STOP and wait for approval of the plan.
> 3. **Execute.** Create files commit by commit. **After every 3 commits, STOP** and report: what landed, CI status, what's next. Wait for approval before continuing.
> 4. **Baseline-SHA gate.** After the vcpkg commit, STOP until the user confirms they've run `vcpkg x-update-baseline` and committed the baseline.
> 5. **Verify.** When the last commit lands, run the success-criteria checks and produce a handoff report. Include a list of every `TODO` / `NotImplemented` left for later milestones.
>
> If at any point a requirement conflicts with the five source-of-truth docs — STOP and ask. Those docs win.

---

## When your Claude limit resets — review prompt

Paste this into a fresh Claude session once your usage resets and Gemini has landed some work:

> I've been running Gemini Antigravity on the Cloak C++ encrypted-messenger project while my Claude limit was exhausted. Gemini has executed milestone M1.1 (scaffold). I want you to do a thorough review before M1.2 begins.
>
> Please read, in this order:
>
> 1. `GEMINI.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ROADMAP.md`, `WINDOWS_BUILD.md` — source of truth.
> 2. The ADRs under `docs/adr/` — especially 0001 (OOP, not C ABI) and 0003 (Noise XX).
> 3. The scaffold Gemini produced — `CMakeLists.txt`, `CMakePresets.json`, `vcpkg.json`, the cmake modules, and every `src/<sub>/` directory.
>
> Then produce:
>
> 1. **A drift report.** Every place where Gemini's scaffold diverges from the architecture docs, with severity (major/minor/cosmetic). Include anything Gemini silently deviated from, added beyond the brief, or omitted.
> 2. **A readiness check for M1.2 (Crypto facade).** Given what landed, what's blocking `src/crypto/Crypto.{h,cpp}` from being implemented cleanly? Specifically check: is `SecureBuffer` API good enough, does the Error type support the crypto error cases, are the Catch2 test harnesses wired to compile real tests.
> 3. **A list of ADR gaps.** Decisions Gemini made that should have been ADRs but weren't, and decisions we made without recording them.
> 4. **The M1.2 handoff prompt.** A prompt for Gemini (or me) to execute M1.2 with the same plan-first-then-checkpoint workflow. Use `ultrathink` level reasoning for this prompt — the Crypto facade is security-critical and its interface shapes all later crypto code.
>
> Use `ultrathink`. Be direct about problems; don't soften.
