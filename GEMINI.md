# GEMINI.md

This file is read by Gemini (Antigravity) at session start. It encodes the non-negotiable rules and conventions of this codebase. Read it fully, then read `ARCHITECTURE.md`, `THREAT_MODEL.md`, and `ROADMAP.md` before making non-trivial changes.

## Project

**Cloak** — a Windows-native, terminal-based, end-to-end encrypted peer-to-peer LAN messenger in modern C++. Phase 1 delivers working LAN text chat between two installed instances and builds the foundation for later files, groups, multi-device, and optional cross-network transports.

## Platform

- Target: Windows 10 version 1903 or later, x64.
- Compiler: MSVC 2022 (v143 toolset).
- Build: CMake ≥ 3.25 + Ninja. vcpkg manifest mode.
- No WSL, no MinGW, no cross-compilation. MSVC native.
- Developer environment: Windows 10/11 with Visual Studio 2022 or Build Tools + VS Code.

## Language

- **C++23.** `/std:c++latest` on MSVC. `std::expected`, designated initializers, ranges, `std::format` / `std::print` where it improves readability.
- **Idiomatic modern OOP.** Real class hierarchies. Abstract base classes with virtual dispatch where Phase 2+ will add implementations. Concrete classes with hidden state. RAII everywhere.
- No `using namespace std;` at any scope. No `#define` for constants (use `constexpr`). No raw `new`/`delete`.
- `std::unique_ptr` for exclusive ownership. `std::shared_ptr` only where lifetime is genuinely shared. Prefer values and moves.

## Current phase

Phase 1 — see `ROADMAP.md` for milestone breakdown. Build the Phase 1 features AND the extension seams for Phase 2–3. Do not implement Phase 2+ features; do build the abstract base classes and plug points they will use.

## Non-negotiables

1. **No custom cryptographic primitives.** libsodium only. If a primitive isn't in libsodium, stop and ask.
2. **No raw `new` / `delete`.** Smart pointers or RAII wrappers only.
3. **Every key buffer is `cloak::SecureBuffer`.** mlocked, zeroed, move-only.
4. **No secret material is ever logged.** Use `log_sensitive(...)`. CI lint enforces.
5. **Every parser has a libFuzzer harness.** Protobuf decoders, framing, Noise message parsing, any config/TOML.
6. **Warnings are errors.** `/W4 /WX /permissive-`. Fix; never suppress.
7. **Every public class has unit tests.** Property tests for protocol classes.
8. **No new dependencies without a PR updating `DEPENDENCIES.md`.**
9. **Every commit builds clean in CI**, including the `asan` preset where supported.
10. **Error handling is `std::expected<T, Error>`.** Exceptions only for genuinely exceptional cases.
11. **Windows-native only.** No POSIX-only APIs. No `prctl`, no `mlockall`. Win32 equivalents (`VirtualLock`, `DnsServiceRegister`, etc.) where needed.
12. **Constant-time comparisons for all secret material.** `Crypto::constant_time_equal` — never `memcmp`.

## Repo layout

```
GEMINI.md                    ARCHITECTURE.md    ROADMAP.md
THREAT_MODEL.md              WINDOWS_BUILD.md   CMakeLists.txt
CMakePresets.json            vcpkg.json         vcpkg-configuration.json
.clang-format  .clang-tidy   .editorconfig      .gitignore
cmake/                       docs/adr/          docs/archive/
src/{core,crypto,identity,wire,discovery,transport,session,store,ui,app}/
include/cloak/
tests/{unit,integration,fuzz,vectors}/
proto/   installer/   .github/workflows/
```

## Coding conventions

- **Formatter.** `.clang-format` (LLVM base; 100-col; 4-space indent; pointer-left; always-brace). Run on every changed file.
- **Linter.** `.clang-tidy` with `bugprone-*`, `cert-*`, `cppcoreguidelines-*`, `modernize-*`, `performance-*`, `readability-*`, plus `security-*`. `bugprone-exception-escape` and `cert-*` are errors.
- **Naming.**
  - Types: `PascalCase` (`Session`, `PeerDirectory`).
  - Functions and variables: `snake_case` (`perform_handshake`, `peer_id`).
  - Constants and enumerators: `kCamelCase` (`kMaxMessageSize`).
  - Private members: trailing underscore (`identity_`, `transport_`).
  - Namespaces: `snake_case` (`cloak::crypto`, `cloak::transport`).
- Headers: `#pragma once`. Include what you use. System headers with `<...>`, project headers with `"..."`.
- One class per header/source pair. Small focused classes; split aggressively.

## Class-design rules

- **Abstract base classes** for extension points (`Transport`, `DiscoveryService`, `Session` serializer). Pure virtual methods. Virtual destructor. Non-copyable, non-movable unless explicit.
- **Concrete classes** are either values (copyable, movable — e.g. `PeerRecord`, `Message`) or resources (move-only, RAII — e.g. `Session`, `MessageStore`).
- **No inheritance for code reuse.** Composition instead. Inheritance expresses "is-a" only.
- **Rule of zero** by default. Define special members only when ownership is non-trivial.
- **Constructors do not throw** where preventable; prefer static factories returning `std::expected<T, Error>` for fallible construction.

## Error handling

- `std::expected<T, Error>` at every class boundary.
- `Error` struct: `{ErrorCode code; std::string message; std::optional<std::unique_ptr<Error>> cause;}`.
- `ErrorCode` is a single `enum class` in `core/error.h`. Add codes as needed; do not fragment into per-module enums.
- No exception may cross a class public interface. An exception inside an implementation detail that leaks out is a bug.

## Testing

- **Framework.** Catch2 v3.
- **Structure.** `tests/unit/<module>/test_<thing>.cpp`. One test binary per module.
- **RFC vectors** in `tests/vectors/` loaded at test runtime.
- **Property tests** use Catch2's generators; seeds logged on failure.
- **Integration** spins up two `ChatApplication` instances in one process with a fake `DiscoveryService` and exercises the full path.
- **Fuzz.** libFuzzer harnesses in `tests/fuzz/`, corpora in `tests/fuzz/corpus/<target>/`.

## CI

GitHub Actions on `windows-latest`. Every PR must pass:

- Build: MSVC Debug + Release.
- Tests: unit + integration.
- ASan build (`asan` preset) + tests under ASan.
- `/analyze` (MSVC static analyzer).
- clang-format dry-run check.
- Fuzz smoke: each target 60s on seed corpus.
- Coverage threshold check where configured.

## Workflow expectations

- Small PRs. One class or one concern at a time.
- Conventional commits: `scope: imperative description` (e.g. `session: implement Noise XX responder`).
- For new features, write the integration test first, then fill in classes until it passes.
- PRs touching `crypto/`, `identity/`, or `session/` include `[crypto]` in the title and expect extra review.
- Ambiguity material to security → STOP and ask. Do not guess.

## Things you must NOT do

- Add a dependency not listed in `DEPENDENCIES.md`.
- Use `std::string` to hold secret data (use `SecureBuffer`).
- Use `memcmp` on secret data (use `Crypto::constant_time_equal`).
- Skip tests because "it's obviously correct" — especially for crypto.
- Add a public virtual method just for testing; refactor or use dependency injection.
- Silently accept protocol errors; every branch either recovers explicitly or returns an error.
- Leak platform details across `src/` subsystem boundaries; Win32 specifics live in a clearly-named `.cpp` (e.g. `mdns_discovery_win32.cpp`).
- Modify `docs/archive/v1-signal-inspired/` — that's history.

## Plan-first workflow

Before executing a multi-file task:

1. Read GEMINI.md, ARCHITECTURE.md, THREAT_MODEL.md, and the current `ROADMAP.md` milestone.
2. Produce a plan listing every file you will create or modify, with one sentence per file explaining its purpose.
3. Wait for approval.
4. Execute in commit-sized chunks. After every 3 commits, STOP, report status, and wait.
5. At the end, run the milestone's verification checklist and report pass/fail.

## When in doubt

1. Re-read `THREAT_MODEL.md` and `ARCHITECTURE.md`.
2. Check `docs/adr/` for a decision record.
3. If still unclear, ask — and propose the question as a new ADR.
