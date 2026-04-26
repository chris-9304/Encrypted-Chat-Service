# Dependencies

Cloak uses `vcpkg` for dependency management. No new dependency may be introduced without updating this list.

| Dependency              | Version   | Purpose                                        | Rationale |
|-------------------------|-----------|------------------------------------------------|-----------|
| `libsodium`             | latest    | Core cryptography (Ed25519, X25519, Poly1305)  | Vetted, secure default crypto primitives. |
| `boost-asio`            | latest    | Platform networking and async execution strand | High-performance, mature networking without bringing all of Boost. |
| `boost-program-options` | latest    | Command-line flags parsing                     | Standardized CLI arg parsing. |
| `protobuf`              | latest    | Wire and persistence schema encoding           | Efficient, versionable structuring. |
| `sqlite3`               | latest    | Encrypted-column persistence format            | Ubiquitous and highly resilient local DB. |
| `spdlog`                | latest    | Rotating logging                               | Fast C++ logging standard. |
| `fmt`                   | latest    | String formatting (underpins spdlog)           | Used across the stack for string manipulation. |
| `catch2`                | >= 3.0.0  | Unit/Property testing infrastructure           | Clean macros and property generation syntax. |
| `ftxui`                 | latest    | TUI graphics library                           | Functional, robust Windows terminal UI. |
| `wil`                   | latest    | Windows Implementation Libraries               | Safe wrappers around Win32 platform APIs. |
