# 0001: OOP C++ Not C-ABI

**Status:** Accepted

## Context
When building native applications with future extensibility in mind, we must choose whether to expose C-like ABI module boundaries (opaque pointers + free functions) or use modern C++ Object-Oriented paradigms (abstract base classes, virtual methods, rule of zero). The project explicitly requires seams for future extensions like offline storage, relays, and multi-device support.

## Decision
We will use idiomatic modern C++ OOP. Subsystems are bounded by pure virtual abstract base classes (e.g., `Transport`, `DiscoveryService`) and concrete component integration (e.g., `ChatApplication`). Exceptions do not cross structural boundaries; use `std::expected` for recovery.

## Consequences
- Requires strict toolchain alignment (MSVC / C++23) making cross-compiler integration difficult.
- Affords type-safe compilation and easier polymorphism.
- Direct alignment with the design principle of native RAII resource management.
