# 0002: Windows Native MSVC Setup

**Status:** Accepted

## Context
EncryptiV needs a first-tier, low-friction integration with Windows platform specifics like Win32 mDNS (`DnsServiceRegister`) and high performance.

## Decision
Development, build, and CI strictly target native MSVC on Windows 10/11. We will NOT support POSIX, WSL shims, or MinGW. Tools such as Windows Implementation Libraries (`wil`) will be used to correctly interface with OS primitives.

## Consequences
- Clean consumption of native Windows APIs.
- Platform constraints isolate adoption strictly to Windows client machines.
- Relies heavily on vcpkg for cross-platform OSS dependencies on Windows.
