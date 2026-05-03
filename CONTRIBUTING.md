# Contributing

Welcome to Cloak! To maintain a high level of code quality and security assurance, observe these rules:

## Code rules

1. Follow `ARCHITECTURE.md` and `THREAT_MODEL.md` explicitly. Changes to cryptographic protocols require a new ADR in `docs/adr/`.
2. Build with `MSVC v143` and `/std:c++latest`. Do not introduce MinGW or Clang builds without discussion.
3. Do not suppress warnings. `/W4 /WX /permissive-` is enforced in CI.
4. Smart pointers and RAII only — no raw `new`/`delete` outside of safe abstractions.
5. All secrets must use `cloak::crypto::SecureBuffer<N>` and must **never** be logged. The `CLOAK_UNSAFE_LOG_SECRETS=1` guard exists for debugging only and must not appear in production paths.
6. All recoverable errors use `Result<T>` (`std::expected<T, Error>`). Do not throw exceptions for expected failure modes (network disconnect, bad key, corrupt frame).
7. No custom cryptographic primitives. All crypto goes through `cloak::crypto::Crypto` → libsodium.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(group): add kick command for group admin
fix(wire): validate ReceiptType enum before casting
docs(adr): add ADR-0007 for group forward secrecy
test(session): add out-of-order DR message test
```

## Documentation

- Update `ARCHITECTURE.md` if you add a new module, change the concurrency model, or modify the wire format.
- Update `ROADMAP.md` if you close a phase milestone or add a v1.0 production item.
- Update `report.md` if you add a significant new feature or protocol.
- Add a new ADR in `docs/adr/` for significant architectural decisions.

## Running tests

```powershell
ctest --preset debug --output-on-failure          # all tests
ctest --preset debug -R test_wire --output-on-failure  # single module
cmake --preset asan && cmake --build --preset asan
ctest --preset asan --output-on-failure           # with AddressSanitizer
```

## Security reports

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy. Do not file public issues for security vulnerabilities.
