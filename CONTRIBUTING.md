# Contributing

Welcome to Cloak! 
To maintain a high level of code assurance, observe these rules:

1. Follow `GEMINI.md`, `ARCHITECTURE.md`, and `THREAT_MODEL.md` explicitly.
2. Ensure you build using `MSVC v143` with `/std:c++latest`.
3. Do not suppress warnings; `/W4 /WX` is enforced.
4. Smart pointers and RAII wrappers only — raw memory management should only happen inside safe abstractions.
5. All secrets must use `cloak::SecureBuffer` and must *never* be logged.
6. Commit logically and use conventional commit messages.
