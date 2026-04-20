# Running the Demo

The `ev-chat` architecture has been streamlined into a quick, localized REPL mimicking end-to-end authenticated encryption via simulated console loops.

### Step 1: Environment Validations
Ensure your Visual Studio 2022 / VCPKG configurations reside inside the project tree. 

Load up your VS Developer Command prompts to sync paths correctly, and execute:
```powershell
cmake --preset debug
cmake --build --preset debug
```

### Step 2: Establish "Bob" locally
Find a terminal (or split the screen natively in Windows Terminal) and spawn "Bob" acting as the passive listener on port `13370`:

```powershell
./out/build/debug/src/app/ev-chat.exe --name Bob --port 13370
```
*Bob generates ephemeral X25519 configurations safely into memory.*

### Step 3: Establish "Alice"
Open a secondary terminal targeting local host delivery.

```powershell
./out/build/debug/src/app/ev-chat.exe --name Alice --connect 127.0.0.1:13370
```
*Alice instantly negotiates Identity fingerprints over TCP boundaries seamlessly tying HKDF keys logically over identical boundaries.*

### Step 4: Interact!
Once the terminals show `[System] Accepted connection from` or `[System] Connected to`, type directly into the terminal. Each payload will process through AEAD encryptions and deliver exactly verified across the wire length. 

Exit cleanly by pressing `Ctrl-C` enforcing correct RAII teardowns!
