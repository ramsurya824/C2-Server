# C2-server




## 🧠 Project Architecture


<img src="https://github.com/user-attachments/assets/ab272d6a-8a90-4332-b4a0-00748964a4d6" alt="Architecture" width="600"/>



The architecture of this Command and Control (C2) infrastructure is composed of three core components:

---

### 🦠 Malware Agent
- Lightweight payload executed on victim systems.
- Establishes outbound connection to the C2 Server.
- Waits for commands and executes them (shell, file ops, etc.).
- Sends results or data (e.g., screenshots, keylogs) back to the server.

---

### 🖥️ C2 Server (Listeners)
- Central communication hub.
- Listens for connections from multiple agents.
- Relays commands from the operator to agents.
- Logs and stores agent responses.
- Can handle multiple concurrent sessions.

---

### 🪟 C2 WPF Application (Operator Panel)
- Windows desktop GUI for attackers/operators.
- Features:
  - Agent session management
  - Real-time command and control
  - Logs and file transfer

---

    - **Bypassing Api hooking** - Callback-Based Evasion (stealthier than indirect system calls) - mainly to evade EDRs which uses userland hooking and ETW(Event Tracing Window)

### ShellcodeEncryption.cpp

- Uses XOR encryption algorithm to encrypt the shellcode.
