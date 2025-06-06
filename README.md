# C2-server




## 🧠 Project Architecture


<img src="https://github.com/user-attachments/assets/c507c7a8-1272-4723-a7b3-15a3bd908045" alt="Architecture" width="600"/>



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


