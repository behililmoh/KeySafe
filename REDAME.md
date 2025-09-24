# KeySafe
# 🔐 SafePass — A Simple & Secure Password Manager (Python + Tkinter)

# 🔐 KeySafe — A Secure Password Manager (Python + Tkinter)

KeySafe is a lightweight and secure password manager built with **Python**, **Tkinter**, and **Cryptography (Fernet)**.  
It uses a **master password** for strong encryption and user authentication.

---

## 🚀 Features

- Store and manage encrypted passwords (AES/Fernet).
- Simple and user-friendly Tkinter GUI.
- Search accounts quickly by website name.
- Copy passwords to clipboard (requires `xclip` or `xsel` on Linux).
- Support for multiple accounts per website.
- Master password secured with **PBKDF2HMAC key derivation**.

---

## 📂 Project Structure

KeySafe/
├── passord_manager_gui_3.py # Main application (with master password)
├── requirements.txt # Python dependencies
├── README.md # Documentation
├── data/ # Encrypted data storage
└── scripts/ # Utility scripts

---

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/KeySafe.git
   cd KeySafe
     ```
2. Create and activate a virtual environment:
  ```bash
python3 -m venv .venv
source .venv/bin/activate
  ```
  

3. Install dependencies:
pip install -r requirements.txt

4. (Linux only) install Tkinter and clipboard support:
sudo apt-get install python3-tk xclip -y

▶️ Usage

Run the application
python passord_manager_gui_3.py
🛠 Possible Improvements

Secure export/import of stored data.

Auto-lock after inactivity.

Multi-user support.

Modern UI (e.g., ttkbootstrap).

📜 License

This project is licensed under the MIT License.
You are free to use, modify, and distribute it.
