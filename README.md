# Cryptographic Library

**A modular cryptographic library featuring custom implementations of classic algorithms in Python.**  
[GitHub Repo](https://github.com/Stefan3002/Cryptographic-Library)

## 🔍 Overview

This library provides a Python-based educational toolkit for experimenting with fundamental cryptographic algorithms. It's designed to help learners and educators explore encryption concepts through readable and modifiable code.

---

## 🔐 Included Algorithms

- 🔁 **ChaCha20**
- 🔁 **Camellia**
- 🔐 **RSA Encryption**

---

## 🛠 Technologies Used

- Python 3.8+

---

## 🚀 Getting Started

### Requirements

- Python 3.8 or higher

### Installation

```bash
git clone https://github.com/Stefan3002/Cryptographic-Library.git
cd Cryptographic-Library
```

### Example Usage

```python
from rsa import RSA

rsa = RSA()
rsa.generate_keys()
ciphertext = rsa.encrypt("Hello world!")
plaintext = rsa.decrypt(ciphertext)
print(plaintext)  # Output: Hello world!
```

---


## 🎓 Educational Use

- Understand cryptographic processes in a lightweight codebase
- Use in coursework, labs, or personal study
- Easily modify to explore variations of algorithms

---

## 📄 License

MIT License.

---

## 📬 Contact

Author: [Ștefan Secrieru](https://stefansecrieru.com)  
GitHub: [@Stefan3002](https://github.com/Stefan3002)
