# AES-256 Password Encryptor

Cross-platform ready CLI utility for **Linux**.

Uses internationally recognized cryptographic standards:
- **AES-256-CBC**
- **PBKDF2-HMAC-SHA256**

## Modes
- **A** — Encrypt text with a password  
- **B** — Decrypt data with the same password  

Encryption generates and requires:
- Salt  
- IV  
- Ciphertext  

All values must be preserved to restore the original text.

Language: **C**  
Library: **OpenSSL**
