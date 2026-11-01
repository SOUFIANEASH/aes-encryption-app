# AES Encryption & Decryption (Tkinter desktop app)

Encrypt and decrypt text with AES. Choose the mode (ECB / CBC / CFB) and the key length (128 / 192 / 256 bits). The ciphertext can be saved to a `.txt` file and loaded back for decryption.

## Run

```
py -m pip install pycryptodome
py aes_app.py
```

## How to use

1. Choose **Encrypt** or **Decrypt**, a **mode** and a **key length**.
2. Type the **secret key** (it cannot be empty).
3. Encrypt: type the text in the input box, click **Run**, then **Save result to .txt**.
   Decrypt: click **Load .txt into input**, enter the same key, mode and key length, click **Run**.

## Key handling

AES needs a key of exactly 16, 24 or 32 bytes. The password is hashed with SHA-256 (32 bytes) and the first 16, 24 or 32 bytes are used, depending on the selected key length. The same password always gives the same key.

## File format

One line of Base64 text: `IV + ciphertext` (ECB has no IV). Use the same mode and key length when decrypting.

## What is AES?

AES is a symmetric block cipher: the same key encrypts and decrypts. It works on 128-bit (16-byte) blocks, and each block goes through several rounds of substitution, shifting, mixing and key addition. The number of rounds depends on the key size:

| Variant | Key | Rounds |
|---|---|---|
| AES-128 | 128 bits | 10 |
| AES-192 | 192 bits | 12 |
| AES-256 | 256 bits | 14 |

A longer key means more possible keys (2^128, 2^192, 2^256), so it is harder to break, at a small speed cost.

## Modes

- **ECB**: each block is encrypted separately. Identical blocks give identical output, so patterns leak. No IV. Weak.
- **CBC**: each block is XORed with the previous ciphertext block before encryption; the first uses a random IV. Needs padding.
- **CFB**: encrypts the previous ciphertext block and XORs it with the plaintext (stream-like). Random IV, no padding.

The IV is a random value stored in the file so that the same text encrypts differently each time.

## Note

The AES algorithm comes from the pycryptodome library. This project only handles the key, modes, IV, padding, files and the window. A real system would also use a salted password hash (like PBKDF2) and an authenticated mode such as AES-GCM.
