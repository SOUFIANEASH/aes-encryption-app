"""AES Encryption / Decryption - simple desktop app (Tkinter).

Run:  py aes_app.py      (needs:  py -m pip install pycryptodome)
"""
import base64
import hashlib
import os

from Crypto.Cipher import AES                 # the AES algorithm (library)
from Crypto.Util.Padding import pad, unpad    # padding for ECB / CBC


# ---------------------------------------------------------------- crypto part
def make_key(password, key_bits):
    """AES needs exactly 16 / 24 / 32 bytes.
    We hash the password with SHA-256 (32 bytes) and keep the first
    key_bits/8 bytes. Same password -> same key, always."""
    if password == "":
        raise ValueError("The secret key must not be empty.")
    return hashlib.sha256(password.encode("utf-8")).digest()[: key_bits // 8]


def encrypt(text, password, mode, key_bits):
    key = make_key(password, key_bits)
    data = text.encode("utf-8")
    if mode == "ECB":                                   # no IV
        iv = b""
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
    elif mode == "CBC":                                 # random IV + padding
        iv = os.urandom(16)
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    else:                                               # CFB: random IV, no padding
        iv = os.urandom(16)
        ciphertext = AES.new(key, AES.MODE_CFB, iv, segment_size=128).encrypt(data)
    # file content = Base64( IV + ciphertext )  -> plain text, fits in a .txt
    return base64.b64encode(iv + ciphertext).decode()


def decrypt(b64_text, password, mode, key_bits):
    key = make_key(password, key_bits)
    try:
        raw = base64.b64decode(b64_text.strip())
        if mode == "ECB":
            data = unpad(AES.new(key, AES.MODE_ECB).decrypt(raw), 16)
        elif mode == "CBC":
            iv, ct = raw[:16], raw[16:]
            data = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        else:
            iv, ct = raw[:16], raw[16:]
            data = AES.new(key, AES.MODE_CFB, iv, segment_size=128).decrypt(ct)
        return data.decode("utf-8")
    except Exception:
        raise ValueError("Decryption failed: wrong key, mode or key length, "
                         "or the file is not valid ciphertext.")


# ------------------------------------------------------------------ GUI part
def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    win = tk.Tk()
    win.title("AES Encryption / Decryption")

    operation = tk.StringVar(value="Encrypt")
    mode = tk.StringVar(value="CBC")
    bits = tk.StringVar(value="256")
    key = tk.StringVar()

    top = tk.Frame(win)
    top.pack(padx=10, pady=8, fill="x")
    tk.Label(top, text="Operation:").grid(row=0, column=0, sticky="w")
    tk.Radiobutton(top, text="Encrypt", variable=operation, value="Encrypt").grid(row=0, column=1)
    tk.Radiobutton(top, text="Decrypt", variable=operation, value="Decrypt").grid(row=0, column=2)
    tk.Label(top, text="Mode:").grid(row=1, column=0, sticky="w")
    ttk.Combobox(top, textvariable=mode, values=["ECB", "CBC", "CFB"],
                 state="readonly", width=8).grid(row=1, column=1)
    tk.Label(top, text="Key length (bits):").grid(row=2, column=0, sticky="w")
    ttk.Combobox(top, textvariable=bits, values=["128", "192", "256"],
                 state="readonly", width=8).grid(row=2, column=1)
    tk.Label(top, text="Secret key:").grid(row=3, column=0, sticky="w")
    tk.Entry(top, textvariable=key, show="*", width=30).grid(row=3, column=1, columnspan=2)

    tk.Label(win, text="Input (plaintext to encrypt, or ciphertext to decrypt):").pack(anchor="w", padx=10)
    input_box = tk.Text(win, height=7, width=70)
    input_box.pack(padx=10)
    tk.Label(win, text="Result:").pack(anchor="w", padx=10)
    output_box = tk.Text(win, height=7, width=70)
    output_box.pack(padx=10)

    def run():
        text = input_box.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Error", "Input is empty.")
            return
        try:
            if operation.get() == "Encrypt":
                result = encrypt(text, key.get(), mode.get(), int(bits.get()))
            else:
                result = decrypt(text, key.get(), mode.get(), int(bits.get()))
        except ValueError as err:
            messagebox.showerror("Error", str(err))
            return
        output_box.delete("1.0", "end")
        output_box.insert("1.0", result)

    def save_file():
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(output_box.get("1.0", "end").strip())

    def load_file():
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                input_box.delete("1.0", "end")
                input_box.insert("1.0", f.read())
            operation.set("Decrypt")

    buttons = tk.Frame(win)
    buttons.pack(pady=8)
    tk.Button(buttons, text="Run", width=12, command=run).pack(side="left", padx=4)
    tk.Button(buttons, text="Save result to .txt", command=save_file).pack(side="left", padx=4)
    tk.Button(buttons, text="Load .txt into input", command=load_file).pack(side="left", padx=4)

    win.mainloop()


if __name__ == "__main__":
    main()
