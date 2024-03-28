import tkinter as tk
import tkinter.ttk as ttk
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CryptoApp:
    def __init__(self, key):
        self.key = key

    def encrypt_message(self, message):
        cipher = AES.new(self.key, AES.MODE_CBC)
        padded_message = pad(message.encode(), AES.block_size)
        ct_bytes = cipher.encrypt(padded_message)
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return iv, ct

    def decrypt_message(self, iv, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, base64.b64decode(iv))
        pt = cipher.decrypt(base64.b64decode(ciphertext))
        unpadded_pt = unpad(pt, AES.block_size)
        return unpadded_pt.decode('utf-8')

def main():
    root = tk.Tk()
    root.title("AES256 Encryption Decryption")

    key = get_random_bytes(32)  # AES256 key
    app = CryptoApp(key)

    message_label = ttk.Label(root, text="Message:")
    message_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
    message_entry = ttk.Entry(root, width=50)
    message_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)

    iv_label = ttk.Label(root, text="IV:")
    iv_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
    iv_entry = ttk.Entry(root, width=50)
    iv_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

    ciphertext_label = ttk.Label(root, text="Ciphertext:")
    ciphertext_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
    ciphertext_entry = ttk.Entry(root, width=50)
    ciphertext_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)

    def encrypt():
        message = message_entry.get()
        iv, ciphertext = app.encrypt_message(message)
        iv_entry.delete(0, tk.END)
        iv_entry.insert(0, iv)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)

    def decrypt():
        iv = iv_entry.get()
        ciphertext = ciphertext_entry.get()
        decrypted_message = app.decrypt_message(iv, ciphertext)
        message_entry.delete(0, tk.END)
        message_entry.insert(0, decrypted_message)

    encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt)
    encrypt_button.grid(row=3, column=1, padx=5, pady=5, sticky="e")

    decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt)
    decrypt_button.grid(row=3, column=2, padx=5, pady=5, sticky="w")

    root.mainloop()

if __name__ == "__main__":
    main()
