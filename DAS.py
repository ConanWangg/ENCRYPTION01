import random
import tkinter as tk
from tkinter import messagebox

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        messagebox.showerror("Error", "Both numbers must be prime.")
        return
    elif p == q:
        messagebox.showerror("Error", "p and q cannot be equal")
        return

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    cipher_text = [pow(ord(char), e, n) for char in plaintext]
    return cipher_text

def decrypt(private_key, cipher_text):
    d, n = private_key
    plain_text = [chr(pow(char, d, n)) for char in cipher_text]
    return ''.join(plain_text)

def encrypt_decrypt():
    p = int(entry_p.get())
    q = int(entry_q.get())

    public_key, private_key = generate_keypair(p, q)
    if public_key and private_key:
        messagebox.showinfo("RSA Keys Generated", f"Public Key: {public_key}\nPrivate Key: {private_key}")

        message = entry_message.get()
        encrypted_message = encrypt(public_key, message)
        messagebox.showinfo("Encrypted Message", f"Encrypted message: {encrypted_message}")

        decrypted_message = decrypt(private_key, encrypted_message)
        messagebox.showinfo("Decrypted Message", f"Decrypted message: {decrypted_message}")

# GUI
root = tk.Tk()
root.title("RSA Encryption/Decryption")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

label_p = tk.Label(frame, text="Enter a prime number (p):")
label_p.grid(row=0, column=0, sticky="w")
entry_p = tk.Entry(frame)
entry_p.grid(row=0, column=1)

label_q = tk.Label(frame, text="Enter another prime number (q):")
label_q.grid(row=1, column=0, sticky="w")
entry_q = tk.Entry(frame)
entry_q.grid(row=1, column=1)

label_message = tk.Label(frame, text="Enter the message to encrypt:")
label_message.grid(row=2, column=0, sticky="w")
entry_message = tk.Entry(frame)
entry_message.grid(row=2, column=1)

encrypt_button = tk.Button(frame, text="Encrypt/Decrypt", command=encrypt_decrypt)
encrypt_button.grid(row=3, columnspan=2)

root.mainloop()
