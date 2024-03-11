from tkinter import Tk, Label, Entry, Button, Frame, StringVar, Text
import random

# Diffie-Hellman key exchange functions
def generate_keys():
    global p, g, private_key, public_key
    p = 23  # prime number
    g = 5   # primitive root of p
    private_key = random.randint(1, p-1)
    public_key = (g ** private_key) % p

def calculate_shared_secret(partner_public_key):
    shared_secret = (partner_public_key ** private_key) % p
    return shared_secret

# Encryption and Decryption functions
def encrypt(message, shared_secret):
    encrypted_message = ""
    for char in message:
        encrypted_char = chr(ord(char) + shared_secret)
        encrypted_message += encrypted_char
    return encrypted_message

def decrypt(encrypted_message, shared_secret):
    decrypted_message = ""
    for char in encrypted_message:
        decrypted_char = chr(ord(char) - shared_secret)
        decrypted_message += decrypted_char
    return decrypted_message

# Event handlers for Encrypt and Decrypt buttons
def on_encrypt():
    partner_public_key = int(entry_partner_public_key.get())
    shared_secret = calculate_shared_secret(partner_public_key)
    message = entry_message.get()
    encrypted_message = encrypt(message, shared_secret)
    encrypted_text.delete(1.0, "end")
    encrypted_text.insert("end", encrypted_message)

def on_decrypt():
    partner_public_key = int(entry_partner_public_key.get())
    shared_secret = calculate_shared_secret(partner_public_key)
    encrypted_message = encrypted_text.get(1.0, "end-1c")
    decrypted_message = decrypt(encrypted_message, shared_secret)
    result.set("Decrypted Message: " + decrypted_message)

# GUI setup
root = Tk()
root.title("Diffie-Hellman Encryption/Decryption")
root.title("CSS_Project Using Diffie-Hellman Keys")
# root.title("By:- Abhilash Wasekar")
root.geometry("400x400")
root.configure(bg="#f0f0f0")

frame = Frame(root, bg="#ffffff", padx=10, pady=10)
frame.pack(padx=20, pady=20, fill="both", expand=True)


label_partner_public_key = Label(frame, text="Enter Partner's Public Key:", bg="#ffffff")
label_partner_public_key.grid(row=0, column=0, pady=10)
entry_partner_public_key = Entry(frame, width=30)
entry_partner_public_key.grid(row=0, column=1, pady=10)

label_message = Label(frame, text="Enter Message:", bg="#ffffff")
label_message.grid(row=1, column=0, pady=10)
entry_message = Entry(frame, width=30)
entry_message.grid(row=1, column=1, pady=10)

encrypt_button = Button(frame, text="Encrypt", command=on_encrypt, bg="#4caf50", fg="white")
encrypt_button.grid(row=2, column=0, pady=10, columnspan=2, sticky="ew")

encrypted_text = Text(frame, height=5, width=40)
encrypted_text.grid(row=3, column=0, columnspan=2, pady=10)

decrypt_button = Button(frame, text="Decrypt", command=on_decrypt, bg="#f44336", fg="white")
decrypt_button.grid(row=4, column=0, pady=10, columnspan=2, sticky="ew")

result = StringVar()
result.set("")
result_label = Label(frame, textvariable=result, bg="#ffffff", wraplength=350)
result_label.grid(row=5, column=0, columnspan=2, pady=10)

# Generate Diffie-Hellman keys
generate_keys()

root.mainloop()
