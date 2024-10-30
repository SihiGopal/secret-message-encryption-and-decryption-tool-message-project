import tkinter as tk
from tkinter import messagebox
try:
    from Crypto.Cipher import AES
    print("PyCryptodome imported successfully!")
except ImportError as e:
    print("Error:", e)



import base64


# Caesar Cipher Encryption
def caesar_encrypt(message, shift):
    return "".join(
        chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
        for char in message
    )


# Caesar Cipher Decryption
def caesar_decrypt(message, shift):
    return "".join(
        chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 - shift) % 26 + 97) if char.islower() else char
        for char in message
    )


# Vigenère Cipher Encryption
def vigenere_encrypt(message, keyword):
    keyword = keyword.lower()
    encrypted_text = []
    keyword_index = 0
    for char in message:
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)]) - 97
            if char.isupper():
                encrypted_text.append(chr((ord(char) - 65 + shift) % 26 + 65))
            else:
                encrypted_text.append(chr((ord(char) - 97 + shift) % 26 + 97))
            keyword_index += 1
        else:
            encrypted_text.append(char)
    return ''.join(encrypted_text)


# Vigenère Cipher Decryption
def vigenere_decrypt(message, keyword):
    keyword = keyword.lower()
    decrypted_text = []
    keyword_index = 0
    for char in message:
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)]) - 97
            if char.isupper():
                decrypted_text.append(chr((ord(char) - 65 - shift) % 26 + 65))
            else:
                decrypted_text.append(chr((ord(char) - 97 - shift) % 26 + 97))
            keyword_index += 1
        else:
            decrypted_text.append(char)
    return ''.join(decrypted_text)


# AES Encryption
def aes_encrypt(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt((message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct


# AES Decryption
def aes_decrypt(encrypted_message, key):
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    pt = (cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


# Tkinter GUI setup
root = tk.Tk()
root.title("Encryption Tool")

# Choose Algorithm
selected_algorithm = tk.StringVar(value="caesar")
tk.Label(root, text="Choose Algorithm:").grid(row=4, column=0)
tk.Radiobutton(root, text="Caesar Cipher", variable=selected_algorithm, value="caesar").grid(row=4, column=1)
tk.Radiobutton(root, text="Vigenère Cipher", variable=selected_algorithm, value="vigenere").grid(row=5, column=1)
tk.Radiobutton(root, text="AES", variable=selected_algorithm, value="aes").grid(row=6, column=1)

# Message and Key Entries
tk.Label(root, text="Enter Message:").grid(row=0, column=0)
entry_message = tk.Entry(root, width=40)
entry_message.grid(row=0, column=1)

tk.Label(root, text="Enter Shift/Keyword/Key:").grid(row=1, column=0)
entry_key = tk.Entry(root, width=40)
entry_key.grid(row=1, column=1)

tk.Label(root, text="Result:").grid(row=2, column=0)
entry_result = tk.Entry(root, width=40)
entry_result.grid(row=2, column=1)


# Encrypt and Decrypt Functions
def encrypt_message():
    message = entry_message.get()
    key = entry_key.get()

    if selected_algorithm.get() == "caesar":
        shift = int(key) if key.isdigit() else 0
        encrypted_text = caesar_encrypt(message, shift)
    elif selected_algorithm.get() == "vigenere":
        encrypted_text = vigenere_encrypt(message, key)
    elif selected_algorithm.get() == "aes":
        if len(key) != 16:
            messagebox.showerror("Error", "AES key must be 16 characters.")
            return
        encrypted_text = aes_encrypt(message, key)

    entry_result.delete(0, tk.END)
    entry_result.insert(0, encrypted_text)


def decrypt_message():
    message = entry_message.get()
    key = entry_key.get()

    if selected_algorithm.get() == "caesar":
        shift = int(key) if key.isdigit() else 0
        decrypted_text = caesar_decrypt(message, shift)
    elif selected_algorithm.get() == "vigenere":
        decrypted_text = vigenere_decrypt(message, key)
    elif selected_algorithm.get() == "aes":
        if len(key) != 16:
            messagebox.showerror("Error", "AES key must be 16 characters.")
            return
        decrypted_text = aes_decrypt(message, key)

    entry_result.delete(0, tk.END)
    entry_result.insert(0, decrypted_text)


# Encrypt and Decrypt Buttons
btn_encrypt = tk.Button(root, text="Encrypt", command=encrypt_message)
btn_encrypt.grid(row=3, column=0)

btn_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message)
btn_decrypt.grid(row=3, column=1)

# Run Tkinter loop
root.mainloop()
