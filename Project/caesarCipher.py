import customtkinter as ctk
import math
import random
import json

# Initialize the application
app = ctk.CTk()
app.geometry("600x650")  # Increased window height to accommodate the new label
app.title("Encryption & Decryption App")

# Set theme
ctk.set_appearance_mode("light")  # Options: "dark", "light"
ctk.set_default_color_theme("blue")

# Global Variables
current_mode = ctk.StringVar(value="RSA")

# Function to update the interface based on selected mode
def update_mode():
    mode = current_mode.get()
    if mode == "RSA":
        rsa_frame.pack(fill="both", expand=True, pady=20)
        caesar_frame.pack_forget()
    else:
        caesar_frame.pack(fill="both", expand=True, pady=20)
        rsa_frame.pack_forget()

# ----- Header Section -----
header_label = ctk.CTkLabel(app, text="Encryption & Decryption Tool", font=("Helvetica", 28, "bold"))
header_label.pack(pady=20)

# ----- Radio Buttons for Mode Selection -----
mode_frame = ctk.CTkFrame(app)
mode_frame.pack(fill="x", pady=10)

mode_label = ctk.CTkLabel(mode_frame, text="Select Encryption Mode:", font=("Helvetica", 16))
mode_label.pack(pady=10, anchor="center")

radio_rsa = ctk.CTkRadioButton(
    mode_frame, text="RSA Encryption", variable=current_mode, value="RSA", command=update_mode
)
radio_rsa.pack(side="left", padx=50)

radio_caesar = ctk.CTkRadioButton(
    mode_frame, text="Caesar Cipher", variable=current_mode, value="Caesar", command=update_mode
)
radio_caesar.pack(side="left", padx=50)

# ----- RSA Frame -----
rsa_frame = ctk.CTkFrame(app)

rsa_label = ctk.CTkLabel(rsa_frame, text="RSA Encryption", font=("Helvetica", 24))
rsa_label.pack(pady=10)

rsa_input_label = ctk.CTkLabel(rsa_frame, text="Enter Plain Text:", font=("Helvetica", 14))
rsa_input_label.pack(pady=5)
rsa_input_entry = ctk.CTkEntry(rsa_frame, width=400)
rsa_input_entry.pack(pady=5)

public_key_label = ctk.CTkLabel(rsa_frame, text="Public Key: ", font=("Helvetica", 14))
public_key_label.pack(pady=5)

private_key_label = ctk.CTkLabel(rsa_frame, text="Private Key: ", font=("Helvetica", 14))
private_key_label.pack(pady=5)

encrypt_button = ctk.CTkButton(rsa_frame, text="Encrypt", command=lambda: encrypt_rsa(), width=200)
encrypt_button.pack(pady=15)

encrypted_text_label = ctk.CTkLabel(rsa_frame, text="Encrypted Text: ", font=("Helvetica", 14))
encrypted_text_label.pack(pady=5)

decrypted_text_label = ctk.CTkLabel(rsa_frame, text="Decrypted Text: ", font=("Helvetica", 14))
decrypted_text_label.pack(pady=5)  # Added this line for RSA decryption

decrypt_button_rsa = ctk.CTkButton(rsa_frame, text="Decrypt", command=lambda: decrypt_rsa(), width=200)
decrypt_button_rsa.pack(pady=15)

# ----- Caesar Cipher Frame -----
caesar_frame = ctk.CTkFrame(app)

caesar_label = ctk.CTkLabel(caesar_frame, text="Caesar Cipher Encryption", font=("Helvetica", 24))
caesar_label.pack(pady=10)

shift_label = ctk.CTkLabel(caesar_frame, text="Enter Shift Value:", font=("Helvetica", 14))
shift_label.pack(pady=5)
shift_entry = ctk.CTkEntry(caesar_frame, width=100)
shift_entry.pack(pady=5)

key_label = ctk.CTkLabel(caesar_frame, text="Enter Key:", font=("Helvetica", 14))
key_label.pack(pady=5)
key_entry = ctk.CTkEntry(caesar_frame, width=100)
key_entry.pack(pady=5)

plain_text_label = ctk.CTkLabel(caesar_frame, text="Enter Plain Text:", font=("Helvetica", 14))
plain_text_label.pack(pady=5)
plain_text_entry = ctk.CTkEntry(caesar_frame, width=400)
plain_text_entry.pack(pady=5)

encrypt_button_caesar = ctk.CTkButton(caesar_frame, text="Encrypt", command=lambda: encrypt_caesar(), width=200)
encrypt_button_caesar.pack(pady=15)

encrypted_text_caesar_label = ctk.CTkLabel(caesar_frame, text="Encrypted Text: ", font=("Helvetica", 14))
encrypted_text_caesar_label.pack(pady=5)

decrypted_text_caesar_label = ctk.CTkLabel(caesar_frame, text="Decrypted Text: ", font=("Helvetica", 14))
decrypted_text_caesar_label.pack(pady=5)  # Added this line for Caesar decryption

decrypt_button_caesar = ctk.CTkButton(caesar_frame, text="Decrypt", command=lambda: decrypt_caesar(), width=200)
decrypt_button_caesar.pack(pady=15)

# Initial state
update_mode()

# Caesar Cipher Encryption/Decryption Functions
def checkKey(key): 
    for x in range(94):
        if (key * x) % 95 == 1:
            return x
    return None  

def encryption(ptext, shift, key):    
    result = ""
    for char in ptext:
        char_value = ord(char) - 31
        cipher_value =  (char_value * key + shift) % 95
        result += chr(cipher_value)
    return result

def decryption(ctext, shift, key):
    dptxt = ""
    if(checkKey(key) != None):
        inverse = checkKey(key)
        for char in ctext:
            char_value = ord(char)
            value = (inverse * (char_value - shift)) % 95
            dptxt += chr(value + 31)
        return dptxt
    else:
        return f"The key {key} is not coprime with the modulus. Choose a different key."

# RSA Encryption/Decryption Functions
def prime(n):
    i = 2
    while(i < n):
        if(n % i == 0):
            return False
        i = i + 1
    return True

def primeGenerator(min=50, max=1000):
    while(True):
        n = random.randint(min, max)
        if(prime(n)):
            return n

def publickey(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 3
    while e < phi_n:
        if math.gcd(e, phi_n) == 1:
            return e, n
        e += 1
    return None, None

def privateKey(p, q, e):
    d = 1
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while (e * d) % phi_n != 1:
        d += 1
    return d, n

def rsaEncrypt(plaintxt, e, n):
    cipher_txt = []
    for i in plaintxt:
        cipher_value = pow(ord(i), e, n)
        cipher_txt.append(cipher_value)
    result = ""
    for j in cipher_txt:
        result += chr(j)
    with open("E:\\SEMESTER 3\\Discrete maths\\Project\\encrypted.txt", "w") as f:
        json.dump(cipher_txt, f)
    return result

def rsaDecrypt(file_path, d, n):
    # Load the ciphertext (list of integers) from the JSON file
    with open(file_path, "r") as f:
        ctxt = json.load(f)
    
    # Decrypt the ciphertext
    dtxt = ""
    for i in ctxt:
        decrypted_value = (i ** d) % n
        dtxt += chr(decrypted_value)
    
    return dtxt

# Encrypt and Decrypt RSA
def encrypt_rsa():
    global rsa_e, rsa_n, rsa_d
    p = primeGenerator()
    q = primeGenerator()
    rsa_e, rsa_n = publickey(p, q)
    rsa_d, rsa_n = privateKey(p, q, rsa_e)
    plaintext = rsa_input_entry.get()
    ciphertext = rsaEncrypt(plaintext, rsa_e, rsa_n)
    
    # Update keys and encrypted text labels
    public_key_label.configure(text=f"Public Key: ({rsa_e}, {rsa_n})")
    private_key_label.configure(text=f"Private Key: ({rsa_d}, {rsa_n})")
    encrypted_text_label.configure(text=f"Encrypted Text: {ciphertext}")  

def decrypt_rsa():
    global rsa_e, rsa_n, rsa_d
    decrypted_text = rsaDecrypt("E:\\SEMESTER 3\\Discrete maths\\Project\\encrypted.txt", rsa_d, rsa_n)
    decrypted_text_label.configure(text=f"Decrypted Text: {decrypted_text}")  # Updated label for decrypted text

# Caesar Cipher Encryption/Decryption
def encrypt_caesar():
    plaintext = plain_text_entry.get()
    shift = int(shift_entry.get())
    key = int(key_entry.get())
    
    # Encrypt the text using Caesar cipher
    encrypted_text = encryption(plaintext, shift, key)
    
    # Display the encrypted text
    encrypted_text_caesar_label.configure(text=f"Encrypted Text: {encrypted_text}")

def decrypt_caesar():
    ciphertext = encrypted_text_caesar_label.cget("text").replace("Encrypted Text: ", "")
    shift = int(shift_entry.get())
    key = int(key_entry.get())
    
    # Decrypt the text using Caesar cipher
    decrypted_text = decryption(ciphertext, shift, key)
    
    # Display the decrypted text
    decrypted_text_caesar_label.configure(text=f"Decrypted Text: {decrypted_text}")

# Start the GUI loop
app.mainloop()
