import tkinter as tk
from tkinter import filedialog, messagebox
import json
from tkinter import simpledialog
from core import generate_aes_key, encrypt_file_aes, decrypt_file_aes, generate_rsa_key_pair, encrypt_string_rsa, decrypt_string_rsa, calculate_sha1
import base64
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1, SHA256
import customtkinter as ctk



LARGEFONT =("Verdana", 35)
HELVETICA = ("Helvetica", 20, "bold")

class MenuFrame(ctk.CTkFrame):
    def __init__(self, master, show_encrypt_frame, show_decrypt_frame, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.show_encrypt_frame = show_encrypt_frame
        self.show_decrypt_frame = show_decrypt_frame
        
        self.encrypt_menu_btn = ctk.CTkButton(self, text="Encrypt File", command=self.show_encrypt_frame)
        self.encrypt_menu_btn.pack(padx=10, pady=10)

        self.decrypt_menu_btn = ctk.CTkButton(self, text="Decrypt File", command=self.show_decrypt_frame)
        self.decrypt_menu_btn.pack(padx=10, pady=10)

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Application")

        self.save_dir = ""
        self.aes_mode = ctk.StringVar(value="EAX")

        # Main Menu
        self.main_menu_frame = MenuFrame(root, self.show_encrypt_frame, self.show_decrypt_frame)
        self.main_menu_frame.pack(padx=10, pady=10)

        # Encrypt Frame
        self.encrypt_frame = ctk.CTkFrame(root)

        self.select_file_btn = ctk.CTkButton(self.encrypt_frame, text="Select File", command=self.select_file)
        self.select_file_btn.grid(row=0, column=0, padx=10, pady=10)

        self.selected_file_label = ctk.CTkLabel(self.encrypt_frame, text="No file selected")
        self.selected_file_label.grid(row=0, column=1, padx=10, pady=10)

        self.select_dir_btn = ctk.CTkButton(self.encrypt_frame, text="Select Directory", command=self.select_directory)
        self.select_dir_btn.grid(row=1, column=0, padx=10, pady=10)

        self.selected_dir_label = ctk.CTkLabel(self.encrypt_frame, text="No directory selected")
        self.selected_dir_label.grid(row=1, column=1, padx=10, pady=10)

        self.encrypt_file_btn = ctk.CTkButton(self.encrypt_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_btn.grid(row=2, column=0, columnspan=2, pady=10)

        self.mode_label = ctk.CTkLabel(self.encrypt_frame, text="AES Mode:")
        self.mode_label.grid(row=3, column=0, padx=10, pady=5)
        self.mode_option = ctk.CTkOptionMenu(self.encrypt_frame, variable=self.aes_mode, values=["CBC", "OFB", "CTR", "ECB", "EAX"])
        self.mode_option.grid(row=3, column=1, padx=10, pady=5)

        self.back_btn_enc = ctk.CTkButton(self.encrypt_frame, text="Back", command=self.show_main_menu)
        self.back_btn_enc.grid(row=4, column=0, columnspan=2, pady=10)

        # Decrypt Frame
        self.decrypt_frame = ctk.CTkFrame(root)

        self.select_enc_file_btn = ctk.CTkButton(self.decrypt_frame, text="Select Encrypted File", command=self.select_enc_file)
        self.select_enc_file_btn.grid(row=0, column=0, padx=10, pady=10)

        self.selected_enc_file_label = ctk.CTkLabel(self.decrypt_frame, text="No file selected")
        self.selected_enc_file_label.grid(row=0, column=1, padx=10, pady=10)

        self.select_key_file_btn = ctk.CTkButton(self.decrypt_frame, text="Select Key File", command=self.select_key_file)
        self.select_key_file_btn.grid(row=1, column=0, padx=10, pady=10)

        self.selected_key_file_label = ctk.CTkLabel(self.decrypt_frame, text="No key file selected")
        self.selected_key_file_label.grid(row=1, column=1, padx=10, pady=10)

        self.enter_key_btn = ctk.CTkButton(self.decrypt_frame, text="Enter Key Manually", command=self.enter_key_manually)
        self.enter_key_btn.grid(row=2, column=0, columnspan=2, pady=10)

        self.check_hash_btn = ctk.CTkButton(self.decrypt_frame, text="Check Hash", command=self.check_hash)
        self.check_hash_btn.grid(row=3, column=0, columnspan=2, pady=10)

        self.decrypt_file_btn = ctk.CTkButton(self.decrypt_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_btn.grid(row=4, column=0, columnspan=2, pady=10)

        self.back_btn_dec = ctk.CTkButton(self.decrypt_frame, text="Back", command=self.show_main_menu)
        self.back_btn_dec.grid(row=5, column=0, columnspan=2, pady=10)

    def show_main_menu(self):
        self.encrypt_frame.pack_forget()
        self.decrypt_frame.pack_forget()
        self.main_menu_frame.pack(padx=10, pady=10)

    def show_encrypt_frame(self):
        self.main_menu_frame.pack_forget()
        self.encrypt_frame.pack(padx=10, pady=10)

    def show_decrypt_frame(self):
        self.main_menu_frame.pack_forget()
        self.decrypt_frame.pack(padx=10, pady=10)

    def select_directory(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.selected_dir_label.configure(text=dir_path)
            self.save_dir = dir_path

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_label.configure(text=file_path)
            self.file_path = file_path

    def encrypt_file(self):
        if hasattr(self, 'file_path'):
            if not self.save_dir:
                messagebox.showwarning("Encrypt File", "No directory selected!")
                return

            # Step b: Generate AES key and encrypt file
            aes_key = generate_aes_key()
            aes_mode = self.aes_mode.get()
            ciphertext, nonce, tag = encrypt_file_aes(self.file_path, aes_key, aes_mode)

            # Step c: Generate RSA key pair and encrypt AES key
            rsa_private_key, rsa_public_key = generate_rsa_key_pair()
            encrypted_aes_key = encrypt_string_rsa(aes_key, rsa_public_key)
            sha1_hash = calculate_sha1(rsa_private_key)

            # Get base name of file
            base_name = os.path.basename(self.file_path)

            # Step d: Save encrypted file
            with open(os.path.join(self.save_dir, base_name + ".enc"), 'wb') as f:
                f.write(nonce + (tag if tag else b'') + ciphertext)

            # Step d: Save metadata with original filename
            metadata = {
                'encrypted_aes_key': encrypted_aes_key,
                'sha1_hash': sha1_hash,
                'aes_mode': aes_mode,
                'original_filename': base_name
            }
            with open(os.path.join(self.save_dir, base_name + ".metadata.txt"), 'w') as f:
                json.dump(metadata, f)

            # Step e: Export RSA key pair
            key_data = {
                'private_key': rsa_private_key,
                'public_key': rsa_public_key
            }
            with open(os.path.join(self.save_dir, base_name + ".keys.txt"), 'w') as f:
                json.dump(key_data, f)

            messagebox.showinfo("Encrypt File", "File encrypted successfully!")
        else:
            messagebox.showwarning("Encrypt File", "No file selected!")

    def select_enc_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_enc_file_label.configure(text=file_path)
            self.enc_file_path = file_path

    def select_key_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_key_file_label.configure(text=file_path)
            self.key_file_path = file_path

    def enter_key_manually(self):
        self.private_key = simpledialog.askstring("Input", "Enter the private key:", show='*')
        self.public_key = simpledialog.askstring("Input", "Enter the public key:")

        if self.private_key and self.public_key:
            self.key_display_frame = ctk.CTkFrame(self.root)
            self.key_display_frame.pack(padx=10, pady=10)

            self.private_key_label = ctk.CTkLabel(self.key_display_frame, text="Private Key:")
            self.private_key_label.grid(row=0, column=0, padx=10, pady=5)
            self.private_key_text = ctk.CTkTextbox(self.key_display_frame, height=5, width=50)
            self.private_key_text.grid(row=0, column=1, padx=10, pady=5)
            self.private_key_text.insert(tk.END, self.private_key)
            self.private_key_text.configure(state=tk.DISABLED)

            self.public_key_label = ctk.CTkLabel(self.key_display_frame, text="Public Key:")
            self.public_key_label.grid(row=1, column=0, padx=10, pady=5)
            self.public_key_text = ctk.CTkTextbox(self.key_display_frame, height=5, width=50)
            self.public_key_text.grid(row=1, column=1, padx=10, pady=5)
            self.public_key_text.insert(tk.END, self.public_key)
            self.public_key_text.configure(state=tk.DISABLED)

    def check_hash(self):
        if hasattr(self, 'enc_file_path'):
            if hasattr(self, 'key_file_path'):
                with open(self.key_file_path, 'r') as f:
                    key_data = json.load(f)
                private_key = key_data['private_key']
            elif hasattr(self, 'private_key'):
                private_key = self.private_key
            else:
                messagebox.showwarning("Check Hash", "No private key entered!")
                return

            metadata_path = self.enc_file_path.replace('.enc', '.metadata.txt')
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Check Hash", "Metadata file is missing or corrupted!")
                return

            sha1_hash = metadata.get('sha1_hash')
            if sha1_hash and calculate_sha1(private_key) == sha1_hash:
                messagebox.showinfo("Check Hash", "SHA-1 hash matches!")
            else:
                messagebox.showerror("Check Hash", "SHA-1 hash does not match!")
        else:
            messagebox.showwarning("Check Hash", "No encrypted file selected!")

    def decrypt_file(self):
        if hasattr(self, 'enc_file_path') and hasattr(self, 'key_file_path'):
            with open(self.key_file_path, 'r') as f:
                key_data = json.load(f)
            private_key = key_data['private_key']

            metadata_path = self.enc_file_path.replace('.enc', '.metadata.txt')
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Decrypt File", "Metadata file is missing or corrupted!")
                return

            sha1_hash = metadata.get('sha1_hash')
            if not sha1_hash or calculate_sha1(private_key) != sha1_hash:
                messagebox.showerror("Decrypt File", "SHA-1 hash does not match!")
                return

            encrypted_aes_key = metadata.get('encrypted_aes_key')
            aes_key = decrypt_string_rsa(encrypted_aes_key, private_key)
            aes_mode = metadata.get('aes_mode', 'EAX')

            original_filename = metadata.get('original_filename', 'decrypted_file')

            with open(self.enc_file_path, 'rb') as f:
                file_content = f.read()
            if aes_mode in ['CBC', 'OFB']:
                nonce_or_iv, ciphertext = file_content[:16], file_content[16:]
                tag = None
            elif aes_mode == 'CTR':
                nonce_or_iv, ciphertext = file_content[:8], file_content[8:]
                tag = None
            elif aes_mode == 'EAX':
                nonce_or_iv, tag, ciphertext = file_content[:16], file_content[16:32], file_content[32:]
            else:  # ECB mode has no nonce or iv
                nonce_or_iv, tag, ciphertext = None, None, file_content

            try:
                decrypted_data = decrypt_file_aes(ciphertext, aes_key, aes_mode, nonce_or_iv, tag)
                with open(os.path.join(self.save_dir, original_filename), 'wb') as f:
                    f.write(decrypted_data)
                messagebox.showinfo("Decrypt File", "File decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Decrypt File", f"An error occurred: {e}")
        else:
            messagebox.showwarning("Decrypt File", "No file or key selected!")

if __name__ == "__main__":
    root = ctk.CTk()
    app = EncryptionApp(root)
    root.mainloop()