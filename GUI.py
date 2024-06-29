import tkinter as tk
from tkinter import filedialog, messagebox
import json
from tkinter import simpledialog
from core import generate_aes_key, encrypt_file_aes, decrypt_file_aes, generate_rsa_key_pair, encrypt_string_rsa, decrypt_string_rsa, calculate_sha1
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1, SHA256


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Application")

        # Encrypt File Section
        self.encrypt_frame = tk.LabelFrame(root, text="Encrypt File", padx=10, pady=10)
        self.encrypt_frame.pack(padx=10, pady=10)

        self.select_file_btn = tk.Button(self.encrypt_frame, text="Select File", command=self.select_file)
        self.select_file_btn.grid(row=0, column=0, padx=10, pady=10)

        self.selected_file_label = tk.Label(self.encrypt_frame, text="No file selected")
        self.selected_file_label.grid(row=0, column=1, padx=10, pady=10)

        self.encrypt_file_btn = tk.Button(self.encrypt_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_btn.grid(row=1, column=0, columnspan=2, pady=10)

        # Decrypt File Section
        self.decrypt_frame = tk.LabelFrame(root, text="Decrypt File", padx=10, pady=10)
        self.decrypt_frame.pack(padx=10, pady=10)

        self.select_enc_file_btn = tk.Button(self.decrypt_frame, text="Select Encrypted File", command=self.select_enc_file)
        self.select_enc_file_btn.grid(row=0, column=0, padx=10, pady=10)

        self.selected_enc_file_label = tk.Label(self.decrypt_frame, text="No file selected")
        self.selected_enc_file_label.grid(row=0, column=1, padx=10, pady=10)

        self.select_key_file_btn = tk.Button(self.decrypt_frame, text="Select Key File", command=self.select_key_file)
        self.select_key_file_btn.grid(row=1, column=0, padx=10, pady=10)

        self.selected_key_file_label = tk.Label(self.decrypt_frame, text="No key file selected")
        self.selected_key_file_label.grid(row=1, column=1, padx=10, pady=10)

        self.enter_key_btn = tk.Button(self.decrypt_frame, text="Enter Key Manually", command=self.enter_key_manually)
        self.enter_key_btn.grid(row=2, column=0, columnspan=2, pady=10)

        self.check_hash_btn = tk.Button(self.decrypt_frame, text="Check Hash", command=self.check_hash)
        self.check_hash_btn.grid(row=3, column=0, columnspan=2, pady=10)

        self.decrypt_file_btn = tk.Button(self.decrypt_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_btn.grid(row=4, column=0, columnspan=2, pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_label.config(text=file_path)
            self.file_path = file_path

    def encrypt_file(self):
        if hasattr(self, 'file_path'):
            # Step b: Generate AES key and encrypt file
            aes_key = generate_aes_key()
            ciphertext, nonce, tag = encrypt_file_aes(self.file_path, aes_key)

            # Step c: Generate RSA key pair and encrypt AES key
            rsa_private_key, rsa_public_key = generate_rsa_key_pair()
            encrypted_aes_key = encrypt_string_rsa(aes_key, rsa_public_key)
            sha1_hash = calculate_sha1(rsa_private_key)

            # Step d: Save encrypted file
            with open(self.file_path + ".enc", 'wb') as f:
                f.write(nonce + tag + ciphertext)

            # Step d: Save metadata
            metadata = {
                'encrypted_aes_key': encrypted_aes_key,
                'sha1_hash': sha1_hash
            }
            with open(self.file_path + ".metadata.txt", 'w') as f:
                json.dump(metadata, f)

            # Step e: Export RSA key pair
            key_data = {
                'private_key': rsa_private_key,
                'public_key': rsa_public_key
            }
            with open(self.file_path + ".keys.txt", 'w') as f:
                json.dump(key_data, f)

            messagebox.showinfo("Encrypt File", "File encrypted successfully!")
        else:
            messagebox.showwarning("Encrypt File", "No file selected!")

    def select_enc_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_enc_file_label.config(text=file_path)
            self.enc_file_path = file_path

    def select_key_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_key_file_label.config(text=file_path)
            self.key_file_path = file_path

    def enter_key_manually(self):
        self.private_key = simpledialog.askstring("Input", "Enter the private key:", show='*')
        self.public_key = simpledialog.askstring("Input", "Enter the public key:")

        if self.private_key and self.public_key:
            self.key_display_frame = tk.LabelFrame(self.root, text="Entered Keys", padx=10, pady=10)
            self.key_display_frame.pack(padx=10, pady=10)

            self.private_key_label = tk.Label(self.key_display_frame, text="Private Key:")
            self.private_key_label.grid(row=0, column=0, padx=10, pady=5)
            self.private_key_text = tk.Text(self.key_display_frame, height=5, width=50)
            self.private_key_text.grid(row=0, column=1, padx=10, pady=5)
            self.private_key_text.insert(tk.END, self.private_key)
            self.private_key_text.config(state=tk.DISABLED)  # Make the Text widget read-only

            self.public_key_label = tk.Label(self.key_display_frame, text="Public Key:")
            self.public_key_label.grid(row=1, column=0, padx=10, pady=5)
            self.public_key_text = tk.Text(self.key_display_frame, height=5, width=50)
            self.public_key_text.grid(row=1, column=1, padx=10, pady=5)
            self.public_key_text.insert(tk.END, self.public_key)
            self.public_key_text.config(state=tk.DISABLED)  # Make the Text widget read-only

    def check_hash(self):
        if hasattr(self, 'enc_file_path'):
            if hasattr(self, 'key_file_path'):
                # Read key file
                with open(self.key_file_path, 'r') as f:
                    key_data = json.load(f)
                private_key = key_data['private_key']
            elif hasattr(self, 'private_key'):
                private_key = self.private_key
            else:
                messagebox.showwarning("Check Hash", "No private key provided!")
                return

            # Check SHA-1 hash
            metadata_path = self.enc_file_path.replace('.enc', '.metadata.txt')
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            sha1_hash = metadata['sha1_hash']
            if calculate_sha1(private_key) == sha1_hash:
                messagebox.showinfo("Check Hash", "SHA-1 hash matches!")
            else:
                messagebox.showerror("Check Hash", "SHA-1 hash does not match!")
        else:
            messagebox.showwarning("Check Hash", "No encrypted file selected!")

    def decrypt_file(self):
        if hasattr(self, 'enc_file_path'):
            if hasattr(self, 'key_file_path'):
                # Read key file
                with open(self.key_file_path, 'r') as f:
                    key_data = json.load(f)
                private_key = key_data['private_key']
                public_key = key_data['public_key']
            elif hasattr(self, 'private_key') and hasattr(self, 'public_key'):
                private_key = self.private_key
                public_key = self.public_key
            else:
                messagebox.showwarning("Decrypt File", "No key provided!")
                return

            # Check SHA-1 hash
            metadata_path = self.enc_file_path.replace('.enc', '.metadata.txt')
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            sha1_hash = metadata['sha1_hash']
            if calculate_sha1(private_key) != sha1_hash:
                messagebox.showerror("Decrypt File", "SHA-1 hash does not match!")
                return

            # Decrypt the AES key
            encrypted_aes_key = metadata['encrypted_aes_key']
            aes_key = decrypt_string_rsa(encrypted_aes_key, private_key)

            # Decrypt the file
            with open(self.enc_file_path, 'rb') as f:
                file_content = f.read()
            nonce, tag, ciphertext = file_content[:16], file_content[16:32], file_content[32:]
            try:
                decrypted_data = decrypt_file_aes(ciphertext, aes_key, nonce, tag)
                with open(self.enc_file_path.replace(".enc", ""), 'wb') as f:
                    f.write(decrypted_data)
                messagebox.showinfo("Decrypt File", "File decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Decrypt File", f"Decryption failed: {e}")
        else:
            messagebox.showwarning("Decrypt File", "No file selected!")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
