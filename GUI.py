import tkinter as tk
from tkinter import filedialog, messagebox
import json
from core import generate_aes_key, encrypt_file_aes, decrypt_file_aes, generate_rsa_key_pair, encrypt_string_rsa, decrypt_string_rsa, calculate_sha1

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

        self.select_key_file_btn = tk.Button(self.decrypt_frame, text="Select Private Key File", command=self.select_key_file)
        self.select_key_file_btn.grid(row=1, column=0, padx=10, pady=10)

        self.selected_key_file_label = tk.Label(self.decrypt_frame, text="No key file selected")
        self.selected_key_file_label.grid(row=1, column=1, padx=10, pady=10)

        self.decrypt_file_btn = tk.Button(self.decrypt_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_btn.grid(row=2, column=0, columnspan=2, pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_label.config(text=file_path)
            self.file_path = file_path

    def encrypt_file(self):
        if hasattr(self, 'file_path'):
            aes_key = generate_aes_key()
            ciphertext, nonce, tag = encrypt_file_aes(self.file_path, aes_key)
            rsa_private_key, rsa_public_key = generate_rsa_key_pair()
            encrypted_aes_key = encrypt_string_rsa(aes_key, rsa_public_key)
            sha1_hash = calculate_sha1(rsa_private_key)

            with open(self.file_path + ".enc", 'wb') as f:
                f.write(nonce + tag + ciphertext)

            metadata = {
                'encrypted_aes_key': encrypted_aes_key.hex(),
                'sha1_hash': sha1_hash
            }
            with open(self.file_path + ".metadata", 'w') as f:
                json.dump(metadata, f)

            with open(self.file_path + ".private_key", 'wb') as f:
                f.write(rsa_private_key)

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

    def decrypt_file(self):
        if hasattr(self, 'enc_file_path') and hasattr(self, 'key_file_path'):
            with open(self.key_file_path, 'rb') as f:
                private_key = f.read()
            with open(self.enc_file_path + ".metadata", 'r') as f:
                metadata = json.load(f)
            sha1_hash = metadata['sha1_hash']
            if calculate_sha1(private_key) != sha1_hash:
                messagebox.showerror("Decrypt File", "SHA-1 hash does not match!")
                return
            encrypted_aes_key = bytes.fromhex(metadata['encrypted_aes_key'])
            aes_key = decrypt_string_rsa(encrypted_aes_key, private_key)
            with open(self.enc_file_path, 'rb') as f:
                file_content = f.read()
            nonce, tag, ciphertext = file_content[:16], file_content[16:32], file_content[32:]
            try:
                decrypted_data = decrypt_file_aes(ciphertext, aes_key, nonce, tag)
                with open(self.enc_file_path.replace(".enc", ".dec"), 'wb') as f:
                    f.write(decrypted_data)
                messagebox.showinfo("Decrypt File", "File decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Decrypt File", f"Decryption failed: {e}")
        else:
            messagebox.showwarning("Decrypt File", "No file or key selected!")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
