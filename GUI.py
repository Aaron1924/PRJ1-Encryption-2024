import tkinter as tk
from tkinter import filedialog, messagebox
import json
import customtkinter as ctk
from core import generate_aes_key, encrypt_file_aes, decrypt_file_aes, generate_rsa_key_pair, encrypt_string_rsa, decrypt_string_rsa, calculate_sha1
import os.path

LARGEFONT =("Verdana", 35)
HELVETICA = ("Helvetica", 20, "bold")
class EncryptionApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        tk.Tk.title(self, "File Encryption App")
        tk.Tk.geometry(self, "1000x800")

        #container will contain all the frame
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        #dictionary to store all the frames
        self.frames = {}
        for F in (MenuFrame, EncryptionFrame, DecryptionFrame):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame

            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("MenuFrame")

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()

class MenuFrame(tk.Frame):
    def __init__(self,parent, controller):
        # Menu Section
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="File Encryption App",font=LARGEFONT)
        label.grid(row=0,column=2,padx = 10, pady = 10) 

        encrypt_btn = tk.Button(self,
                                 text="Encrypt File",
                                 font=HELVETICA,
                                 width=20,
                                 height=5,
                                 command=lambda: controller.show_frame("EncryptionFrame"))
        encrypt_btn.grid(row = 1,column=1,padx=10, pady=10)

        decrypt_btn = tk.Button(self, text="Decrypt File",
                                font= HELVETICA,
                                width=20,
                                height=5,
                                command=lambda: controller.show_frame("DecryptionFrame"))
        decrypt_btn.grid(row=1,column=3, padx=10, pady=10)


class EncryptionFrame(tk.Frame):
    def __init__(self,parent, controller):
        # Encrypt File Section
        tk.Frame.__init__(self, parent)
        
        label = tk.Label(self, text="Encrypt File",font=LARGEFONT)
        label.grid(row=0,column=2,padx = 10, pady = 10)
        self.controller = controller

        select_file_btn = tk.Button(self,text = "Select File",command=lambda: SelectFile.select_file(self))
        select_file_btn.grid(row=1,column=0,padx=10,pady=10)

        selected_file_label = tk.Label(self, text="No file selected")
        selected_file_label.grid(row=1,column=1,padx=10,pady=10)

        encrypt_file_btn = tk.Button(self, text="Encrypt File",command=lambda: Encrypt.encrypt_file(self))
        encrypt_file_btn.grid(row=2,column=0,columnspan=2,pady=10)

        
class DecryptionFrame(tk.Frame):
    def __init__(self,parent, controller):
        # Decrypt File Section
        tk.Frame.__init__(self, parent)

        label = tk.Label(self, text="Decrypt File",font=LARGEFONT)
        label.grid(row=0,column=2,padx = 10, pady = 10)
        self.controller = controller

        select_en_file_btn = tk.Button(self,text = "Select Encrypted File",command=lambda: SelectFile.select_file(self))
        select_en_file_btn.grid(row=1,column=0,padx=10,pady=10)

        selected_file_label = tk.Label(self, text="No file selected")
        selected_file_label.grid(row=1,column=1,padx=10,pady=10)

        select_key_file_btn = tk.Button(self, text="Select Key File",command=lambda: SelectFile.select_key_file(self))
        select_key_file_btn.grid(row=2,column=0,padx=10,pady=10)

        selected_file_label = tk.Label(self, text="No file selected")
        selected_file_label.grid(row=2,column=1,padx=10,pady=10)

        decrypt_btn = tk.Button(self, text="Decrypt File",command=lambda: Decrypt.decrypt_file(self))
        decrypt_btn.grid(row=3,column=0,padx=10,pady=10)


class SelectFile:
    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_label.config(text=file_path)
            self.file_path = file_path
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
    # def save_file(self):
    #     file_path = filedialog.savefilelog()
    #     if file_path:
    #         self.selected_file_label.config(text=file_path)
    #         self.file_path = file_path

class Encrypt:
    def encrypt_file(self):
        if hasattr(self, 'file_path'):
            # Step b: Generate AES key and encrypt file
            aes_key = generate_aes_key()
            ciphertext, nonce, tag = encrypt_file_aes(self.file_path, aes_key)

            # Step c: Generate RSA key pair and encrypt AES key
            rsa_private_key, rsa_public_key = generate_rsa_key_pair()
            encrypted_aes_key = encrypt_string_rsa(aes_key, rsa_public_key)


            # output encrypted aes key to screen
            
            sha1_hash = calculate_sha1(rsa_private_key)

            # Step d: Save metadata
            with open(self.file_path + ".enc", 'wb') as f:
                f.write(nonce + tag + ciphertext)

            metadata = {
                'encrypted_aes_key': encrypted_aes_key.hex(),
                'sha1_hash': sha1_hash
            }
            with open(self.file_path + ".metadata", 'w') as f:
                json.dump(metadata, f)

            # Step e: Export RSA private key
            with open(self.file_path + ".private_key", 'wb') as f:
                f.write(rsa_private_key)

            messagebox.showinfo("Encrypt File", "File encrypted successfully!")
        else:
            messagebox.showwarning("Encrypt File", "No file selected!")


class Decrypt:
    def decrypt_file(self):
        if hasattr(self, 'enc_file_path') and hasattr(self, 'key_file_path'):
            # Step b: Read private key from file
            with open(self.key_file_path, 'rb') as f:
                private_key = f.read()
            
            # Step c: Check SHA-1 hash
            with open(self.enc_file_path + ".metadata", 'r') as f:
                metadata = json.load(f)
            sha1_hash = metadata['sha1_hash']
            if calculate_sha1(private_key) != sha1_hash:
                messagebox.showerror("Decrypt File", "SHA-1 hash does not match!")
                return
            
            # Step d: Decrypt the AES key
            encrypted_aes_key = bytes.fromhex(metadata['encrypted_aes_key'])
            aes_key = decrypt_string_rsa(encrypted_aes_key, private_key)

            # Step e: Decrypt the file
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
    main = EncryptionApp()
    main.mainloop()
