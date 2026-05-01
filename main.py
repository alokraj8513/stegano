import os
import platform
import subprocess
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Import updated backend functions
from image_utils import embed_message, extract_message, generate_lsb_map, predict_steganography

ALGORITHMS = ["AES-256-GCM", "ChaCha20-Poly1305", "Fernet", "XOR (Legacy)"]


class SteganoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛡️ Advanced Cryptographic Steganography")
        self.geometry("750x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        ctk.CTkLabel(self, text="Stegano Application", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(10, 0))

        self.tabview = ctk.CTkTabview(self, width=720, height=580)
        self.tabview.pack(padx=10, pady=10)

        self.encrypt_tab = self.tabview.add("Encryption")
        self.decrypt_tab = self.tabview.add("Decryption")
        self.analysis_tab = self.tabview.add("Forensic Analysis")
        self.help_tab = self.tabview.add("Help")

        self.build_encrypt_tab()
        self.build_decrypt_tab()
        self.build_analysis_tab()
        self.build_help_tab()

    # ==========================================
    # ENCRYPTION TAB
    # ==========================================
    def build_encrypt_tab(self):
        self.enc_img_path = ctk.StringVar()
        self.enc_algo_var = ctk.StringVar(value=ALGORITHMS[0])

        ctk.CTkLabel(self.encrypt_tab, text="Select Image").pack(pady=2)
        ctk.CTkEntry(self.encrypt_tab, textvariable=self.enc_img_path, width=520).pack(pady=2)
        ctk.CTkButton(self.encrypt_tab, text="Browse", command=self.browse_enc_img).pack(pady=2)

        ctk.CTkLabel(self.encrypt_tab, text="Algorithm").pack(pady=(10, 2))
        ctk.CTkOptionMenu(self.encrypt_tab, variable=self.enc_algo_var,
                          values=ALGORITHMS, width=300).pack(pady=2)

        ctk.CTkLabel(self.encrypt_tab, text="Message to Hide").pack(pady=(10, 2))
        self.message_box = ctk.CTkTextbox(self.encrypt_tab, height=100, width=600)
        self.message_box.pack(pady=2)

        ctk.CTkLabel(self.encrypt_tab, text="Encryption Key / Password").pack(pady=(10, 2))
        self.enc_key_entry = ctk.CTkEntry(self.encrypt_tab, width=300, show="*")
        self.enc_key_entry.pack(pady=2)

        ctk.CTkButton(self.encrypt_tab, text="Embed Message", command=self.embed_gui).pack(pady=15)

    def browse_enc_img(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp *.jpg")])
        if file_path:
            self.enc_img_path.set(file_path)

    def embed_gui(self):
        try:
            path = self.enc_img_path.get()
            message = self.message_box.get("1.0", "end").strip()
            key = self.enc_key_entry.get().strip()
            algo = self.enc_algo_var.get()

            if not (path and os.path.exists(path)):
                messagebox.showerror("Error", "Image path is invalid.")
                return
            if not message or not key:
                messagebox.showwarning("Warning", "Message and Key cannot be empty.")
                return

            # Clean output filename based on algorithm
            safe_algo_name = algo.split()[0].replace("-", "")
            output_path = os.path.splitext(path)[0] + f"_encoded_{safe_algo_name}.png"

            embed_message(path, message, key, algo, output_path)
            messagebox.showinfo("Success", f"Message embedded using {algo} and saved to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    # ==========================================
    # DECRYPTION TAB
    # ==========================================
    def build_decrypt_tab(self):
        self.dec_img_path = ctk.StringVar()
        self.dec_algo_var = ctk.StringVar(value=ALGORITHMS[0])

        ctk.CTkLabel(self.decrypt_tab, text="Select Image").pack(pady=2)
        ctk.CTkEntry(self.decrypt_tab, textvariable=self.dec_img_path, width=520).pack(pady=2)
        ctk.CTkButton(self.decrypt_tab, text="Browse", command=self.browse_dec_img).pack(pady=2)

        ctk.CTkLabel(self.decrypt_tab, text="Algorithm Used").pack(pady=(10, 2))
        ctk.CTkOptionMenu(self.decrypt_tab, variable=self.dec_algo_var,
                          values=ALGORITHMS, width=300).pack(pady=2)

        ctk.CTkLabel(self.decrypt_tab, text="Decryption Key / Password").pack(pady=(10, 2))
        self.dec_key_entry = ctk.CTkEntry(self.decrypt_tab, width=300, show="*")
        self.dec_key_entry.pack(pady=2)

        ctk.CTkButton(self.decrypt_tab, text="Extract Message", command=self.extract_gui).pack(pady=15)

        ctk.CTkLabel(self.decrypt_tab, text="Extracted Message").pack(pady=2)
        self.output_box = ctk.CTkTextbox(self.decrypt_tab, height=120, width=600)
        self.output_box.pack(pady=2)

    def browse_dec_img(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp *.jpg")])
        if file_path:
            self.dec_img_path.set(file_path)

    def extract_gui(self):
        try:
            path = self.dec_img_path.get()
            key = self.dec_key_entry.get().strip()
            algo = self.dec_algo_var.get()

            if not (path and os.path.exists(path)):
                messagebox.showerror("Error", "Image path is invalid.")
                return
            if not key:
                messagebox.showwarning("Warning", "Key cannot be empty.")
                return

            msg = extract_message(path, key, algo)
            self.output_box.delete("1.0", "end")
            self.output_box.insert("1.0", msg)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    # ==========================================
    # FORENSIC ANALYSIS TAB
    # ==========================================
    def build_analysis_tab(self):
        self.ana_img_path = ctk.StringVar()

        ctk.CTkLabel(self.analysis_tab, text="Select Image for Analysis").pack(pady=5)
        ctk.CTkEntry(self.analysis_tab, textvariable=self.ana_img_path, width=520).pack(pady=2)
        ctk.CTkButton(self.analysis_tab, text="Browse", command=self.browse_ana_img).pack(pady=2)

        ctk.CTkButton(self.analysis_tab, text="Generate Data Concentration Map",
                      command=self.run_lsb_map).pack(pady=15)

        ctk.CTkButton(self.analysis_tab, text="Run ML Steganalysis",
                      command=self.run_ml_check, fg_color="#8B0000", hover_color="#5c0000").pack(pady=5)

        ctk.CTkLabel(self.analysis_tab, text="Terminal Output").pack(pady=(15, 5))
        self.ana_output_box = ctk.CTkTextbox(self.analysis_tab, height=150, width=600,
                                             font=("Consolas", 12), text_color="#00FF00", fg_color="black")
        self.ana_output_box.pack(pady=5)
        self.ana_output_box.insert("end", "System ready. Awaiting forensic task...\n")

    def browse_ana_img(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp *.jpg")])
        if file_path:
            self.ana_img_path.set(file_path)

    def run_lsb_map(self):
        try:
            path = self.ana_img_path.get()
            if not (path and os.path.exists(path)):
                messagebox.showerror("Error", "Image path is invalid.")
                return

            output_path = os.path.splitext(path)[0] + "_lsb_map.png"
            generate_lsb_map(path, output_path)

            self.ana_output_box.insert("end", f"\n[+] SUCCESS: LSB Map generated.\n    Saved to: {output_path}\n")
            self.ana_output_box.see("end")

            if platform.system() == 'Darwin':
                subprocess.call(('open', output_path))
            elif platform.system() == 'Windows':
                os.startfile(output_path)
            else:
                subprocess.call(('xdg-open', output_path))
        except Exception as e:
            self.ana_output_box.insert("end", f"\n[-] ERROR: {str(e)}\n")
            self.ana_output_box.see("end")

    def run_ml_check(self):
        try:
            path = self.ana_img_path.get()
            if not (path and os.path.exists(path)):
                messagebox.showerror("Error", "Image path is invalid.")
                return
            self.ana_output_box.insert("end", "\n[*] Running ML Steganalysis heuristics...\n")
            is_modified, confidence = predict_steganography(path)
            if is_modified:
                result = f"[!] ALERT: Steganography Detected (Confidence: {confidence:.2f}%)\n"
            else:
                result = f"[-] CLEAN: No significant modifications found. (Confidence: {confidence:.2f}%)\n"
            self.ana_output_box.insert("end", result)
            self.ana_output_box.see("end")
        except Exception as e:
            self.ana_output_box.insert("end", f"\n[-] ERROR: {str(e)}\n")
            self.ana_output_box.see("end")

    # ==========================================
    # HELP TAB
    # ==========================================
    def build_help_tab(self):
        help_text = (
            "📘 How to Use:\n\n"
            "🔐 Encryption & Decryption:\n"
            "1. Select your target image.\n"
            "2. Select your encryption algorithm.\n"
            "   - AES-256-GCM: Standard, authenticated, high security.\n"
            "   - ChaCha20-Poly1305: Fast, highly secure stream cipher.\n"
            "   - Fernet: Standard Python cryptography recipe.\n"
            "   - XOR: Legacy/Educational only.\n"
            "3. Provide your message and a strong password.\n"
            "4. Ensure you use the EXACT SAME algorithm and password to decrypt.\n\n"
            "🕵️ Forensic Analysis:\n"
            "1. Generate an LSB Map to visually inspect data concentration.\n"
            "2. Run ML Steganalysis to detect anomalies statistically."
        )
        box = ctk.CTkTextbox(self.help_tab, height=500, width=660, font=("Arial", 13))
        box.pack(padx=10, pady=10)
        box.insert("1.0", help_text)
        box.configure(state="disabled")


if __name__ == "__main__":
    app = SteganoApp()
    app.mainloop()