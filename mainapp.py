import customtkinter as ctk
from tkinter import messagebox

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# ================= CAESAR CIPHER =================

def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# ================= PLAYFAIR CIPHER =================

def generate_matrix(key):
    key = key.upper().replace("J", "I")
    seen = set()
    matrix = []

    for c in key:
        if c.isalpha() and c not in seen:
            matrix.append(c)
            seen.add(c)

    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen:
            matrix.append(c)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_pos(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c

def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = ''.join(c for c in text if c.isalpha())
    result = ""
    i = 0
    while i < len(text):
        result += text[i]
        if i+1 < len(text) and text[i] == text[i+1]:
            result += "X"
            i += 1
        elif i+1 < len(text):
            result += text[i+1]
            i += 2
        else:
            result += "X"
            i += 1
    return result

def playfair_encrypt(text, key):
    matrix = generate_matrix(key)
    text = prepare_text(text)
    out = ""

    for i in range(0, len(text), 2):
        r1,c1 = find_pos(matrix, text[i])
        r2,c2 = find_pos(matrix, text[i+1])

        if r1 == r2:
            out += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
        elif c1 == c2:
            out += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
        else:
            out += matrix[r1][c2] + matrix[r2][c1]
    return out

def playfair_decrypt(text, key):
    matrix = generate_matrix(key)
    text = text.upper()
    out = ""

    for i in range(0, len(text), 2):
        r1,c1 = find_pos(matrix, text[i])
        r2,c2 = find_pos(matrix, text[i+1])

        if r1 == r2:
            out += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2:
            out += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else:
            out += matrix[r1][c2] + matrix[r2][c1]
    return out

# ================= GUI APP =================

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Classical Cryptography Tool – Caesar & Playfair Cipher")
        self.geometry("1000x720")
        self.minsize(900, 680)
        self.resizable(True, True)

        try:
            self.state("zoomed")
        except:
            pass

        self.cipher = ctk.StringVar(value="Caesar")
        self.build_ui()

    def build_ui(self):
        ctk.CTkLabel(
            self, text="Classical Cryptography Tool",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=(20, 5))

        ctk.CTkLabel(
            self,
            text="Caesar & Playfair Cipher Encryption / Decryption (Modern GUI)",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 20))

        switch_frame = ctk.CTkFrame(self)
        switch_frame.pack(pady=10)

        ctk.CTkRadioButton(
            switch_frame, text="Caesar Cipher",
            variable=self.cipher, value="Caesar",
            command=self.update_ui
        ).pack(side="left", padx=30)

        ctk.CTkRadioButton(
            switch_frame, text="Playfair Cipher",
            variable=self.cipher, value="Playfair",
            command=self.update_ui
        ).pack(side="left", padx=30)

        self.dynamic = ctk.CTkFrame(self)
        self.dynamic.pack(padx=30, pady=15, fill="both", expand=True)

        # ---------- Output Section ----------
        output_frame = ctk.CTkFrame(self)
        output_frame.pack(padx=30, pady=10, fill="x")

        ctk.CTkLabel(
            output_frame, text="Output",
            font=ctk.CTkFont(weight="bold")
        ).pack(anchor="w", padx=10, pady=(5, 0))

        self.output = ctk.CTkTextbox(output_frame, height=130)
        self.output.pack(padx=10, pady=5, fill="x")

        self.copy_btn = ctk.CTkButton(
            output_frame, text="📋 Copy to Clipboard",
            command=self.copy_output
        )
        self.copy_btn.pack(pady=(10, 5))

        # STATUS MESSAGE (VISIBLE BELOW COPY BUTTON)
        self.status = ctk.CTkLabel(
            output_frame,
            text="Ready",
            text_color="green"
        )
        self.status.pack(pady=(0, 10))

        self.update_ui()

    def clear(self):
        for w in self.dynamic.winfo_children():
            w.destroy()

    def update_ui(self):
        self.clear()
        if self.cipher.get() == "Caesar":
            self.caesar_ui()
        else:
            self.playfair_ui()

    # -------- Caesar UI --------
    def caesar_ui(self):
        self.c_text = ctk.CTkTextbox(self.dynamic, height=160)
        self.c_text.pack(padx=20, pady=15, fill="x")

        self.shift = ctk.CTkEntry(
            self.dynamic,
            placeholder_text="Shift Key (Numbers only)"
        )
        self.shift.pack(padx=20, pady=10)

        btn = ctk.CTkFrame(self.dynamic)
        btn.pack(pady=15)

        ctk.CTkButton(btn, text="Encrypt", command=self.caesar_encrypt).pack(side="left", padx=20)
        ctk.CTkButton(btn, text="Decrypt", command=self.caesar_decrypt).pack(side="left", padx=20)

    def caesar_encrypt(self):
        try:
            text = self.c_text.get("1.0","end").strip()
            shift = int(self.shift.get())
            result = caesar_encrypt(text, shift)
            self.show_result(result, "Caesar Encryption Successful")
            messagebox.showinfo("Success", "Caesar Encryption completed successfully!")
        except:
            messagebox.showerror("Error", "Please enter a valid numeric shift key")

    def caesar_decrypt(self):
        try:
            text = self.c_text.get("1.0","end").strip()
            shift = int(self.shift.get())
            result = caesar_decrypt(text, shift)
            self.show_result(result, "Caesar Decryption Successful")
            messagebox.showinfo("Success", "Caesar Decryption completed successfully!")
        except:
            messagebox.showerror("Error", "Please enter a valid numeric shift key")

    # -------- Playfair UI --------
    def playfair_ui(self):
        self.p_key = ctk.CTkEntry(
            self.dynamic,
            placeholder_text="Enter Playfair Key"
        )
        self.p_key.pack(padx=20, pady=10, fill="x")

        self.p_text = ctk.CTkTextbox(self.dynamic, height=160)
        self.p_text.pack(padx=20, pady=15, fill="x")

        btn = ctk.CTkFrame(self.dynamic)
        btn.pack(pady=15)

        ctk.CTkButton(btn, text="Encrypt", command=self.playfair_encrypt).pack(side="left", padx=20)
        ctk.CTkButton(btn, text="Decrypt", command=self.playfair_decrypt).pack(side="left", padx=20)

    def playfair_encrypt(self):
        if not self.p_key.get():
            messagebox.showerror("Error", "Playfair key is required")
            return
        result = playfair_encrypt(self.p_text.get("1.0","end"), self.p_key.get())
        self.show_result(result, "Playfair Encryption Successful")
        messagebox.showinfo("Success", "Playfair Encryption completed successfully!")

    def playfair_decrypt(self):
        if not self.p_key.get():
            messagebox.showerror("Error", "Playfair key is required")
            return
        result = playfair_decrypt(self.p_text.get("1.0","end"), self.p_key.get())
        self.show_result(result, "Playfair Decryption Successful")
        messagebox.showinfo("Success", "Playfair Decryption completed successfully!")

    def show_result(self, text, status_msg):
        self.output.delete("1.0","end")
        self.output.insert("1.0", text)
        self.status.configure(text=status_msg)

    def copy_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.output.get("1.0","end").strip())
        self.status.configure(text="Output copied to clipboard successfully")
        messagebox.showinfo("Copied", "Encrypted/Decrypted text copied to clipboard!")

# ================= RUN =================

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
