import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed  # Use ThreadPoolExecutor instead of ProcessPoolExecutor
import bcrypt
from passlib.hash import nthash
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

# -------------------------------
# Supported hash types
hash_name = [
    'md5', 'sha1', 'sha224', 'sha256', 'sha384',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
    'sha512', 'bcrypt', 'ntlm', 'salted'
]

# -------------------------------
# Password generator
def generate_passwords(min_length, max_length, characters):
    for length in range(min_length, max_length + 1):
        for pwd in itertools.product(characters, repeat=length):
            yield ''.join(pwd)

# -------------------------------
# Check if password matches hash
def check_hash(hash_type, password, target_hash, salt=None, salt_pos='prefix', salted_alg='sha256'):
    password_bytes = password.encode()

    if hash_type in hashlib.algorithms_available:
        return getattr(hashlib, hash_type)(password_bytes).hexdigest() == target_hash

    elif hash_type == 'bcrypt':
        return bcrypt.checkpw(password_bytes, target_hash.encode())

    elif hash_type == 'ntlm':
        return nthash.hash(password) == target_hash

    elif hash_type == 'salted':
        if not salt:
            return False
        salt_bytes = salt.encode()
        candidate = (salt_bytes + password_bytes) if salt_pos == 'prefix' else (password_bytes + salt_bytes)
        return getattr(hashlib, salted_alg)(candidate).hexdigest() == target_hash

    return False

# -------------------------------
# Check a batch of passwords
def check_chunk(chunk, hash_type, target_hash, salt, salt_pos, salted_alg, progress_callback=None):
    for pwd in chunk:
        if progress_callback:
            progress_callback(current=pwd)
        if check_hash(hash_type, pwd, target_hash, salt, salt_pos, salted_alg):
            return pwd
    return None

# -------------------------------
# Crack hash function with optional progress callback
def crack_hash(target_hash, wordlist=None, hash_type='md5', min_length=0, max_length=0,
               characters=string.ascii_letters + string.digits + string.punctuation,
               max_workers=4, salt=None, salt_pos='prefix', salted_alg='sha256',
               chunk_size=1000, progress_callback=None):

    if hash_type not in hash_name:
        raise ValueError(f'[!] Invalid hash type: {hash_type} supported are {hash_name}')

    # --- Wordlist Mode ---
    if wordlist:
        with open(wordlist, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        total_lines = len(lines)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:  # Changed to ThreadPoolExecutor
            futures = {executor.submit(check_hash, hash_type, line, target_hash, salt, salt_pos, salted_alg): line for line in lines}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if progress_callback:
                    progress_callback(percent=(completed / total_lines) * 100)
                if future.result():
                    return futures[future]

    # --- Brute Force Mode ---
    elif min_length > 0 and max_length > 0:
        total_combinations = sum(len(characters) ** length for length in range(min_length, max_length + 1))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:  # Changed to ThreadPoolExecutor
            futures = []
            batch = []
            processed = 0

            for pwd in generate_passwords(min_length, max_length, characters):
                batch.append(pwd)
                if len(batch) >= chunk_size:
                    futures.append(executor.submit(check_chunk, batch.copy(), hash_type, target_hash, salt, salt_pos, salted_alg, progress_callback))
                    batch.clear()

                processed += 1
                if progress_callback:
                    progress_callback(percent=(processed / total_combinations) * 100)

                for f in list(futures):
                    if f.done():
                        result = f.result()
                        if result:
                            return result
                        futures.remove(f)

            if batch:
                futures.append(executor.submit(check_chunk, batch, hash_type, target_hash, salt, salt_pos, salted_alg, progress_callback))

            for f in as_completed(futures):
                result = f.result()
                if result:
                    return result

    return None

# -------------------------------
# GUI
class HashCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Hash Cracker GUI")
        self.root.geometry("650x600")

        tk.Label(root, text="Hash to Crack:").pack(anchor='w', padx=10, pady=2)
        self.hash_entry = tk.Entry(root, width=80)
        self.hash_entry.pack(padx=10, pady=2)

        tk.Label(root, text="Hash Type:").pack(anchor='w', padx=10, pady=2)
        self.hash_type_var = tk.StringVar(value='md5')
        tk.OptionMenu(root, self.hash_type_var, *hash_name).pack(padx=10, pady=2, anchor='w')

        tk.Label(root, text="Wordlist (optional):").pack(anchor='w', padx=10, pady=2)
        frame = tk.Frame(root)
        frame.pack(padx=10, pady=2, fill='x')
        self.wordlist_entry = tk.Entry(frame, width=60)
        self.wordlist_entry.pack(side='left', padx=5)
        tk.Button(frame, text="Browse", command=self.browse_wordlist).pack(side='left')

        tk.Label(root, text="Min Length (for brute-force):").pack(anchor='w', padx=10, pady=2)
        self.min_length_entry = tk.Entry(root)
        self.min_length_entry.pack(padx=10, pady=2, anchor='w')

        tk.Label(root, text="Max Length (for brute-force):").pack(anchor='w', padx=10, pady=2)
        self.max_length_entry = tk.Entry(root)
        self.max_length_entry.pack(padx=10, pady=2, anchor='w')

        tk.Label(root, text="Characters to use (include special chars):").pack(anchor='w', padx=10, pady=2)
        self.characters_entry = tk.Entry(root, width=80)
        self.characters_entry.insert(0, string.ascii_letters + string.digits + string.punctuation)
        self.characters_entry.pack(padx=10, pady=2)

        tk.Label(root, text="Salt (optional):").pack(anchor='w', padx=10, pady=2)
        self.salt_entry = tk.Entry(root, width=80)
        self.salt_entry.pack(padx=10, pady=2)

        tk.Label(root, text="Salt Position:").pack(anchor='w', padx=10, pady=2)
        self.salt_pos_var = tk.StringVar(value='prefix')
        tk.OptionMenu(root, self.salt_pos_var, 'prefix', 'suffix').pack(padx=10, pady=2, anchor='w')

        tk.Label(root, text="Algorithm for Salted Hash (if applicable):").pack(anchor='w', padx=10, pady=2)
        self.salted_alg_entry = tk.Entry(root)
        self.salted_alg_entry.insert(0, 'sha256')
        self.salted_alg_entry.pack(padx=10, pady=2, anchor='w')

        tk.Button(root, text="Start Cracking", command=self.start_cracking).pack(pady=10)

        self.progress = ttk.Progressbar(root, orient='horizontal', length=600, mode='determinate')
        self.progress.pack(padx=10, pady=5)

        tk.Label(root, text="Current Password Tried:").pack(anchor='w', padx=10, pady=2)
        self.current_pwd_label = tk.Label(root, text="", fg="blue")
        self.current_pwd_label.pack(anchor='w', padx=10, pady=2)

        tk.Label(root, text="Output:").pack(anchor='w', padx=10, pady=2)
        self.output_text = tk.Text(root, height=12)
        self.output_text.pack(padx=10, pady=2, fill='both', expand=True)

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(title="Select Wordlist",
                                              filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, filename)

    def start_cracking(self):
        threading.Thread(target=self.crack).start()

    def update_progress(self, percent=0, current=None):
        self.progress['value'] = percent
        if current:
            self.current_pwd_label.config(text=current)
        self.root.update_idletasks()

    def crack(self):
        self.output_text.delete(1.0, tk.END)
        self.progress['value'] = 0
        self.current_pwd_label.config(text="")

        target_hash = self.hash_entry.get().strip()
        wordlist = self.wordlist_entry.get().strip() or None
        hash_type = self.hash_type_var.get()
        min_length = int(self.min_length_entry.get() or 0)
        max_length = int(self.max_length_entry.get() or 0)
        characters = self.characters_entry.get().strip() or string.ascii_letters + string.digits + string.punctuation
        salt = self.salt_entry.get().strip() or None
        salt_pos = self.salt_pos_var.get()
        salted_alg = self.salted_alg_entry.get().strip() or 'sha256'

        if not target_hash:
            messagebox.showerror("Error", "Please enter a hash to crack")
            return

        self.output_text.insert(tk.END, "[*] Cracking started...\n")
        self.output_text.update()

        try:
            result = crack_hash(
                target_hash,
                wordlist=wordlist,
                hash_type=hash_type,
                min_length=min_length,
                max_length=max_length,
                characters=characters,
                salt=salt,
                salt_pos=salt_pos,
                salted_alg=salted_alg,
                max_workers=4,
                progress_callback=self.update_progress
            )
            if result:
                self.output_text.insert(tk.END, f"[+] Password found: {result}\n")
                self.update_progress(100, result)
            else:
                self.output_text.insert(tk.END, "[!] Password not found.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"[!] Error: {e}\n")

# -------------------------------
if __name__ == '__main__':
    root = tk.Tk()
    app = HashCrackerGUI(root)
    root.mainloop()
