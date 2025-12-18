import customtkinter as ctk
from tkinter import messagebox, simpledialog
import re, random, hashlib, json, time, os
DATA_FILE = "users.json"

def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users():
    with open(DATA_FILE, "w") as f:
        json.dump(users, f, indent=4)



def upgrade_old_users_format():
    global users
    changed = False
    for username, value in list(users.items()):
       
        if isinstance(value, str):
            users[username] = {
                "password": value,
                "dob": "",
                "mobile": ""
            }
            changed = True
    if changed:
        save_users()

users = load_users()
upgrade_old_users_format()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[@$!%*#?&]", password): score += 1
    return min(score, 4)

def register_user():
    user = entry_user.get()
    pwd = entry_pass.get()
    dob = entry_dob.get()
    mobile = entry_mobile.get()

    if not user or not pwd or not dob or not mobile:
        messagebox.showerror("Error", "Please fill all fields.")
        return

    if user in users:
        messagebox.showerror("Error", "User already exists!")
        return

    users[user] = {
        "password": hash_password(pwd),
        "dob": dob,
        "mobile": mobile
    }
    save_users()
    messagebox.showinfo("Success", "Account created successfully!")

def login_user():
    user = entry_user.get()
    pwd = entry_pass.get()

    if user in users and users[user]["password"] == hash_password(pwd):
        messagebox.showinfo("Success", "Login Successful!")
    else:
        messagebox.showerror("Error", "Invalid username or password.")

def forgot_password():
    user = entry_user.get()
    if user not in users:
        messagebox.showerror("Error", "User not found!")
        return

    otp = str(random.randint(100000, 999999))
    otp_time = time.time()
    fake_sms_popup(otp) 
    attempts = 0

    while attempts < 3:
        entered = simpledialog.askstring("OTP Verification", f"Enter OTP (Attempt {attempts+1}/3):")
        if not entered:
            return
        if time.time() - otp_time > 30:
            messagebox.showerror("Error", "OTP expired! Please request again.")
            return
        if entered == otp:
            new_pwd = simpledialog.askstring("Reset Password", "Enter new password:")
            if not new_pwd:
                return
            users[user]["password"] = hash_password(new_pwd)
            save_users()
            messagebox.showinfo("Success", "Password reset successful!")
            return
        else:
            messagebox.showerror("Error", "Incorrect OTP!")
            attempts += 1
    messagebox.showerror("Error", "Too many failed attempts!")

def forgot_username():

    dob = simpledialog.askstring("Recover Username", "Enter your Date of Birth (DD-MM-YYYY):", show="*")
    mobile = simpledialog.askstring("Recover Username", "Enter your registered Mobile Number:", show="*")

    if not dob or not mobile:
        messagebox.showerror("Error", "Both fields are required.")
        return

    for user, details in users.items():
        if details.get("dob") == dob and details.get("mobile") == mobile:
            messagebox.showinfo("Username Found", f"✅ Your username is: {user}")
            return

    messagebox.showerror("Error", "No account found with the provided details.")

def fake_sms_popup(otp):
    sms = ctk.CTkToplevel(app)
    sms.geometry("250x150")
    sms.title("📱 SMS Notification")
    sms_label = ctk.CTkLabel(sms, text=f"From: OTP_Service\n\nYour OTP is: {otp}\n\nValid for 30s", wraplength=200)
    sms_label.pack(padx=20, pady=20)
    ctk.CTkButton(sms, text="Close", command=sms.destroy).pack(pady=5)

app = ctk.CTk()
app.title("Password Manager")
app.geometry("400x550")
ctk.set_appearance_mode("system")

frame = ctk.CTkFrame(app, corner_radius=15)
frame.pack(padx=20, pady=30, fill="both", expand=True)

ctk.CTkLabel(frame, text="🔐 Password Manager", font=("Arial", 20, "bold")).pack(pady=15)

entry_user = ctk.CTkEntry(frame, placeholder_text="Enter Username")
entry_user.pack(pady=8)

entry_pass = ctk.CTkEntry(frame, placeholder_text="Enter Password", show="*")
entry_pass.pack(pady=8)

entry_dob = ctk.CTkEntry(frame, placeholder_text="Enter DOB (DD-MM-YYYY)", show="*")
entry_dob.pack(pady=8)

entry_mobile = ctk.CTkEntry(frame, placeholder_text="Enter Mobile Number", show="*")
entry_mobile.pack(pady=8)

strength_label = ctk.CTkLabel(frame, text="Strength: -")
strength_label.pack()

def update_strength(event):
    pwd = entry_pass.get()
    s = check_strength(pwd)
    levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    strength_label.configure(text=f"Strength: {levels[s]}")

entry_pass.bind("<KeyRelease>", update_strength)

ctk.CTkButton(frame, text="Register", command=register_user, fg_color="#0078D7").pack(pady=5)
ctk.CTkButton(frame, text="Login", command=login_user, fg_color="#4CAF50").pack(pady=5)
ctk.CTkButton(frame, text="Forgot Password", command=forgot_password, fg_color="#FFA000").pack(pady=5)
ctk.CTkButton(frame, text="Forgot Username", command=forgot_username, fg_color="#9C27B0").pack(pady=5)

app.mainloop()