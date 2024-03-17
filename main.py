import tkinter as tk
from tkinter import messagebox  # Import messagebox module
import os

def read_password_from_file():
    """
    Function to read the password from the text file.
    """
    with open("password.txt", "r") as file:
        return file.readline().strip()  # Read the password and remove leading/trailing whitespace

def authenticate():
    """
    Function to authenticate the user with a password.
    """
    password = read_password_from_file()  # Read the password from the file
    user_password = password_entry.get()  # Get the password entered by the user
    if user_password == password:  # Check if the entered password matches the stored password
        main_window()  # Call the main window function if authentication succeeds
    else:
        messagebox.showerror("Error", "Incorrect password!")  # Show error message if authentication fails

def main_window():
    """
    Function to create the main application window.
    """
    global root
    root = tk.Tk()
    root.title("Gaius Julius Caesar Cipherinator - PRO MAX ULTRA")
    icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
    root.iconbitmap(icon_path)
    root.geometry("500x300")

    # Create input fields
    text_label = tk.Label(root, text="Enter text:")
    text_label.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

    global entry_text, entry_shift, result_label
    entry_text = tk.Entry(root, width=50)
    entry_text.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

    shift_label = tk.Label(root, text="Enter shift:")
    shift_label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

    validate_shift = root.register(validate_shift_input)
    entry_shift = tk.Entry(root, width=10, validate="key", validatecommand=(validate_shift, "%S"))
    entry_shift.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    # Create buttons for encryption, decryption, reset, and copy
    encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
    encrypt_button.place(relx=0.35, rely=0.6, anchor=tk.CENTER)

    decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
    decrypt_button.place(relx=0.5, rely=0.6, anchor=tk.CENTER)

    reset_button = tk.Button(root, text="Reset", command=reset)
    reset_button.place(relx=0.65, rely=0.6, anchor=tk.CENTER)

    copy_button = tk.Button(root, text="Copy Result", command=copy_result)
    copy_button.place(relx=0.5, rely=0.7, anchor=tk.CENTER)

    # Label to display result
    result_label = tk.Label(root, text="")
    result_label.place(relx=0.5, rely=0.8, anchor=tk.CENTER)

    root.mainloop()

def caesar_cipher(text, shift):
    """
    Function to perform Caesar Cipher encryption or decryption.
    """
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def encrypt():
    """
    Function to encrypt the entered text.
    """
    plaintext = entry_text.get()
    shift = int(entry_shift.get())
    ciphertext = caesar_cipher(plaintext, shift)
    result_label.config(text="Encrypted Text: " + ciphertext)

def decrypt():
    """
    Function to decrypt the entered text.
    """
    ciphertext = entry_text.get()
    shift = -int(entry_shift.get())
    plaintext = caesar_cipher(ciphertext, shift)
    result_label.config(text="Decrypted Text: " + plaintext)

def reset():
    """
    Function to reset input fields and result label.
    """
    entry_text.delete(0, tk.END)
    entry_shift.delete(0, tk.END)
    result_label.config(text="")

def copy_result():
    """
    Function to copy the result to the clipboard.
    """
    result = result_label.cget("text")
    result_text = result.split(": ")[1]
    root.clipboard_clear()
    root.clipboard_append(result_text)
    copy_label.config(text="Result copied to clipboard.")

def validate_shift_input(char):
    """
    Function to validate input for shift entry field.
    """
    return char.isdigit() or char == "\b"

# Create Tkinter window for password input
password_window = tk.Tk()
password_window.title("Enter Password")
password_window.geometry("300x100")

password_label = tk.Label(password_window, text="Enter Password:")
password_label.pack()

password_entry = tk.Entry(password_window, show="*")
password_entry.pack()

authenticate_button = tk.Button(password_window, text="Authenticate", command=authenticate)
authenticate_button.pack()

password_window.mainloop()
