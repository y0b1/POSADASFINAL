import tkinter as tk  # Import the Tkinter module for GUI
import os  # Import the os module for handling file paths

def caesar_cipher(text, shift):
    """
    Function to perform Caesar Cipher encryption or decryption.
    """
    result = ""  # Initialize an empty string to store the result
    for char in text:
        if char.isalpha():  # Check if the character is alphabetic
            shifted = ord(char) + shift  # Shift the character in ASCII value
            if char.islower():  # Check if the character is lowercase
                if shifted > ord('z'):  # Wrap around if shifted beyond 'z'
                    shifted -= 26
                elif shifted < ord('a'):  # Wrap around if shifted before 'a'
                    shifted += 26
            elif char.isupper():  # Check if the character is uppercase
                if shifted > ord('Z'):  # Wrap around if shifted beyond 'Z'
                    shifted -= 26
                elif shifted < ord('A'):  # Wrap around if shifted before 'A'
                    shifted += 26
            result += chr(shifted)  # Append the shifted character to the result
        else:
            result += char  # If the character is not alphabetic, keep it unchanged
    return result  # Return the encrypted or decrypted text

def encrypt():
    """
    Function to encrypt the entered text.
    """
    plaintext = entry_text.get()  # Get the text entered by the user
    shift = int(entry_shift.get())  # Get the shift value entered by the user
    ciphertext = caesar_cipher(plaintext, shift)  # Encrypt the text
    result_label.config(text="Encrypted Text: " + ciphertext)  # Update result label

def decrypt():
    """
    Function to decrypt the entered text.
    """
    ciphertext = entry_text.get()  # Get the text entered by the user
    shift = -int(entry_shift.get())  # Get the negative shift value for decryption
    plaintext = caesar_cipher(ciphertext, shift)  # Decrypt the text
    result_label.config(text="Decrypted Text: " + plaintext)  # Update result label

def reset():
    """
    Function to reset input fields and result label.
    """
    entry_text.delete(0, tk.END)  # Clear the text entry field
    entry_shift.delete(0, tk.END)  # Clear the shift entry field
    result_label.config(text="")  # Clear the result label

def copy_result():
    """
    Function to copy the result to the clipboard.
    """
    result = result_label.cget("text")  # Get the text from the result label
    result_text = result.split(": ")[1]  # Extract the actual result text
    root.clipboard_clear()  # Clear the clipboard
    root.clipboard_append(result_text)  # Append the result text to the clipboard
    copy_label.config(text="Result copied to clipboard.")  # Update copy confirmation label

def validate_shift_input(char):
    """
    Function to validate input for shift entry field.
    """
    return char.isdigit() or char == "\b"  # Allow only digits and backspace

# Create Tkinter window
root = tk.Tk()  # Create the main window
root.title("Caesar Cipherinator")  # Set the window title

# Set window icon
icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")  # Get the path to the icon file
root.iconbitmap(icon_path)  # Set the window icon

# Make window larger
root.geometry("500x300")  # Set the initial window size

# Create input fields
text_label = tk.Label(root, text="Enter text:")  # Create label for text entry
text_label.place(relx=0.5, rely=0.2, anchor=tk.CENTER)  # Position label in the middle

entry_text = tk.Entry(root, width=50)  # Create text entry field with increased width
entry_text.place(relx=0.5, rely=0.3, anchor=tk.CENTER)  # Position text entry field

shift_label = tk.Label(root, text="Enter shift:")  # Create label for shift entry
shift_label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)  # Position label in the middle

# Validation for shift entry field
validate_shift = root.register(validate_shift_input)  # Register validation function
entry_shift = tk.Entry(root, width=10, validate="key", validatecommand=(validate_shift, "%S"))  # Create shift ent
