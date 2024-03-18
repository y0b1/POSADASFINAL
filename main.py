import tkinter as tk  #mainwindow
from tkinter import messagebox  #errorbox
import os  #filehandling

# The code doesn't use classes because it's simple and functions adequately without them.

def readpassfromfile():
    """
    Function to read the password from the text file.
    """
    with open("password.txt", "r") as file:
        return file.readline().strip()  # The strip() helps you remove these whitespace characters.

def authenticate():
    """
    Function to authenticate the user with a password.
    """
    password = readpassfromfile()  # Read password from file
    user_password = passwordentry.get()  # Get password entered by user
    if user_password == password:  # Check if entered password matches stored password
        mainwindow()  # Call mainwin function if authentication succeeds
    else:
        messagebox.showerror("Error", "Incorrect password!")  #errorbox

def mainwindow():
    """
    Function to create the main application window.
    """
    global mainwin  # mainwin global var
    mainwin = tk.Tk()  # new window
    mainwin.title("Gaius Julius Caesar Cipherinator - PRO MAX ULTRA")
#icon
    iconpath = os.path.join(os.path.dirname(__file__), "icon.ico")
    """os.path.dirname(__file__): os.path.dirname() returns the directory name of a path. 
    __file__ is a special variable in Python that holds the path of the current script.
    os.path.dirname(__file__) gives the directory containing the current script.
    os.path.join(): This function joins one or more path components intelligently. It's used here to join the directory containing the current script with the filename."""
    mainwin.iconbitmap(iconpath)  #seticon
    mainwin.geometry("500x300") #windowsize
#input fields
    textlabel = tk.Label(mainwin, text="Enter text:")  # Create label for text entry
    textlabel.place(relx=0.5, rely=0.2, anchor=tk.CENTER)  # Place text label in window

    global entrytext, entryshift, resultlabel  #entrytext, entryshift, and resultlabel as global variables
    entrytext = tk.Entry(mainwin, width=50)  # Create entry widget for text input
    entrytext.place(relx=0.5, rely=0.3, anchor=tk.CENTER)  # Place text entry widget in window

    shiftlabel = tk.Label(mainwin, text="Enter shift(up to 25):")  # Create label for shift entry
    shiftlabel.place(relx=0.5, rely=0.4, anchor=tk.CENTER)  # Place shift label in window

    validateshift = mainwin.register(validateshiftinput)  # Register function for validating shift input
    entryshift = tk.Entry(mainwin, width=10, validate="key", validatecommand=(validateshift, "%S"))  # Create entry widget for shift input
    entryshift.place(relx=0.5, rely=0.5, anchor=tk.CENTER)  # Place shift entry widget in window

    # Create buttons for encryption, decryption, reset, and copy
    encryptbutton = tk.Button(mainwin, text="Encrypt", command=encrypt)  # Create button for encryption
    encryptbutton.place(relx=0.35, rely=0.6, anchor=tk.CENTER)  # Place encryption button in window

    decryptbutton = tk.Button(mainwin, text="Decrypt", command=decrypt)  # Create button for decryption
    decryptbutton.place(relx=0.5, rely=0.6, anchor=tk.CENTER)  # Place decryption button in window

    resetbutton = tk.Button(mainwin, text="Reset", command=reset)  # Create button for reset
    resetbutton.place(relx=0.65, rely=0.6, anchor=tk.CENTER)  # Place reset button in window

    copybutton = tk.Button(mainwin, text="Copy Result", command=copyresult)  # Create button for copying result
    copybutton.place(relx=0.5, rely=0.7, anchor=tk.CENTER)  # Place copy button in window

    # Label to display result
    resultlabel = tk.Label(mainwin, text="")  # Create label for displaying result
    resultlabel.place(relx=0.5, rely=0.8, anchor=tk.CENTER)  # Place result label in window

    mainwin.mainloop()  # Start the main event loop

def caesarcipher(text, shift):
    """
    Function to perform Caesar Cipher encryption or decryption.
    """
    result = ""  # Initialize an empty string for the result
    for char in text:  # Iterate through each character in the text
        if char.isalpha():  # Check if the character is alphabetic
            shifted = ord(char) + shift  # Calculate the shifted character's ASCII value
            if char.islower():  # If the character is lowercase
                if shifted > ord('z'):  # If the shifted character exceeds 'z'
                    shifted -= 26  # Wrap around to the beginning of the alphabet
                elif shifted < ord('a'):  # If the shifted character is less than 'a'
                    shifted += 26  # Wrap around to the end of the alphabet
            elif char.isupper():  # If the character is uppercase
                if shifted > ord('Z'):  # If the shifted character exceeds 'Z'
                    shifted -= 26  # Wrap around to the beginning of the alphabet
                elif shifted < ord('A'):  # If the shifted character is less than 'A'
                    shifted += 26  # Wrap around to the end of the alphabet
            result += chr(shifted)  # Append the shifted character to the result string
        else:
            result += char  # If the character is not alphabetic, append it to the result string
    return result  # Return the resulting string

def encrypt():
    """
    Function to encrypt the entered text.
    """
    plaintext = entrytext.get()  # Get the plaintext from the entry widget
    shift = int(entryshift.get())  # Get the shift value from the entry widget
    ciphertext = caesarcipher(plaintext, shift)  # Encrypt the plaintext using Caesar Cipher
    resultlabel.config(text="Encrypted Text: " + ciphertext)  # Update the result label with the encrypted text

def decrypt():
    """
    Function to decrypt the entered text.
    """
    ciphertext = entrytext.get()  # Get the ciphertext from the entry widget
    shift = -int(entryshift.get())  # Get the negative shift value from the entry widget for decryption
    plaintext = caesarcipher(ciphertext, shift)  # Decrypt the ciphertext using Caesar Cipher
    resultlabel.config(text="Decrypted Text: " + plaintext)  # Update the result label with the decrypted text

def reset():
    """
    Function to reset input fields and result label.
    """
    entrytext.delete(0, tk.END)  # Clear the text entry widget
    entryshift.delete(0, tk.END)  # Clear the shift entry widget
    resultlabel.config(text="")  # Clear the result label

def copyresult():
    """
    Function to copy the result to the clipboard.
    """
    result = resultlabel.cget("text")  # Get the text from the result label
    resulttext = result.split(": ")[1]  # Extract the result text
    mainwin.clipboard_clear()  # Clear the clipboard
    mainwin.clipboard_append(resulttext)  # Append the result text to the clipboard

def validateshiftinput(char):
    """
    Function to validate input for shift entry field.
    """
    return char.isdigit() or char == "\b"  # Allow digits and backspace for shift input

# Create Tkinter window for password input
passwordwindow = tk.Tk()  # Create a new Tkinter window for password input
passwordwindow.title("Enter Password")  # Set window title
passwordwindow.geometry("300x100") # Sets the window size
# Set window icon for password window
password_icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")  # Get the path to the icon file
passwordwindow.iconbitmap(password_icon_path)  # Set the window icon

passwordlabel = tk.Label(passwordwindow, text="Enter Password:")  #label for password entry
passwordlabel.pack()  # Pack password label in window

passwordentry = tk.Entry(passwordwindow, show="*")  # Create entry widget for password input
passwordentry.pack()  # Pack password entry widget in window

authenticatebutton = tk.Button(passwordwindow, text="Authenticate", command=authenticate)  # Create button for authentication
authenticatebutton.pack()  # Pack authentication button in window

passwordwindow.mainloop()  # Start the main event loop for the password window
