import tkinter as tk #importing tkinter to create ui
import customtkinter as ctk #importing customtkinter to customise ui
from tkinter import filedialog #using tkinter to import filedialog to open files
import explorer#to get file path
import RSA#RSA algorithm
import os
import HLCS#own algorithm
import hashlib#to hash passwords


print("CRYPTOGRAPHY PROGRAM INITIATED...")
#using customtkinter to set mode (light or dark)
ctk.set_appearance_mode("dark")
#using customtkinter to set theme color to blue
ctk.set_default_color_theme("green")

#setting root to the customtkinter and customising the frame(ui) size
root = ctk.CTk()
root.title("CRYPTOGRAPHY")
root.geometry("600x400")

#frame position and creation
frame = ctk.CTkFrame(root)
frame.pack(pady=20, padx=60, fill="both", expand=True)#position of the fram
#start of frame1---------------------
#Heading in frame
heading = ctk.CTkLabel(frame, text="CRYPTOGRAPHY", font=("Arial", 24))
heading.pack(pady=12, padx=10)#position of heading in frame

#frame0 to choose the algorithm------
frame0 = ctk.CTkFrame(frame)
frame0.pack(padx=12, pady=10)

#label for segmented button
labelchoose = ctk.CTkLabel(frame0, text="Choose algorithm:",font=("Arial", 15))
labelchoose.pack(side="left", padx=5)

#function to check the data value selected in the segmented button
def segbutton(value):
    global val
    if (value == "HLCS Encryption"):
        val = "HLCS Encryption"
    else:
        val = "RSA Encryption"
    return val

#segmented button to choose which algorithm will be used
segementedButtonEncryptr = ctk.CTkSegmentedButton(frame0,values=["HLCS Encryption", "RSA Encryption"], command=segbutton)
segementedButtonEncryptr.pack(side="left", padx=5)
#end of frame0-----------------------

labelEncrypt = ctk.CTkLabel(frame, text="Encryption", font=("Arial", 20))
labelEncrypt.pack(pady=12, padx=10)

#start of frame2----------------------
frame2 = ctk.CTkFrame(frame)
frame2.pack(padx=12, pady=10)

labelEncrypt = ctk.CTkLabel(frame2, text="select file:", font=("Arial", 15))
labelEncrypt.pack(side="left", padx=5)

#browse_files function
def browse_files():
    global file_path#glonal variable "file_path" is created
    file_path = explorer.browse_files()# file_path retrieved from retrun value from the
    #browse files function in the explorer class

    #this function is created alongside the encrypt button after the
    #select file button is clicked
    def clickEncrypt():
        if (val == "HLCS Encryption"):
            #creating an input box to retrieve the password from user
            dialog = ctk.CTkInputDialog(text="provide password:", title="Password")
            dialogWidth = dialog.winfo_reqwidth()
            dialogHeight = dialog.winfo_reqheight()
            dialog.geometry("200x200")
            password = dialog.get_input()#getting password data from dialogbox

            #hassing password
            passwordBytes = password.encode('utf-8')#converting data to bytes format
            hashedObject = hashlib.sha256()#using sha256 from hashlib to hash the password
            hashedObject.update(passwordBytes)#hashed object is updated with bytes from password
            hashedPassword = hashedObject.hexdigest()#converts hash data to hexadecimal data
            #encryption with HLCS
            encrypted_path = HLCS.encrypt_file(file_path, hashedPassword)#file
            #is encrypted and encryptedfile_path is returned
            encrypted_filename = os.path.basename(encrypted_path)#getting
            #file name from the file_path
            print("file encrypted successfully: " + encrypted_filename)
            os.remove(file_path)#removing unencrypted file from directory

        else:
            try:
                #getting password
                dialog = ctk.CTkInputDialog(text="provide password:", title="Password")
                dialogWidth = dialog.winfo_reqwidth()
                dialogHeight = dialog.winfo_reqheight()
                dialog.geometry("200x200")
                password = dialog.get_input()#getting password data from dialogbox
                #hassing password
                passwordBytes = password.encode('utf-8')#converting data to bytes format
                hashedObject = hashlib.sha256()#using sha256 from hashlib to hash the password
                hashedObject.update(passwordBytes)#hashed object is updated with bytes from password
                hashedPassword = hashedObject.hexdigest()#converts hash data to hexadecimal data
                #encryption with RSA
                publickey, privatekey = RSA.generate_keys()#public and private keys are assigned
                binary = RSA.encrypt_file(file_path, publickey)# binary stored from the returned
                #value of the "encrypt_file" function
                RSA.storeKeys(binary, hashedPassword, publickey, privatekey)#store keys function takes the public key and the binary and private key

            except Exception as e:
                print("could not encrypt, error!", e)#exception

    buttonEncrypt = ctk.CTkButton(frame2, text="Encrypt", command=clickEncrypt)
    buttonEncrypt.pack(side="right", padx=5)

buttonBrowse = ctk.CTkButton(frame2, text="Select file", command=browse_files)
buttonBrowse.pack(side="left", padx=5)
#end of frame3---------------------------

#Decrypt title in frame1
labelDecrypt = ctk.CTkLabel(frame, text="Decryption", font=("Arial", 20))
labelDecrypt.pack(pady=12, padx=10)

#start of frame2----------------------
frame3 = ctk.CTkFrame(frame)
frame3.pack(padx=12, pady=10)

labelselect = ctk.CTkLabel(frame3, text="select file:", font=("Arial", 15))
labelselect.pack(side="left", padx=5)
def browse_files():#browse files function
    global file_path
    file_path = explorer.browse_files()# saves returned value from the function in variable
    #as file_path

    def decrypt_file():
        global val
        if (val == "HLCS Encryption"):
            #creating dialog box fro password
            dialog = ctk.CTkInputDialog(text="provide password:", title="Password")
            dialogWidth = dialog.winfo_reqwidth()
            dialogHeight = dialog.winfo_reqheight()
            dialog.geometry("200x200")#size of box
            password = dialog.get_input()#asssigning value to password variable

            passwordBytes = password.encode('utf-8')#converting to bytes
            hashedObject = hashlib.sha256()#creating hash object with hashlib.sha256
            hashedObject.update(passwordBytes)#updating object with passwordBytes
            hashedPassword2 = hashedObject.hexdigest()#converting hashedObject to hexadecimal data

            decrypted_path = HLCS.decrypt_file(file_path, hashedPassword2)#getting the decrypted file path from decrypt_file function
            decrypted_filename = os.path.basename(decrypted_path)#extracting just file name
            print("file decrypted successfully: " + decrypted_filename)
            os.remove(file_path)#removing encrypted file from directory

        else:
            #getting password
            #creating dialog box for password
            dialog = ctk.CTkInputDialog(text="provide password:", title="Password")
            dialogWidth = dialog.winfo_reqwidth()
            dialogHeight = dialog.winfo_reqheight()
            dialog.geometry("200x200")#dialog box size
            pass2 = dialog.get_input()#assigning input to pass2
            #hasshing password
            passwordBytes = pass2.encode('utf-8')#converting pass2 to bytes
            hashedObject = hashlib.sha256()#creating hash object with hashlib.sha256
            hashedObject.update(passwordBytes)#updating object with passwordBytes
            hashedPassword2 = hashedObject.hexdigest()#converting hashedObject to hexadecimal data
            #getting the binary and privatekey
            binary, privateKey1 = RSA.getPrivateKey(hashedPassword2)#binary and privatekey

            #is returned from the getPrivateKey function
            RSA.decrypt_file(file_path, privateKey1) #decrypt funtion is
            #intitiated with file_path and privatekey as parameters


    buttondencrypt = ctk.CTkButton(frame3, text="Decrypt", command=decrypt_file)
    buttondencrypt.pack(side="right", padx=5)


#encryption button is created when file is chosen
buttonbrowse = ctk.CTkButton(frame3, text="Select file", command=browse_files)
buttonbrowse.pack(side="left", padx=5)

#end of frame3---------------------------
#exit button
def closeProgram():
    print("CRYPTOGRAPHY PROGRAM TERMINATED...")
    exit()

buttonExit = ctk.CTkButton(frame, text="EXIT", command=closeProgram)
buttonExit.pack(pady=12, padx = 10)
buttonExit.place(relx=0.5, rely=0.95, anchor=tk.CENTER)


root.mainloop()
