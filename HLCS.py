import os

def encryption(file_path):
    encrypted_data = ""#initialising

    with open(file_path, "rb") as f:#opening file in binary format
        file_data = f.read()# redaing file data into var"file_data"
        data = file_data.hex()#converting binary data to hexadecimal data
        for char in data:
            encrypted_data += chr(ord(char) + 5)#shifting each hexadecimal char
            #5 up the aschii chart

    return encrypted_data#returns the encrypted data


def encrypt_file(file_path, password):
    #writing hasshed password into file
    with open('HLCSpassword.txt', 'a') as File:#opening empty passwords file
        File.write(f"{password}:{0}\n")#writing the entered password into the file
        print("password saved in: HLCSpassword.txt")
        print("now encrypting file with HLCS")

    encrypted_data = encryption(file_path)#runs encryption with file_path retrieved from
    #the gui that retrieves it from the explorer, also assigning return value to "encrypted_data"
    encryptedFilepath = file_path + ".encrypted"#assigning the new file path with "encrypted" as extension

    with open(encryptedFilepath, "w") as file:#opening encryptedFilepath in write mode
        file.write(encrypted_data)#writing encrypted data to the file it is now in hexadecimal format

    return encryptedFilepath#then returns new file path


def decryption(file_path):
    decrypted_data = ""#assigns to string value

    with open(file_path, "r") as f:#opens file in normal reading mode
        file_data = f.read()#file data written into the var it is still in hexadecimal
        for char in file_data:
            decrypted_data += chr(ord(char) - 5)#shifting data 5 to the left on the ascii table
        data = bytes.fromhex(decrypted_data)#comverting the hexadecimal data into byte-array
    return data#returns decrypted data in byte format


def decrypt_file(file_path, pass2):
    with open('HLCSpassword.txt', 'r') as file:#opening password file in read mode
        for line in file:
            password, voiddata = line.strip().split(':')#getting the hashed password from the file

        if(password == pass2):#testing if the password entered mathes the password saved
            print("Password correct!")
            print("now decrypting file with HLCS")
            decrypted_data = decryption(file_path)#uses the decryption function to decrypt data it then returns
            #the "data" as "decrypted_data"
            decryptedFilepath = f"{os.path.splitext(file_path)[0]}"#removed the ".encrypted" from the file name

            with open(decryptedFilepath, "wb") as file:#opens file in write in binary mode
                file.write(decrypted_data)#byte-array is then written into the file

            with open('HLCSpassword.txt', 'w') as file:#password file is clered
                file.truncate(0)

            return decryptedFilepath#returns the new decrypted file's path
        else:
            print("unable to decrypt password incorrect")
