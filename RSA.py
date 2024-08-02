#class to be able to encrypt and decrypt the file_path data
import math#to be able to use gcd
import os#to be able to use os.path to get path and split text from extension

# Function to find gcd of two numbers
def gcd(a, b):#function initiated
    if b == 0:
        return a
    else:
        return gcd(b, a % b)#returns the greatest values b and (a devided by b returns remainder)

# Extended Greatest Common Divisor Algorithm

# Generate RSA keys
def generate_keys():# function to generate keys (private and public keys)
    p = 23 # hard coded prime value
    q = 41 # hard coded prime value
    n = p * q # creates "n" variable which is the mutiplication of prime numbers p & q
    phi = (p - 1) * (q - 1)# phi is used as euler's totient function where
    #where phi(p) = p-1, It counts how many numbers <= n that have
    #no common factors with n (coprimes). For prime numbers, phi(p) = p-1.
    e = 2 # "e" is assigned a hardcoded value of 2
    while gcd(e, phi) != 1:# here it is tested if e and phi are coprimes
        e += 1 # if e is not a coprime of phi e is incresed with 1 until e is a coprime of phi
    d = 0 # d is inatialised as 0
    while (d * e) % phi != 1: # here we test if the mutiplication value of d and e, devided by phi has a rest.
        d += 1 # if it does not have a rest d will be increased by one untill it has a rest
    return ((e, n), (d, n))# then values (e, n) is returned as publickey, and (d, n) is returned as pribvatekey

def encrypt(data, publicKey):# encryption takes place here
    e, n = publicKey # public key is initailised as (e, n)
    return pow(data, e, n)#then returning the normal data to the power of (e % n)

# RSA decryption with private key
def decrypt(encrypted_data, privateKey):#dectyption takes place here
    d, n = privateKey#private key is initailesed by (d, n)
    return pow(encrypted_data, d, n)#then returning the encrypted data to the power of (d % n)

def storeKeys(binary, password, publicKey, privateKey):# storing keys and binary in a file called "keys.txt"
    with open('keys.txt', 'a') as keysFile:
        keysFile.write(f"{binary}.{password}:{publicKey[0]}!{publicKey[1]},{privateKey[0]};{privateKey[1]}\n")#writing data into file the binary,
        # and password data, and keys will be created in gui form
        # although the function encrypt_file will return the binary data of outputFilepath

def getPrivateKey(pass2): # code to get the private key from the saved data
    with open('keys.txt', 'r') as keysFile:#reading keys file
        for line in keysFile:
            bandp, keys = line.strip().split(':')#splitting the binary and password from the keys(private and public)
            binary, password = bandp.split('.')
            if (password == pass2):#checking if the entered password and the saved passwords in hash are the same
                print("Password correct!")
                print("now decrypting file using RSA")
                _, privateKeyString = keys.split(',')#private key string is then extracted from privatekey[0], and privatekey[1]
                n, d = [int(x) for x in privateKeyString.split(';')] # then the privatekey string is split and n is assigned
                # to privatekey[0] and d is assigned to pribvatekey[1]
                return binary, (n, d)
            else:
                print("Password incorrect!")


def readBinary(file_Path):#reading binary data
    with open(file_Path, "rb") as f: # opening the file in binary format hence "rb"
        binaryData = f.read()# binary data in file is assigned to "binaryData"
        first = binaryData[:5]#This line assigns the first five elements of binaryData to the variable "first"
        #starting from index 0 up to (but not including) index 5.
        last = binaryData[-5:]#This line assigns the last five elements of binaryData to the variable "last"
        #starting from the fifth to last element (-5 index) up to the end of the sequence.

    return (first + last).hex()#returns first and last anfd then the .hex()
    #method is used to convert data into a hexadecimal representation. creates
    #the ability to use "bytes" in code further on.

# encrypting the selectfile
def encrypt_file(file_path, publickey, output_path=None):
    print("now encrypting file with RSA")
    outputFilepath = f"{file_path}.encrypted"# outputFilepath is where the
    #encrypted data file will be writted to, hence ".encrypted"

    # Read the file into memory
    with open(file_path, "rb") as f:#opening file in binary format
        file_data = f.read()# redaing file data into var"file_data"
        encrypted_data = [encrypt(byte, publickey) for byte in file_data]
        #each byte is then encrypted in the file_data using "encrypt" function
        #and the public key which is generated in the gui

    with open(outputFilepath, 'w') as outfile:# outputfile is the opened in
    #writing format
        outfile.write(','.join(str(x) for x in encrypted_data))#encrypted data is
        #then written into the file as string values
        file_name = os.path.basename(outputFilepath)
    print("file encrypted successfully:", file_name)#output in command promt?terminal
    os.remove(file_path)#unencrypted file in them removed

    return readBinary(outputFilepath)#binary format of output file is then returned
    #to the variable "binary" in the gui



# Decrypt a file
def decrypt_file(file_path, privateKey):#file decyrption function
    outputFilepath = f"{os.path.splitext(file_path)[0]}"# splitting file path and assisgning to outputFilepath
    with open(file_path, 'r') as infile:#opring encrypted file in read format
        encrypted_data = [int(x) for x in infile.read().split(',')] # encrypted content is the written into variable
        #named encrypted_data

    decrypted_data = bytes([decrypt(byte, privateKey) for byte in encrypted_data])
    #var decrypted_data is created and assigned to the byte values of the decrypted byted in the "encrypted_data"


    with open(outputFilepath, 'wb') as outfile:#file is opened as write in binary
        outfile.write(decrypted_data)#byte data is written into file (file is now decrypted)
        file_name = os.path.basename(outputFilepath)
    print("file decrypted successfully:", file_name)#output in terminal
    os.remove(file_path)#file removed from directory
    with open('keys.txt', 'w') as file:#clearing keys from file
        file.truncate(0)
