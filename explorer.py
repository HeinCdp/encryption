#This class enables the user to browse files like a file explorer
#and then selecting a file in the explorer further on assigning the selected value
#to the variable name "file_path".
import tkinter as tk #importing tkinter to be able to run the "root = tk.Tk()"
from tkinter import filedialog#importin g filedialog from tkinter
import os #importing os to get the file name from file path
#creating the function for file exploring
def browse_files():#this is the browse_files function initiation
    print("browsing files...")
    root = tk.Tk()#creating root window to be able to use filedialog
    root.withdraw()#exiting root
    #requesting file path and returning the filename
    file_path = filedialog.askopenfilename()#getting the file_path
    file_name = os.path.basename(file_path)#extracting file name from file path
    print("file selected: " + file_name)#printing the selected file name
    #returns file_name to be used as str value
    return file_path#returning file_path(the path, not just file name)
