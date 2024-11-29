'''This script will be designed to compare file hashes to known 
Virus hashes via virustotal'''
import json
import hashlib
import vt
from vt.error import APIError
from PyQt5.QtWidgets import QApplication, QFileDialog


#Load API key from config.json and intialize client
def load_config():
    try:
        with open ('config.json', 'r') as config_file:
            config_data = json.load(config_file)
        key = config_data['api_credentials']['api_key']
        client = vt.Client(f"{key}")
        return client
    except Exception as e:
        print(e)

#Use a PYQT window to select a file
def get_file():
    app = QApplication([])  
    dialog = QFileDialog()  
    dialog.setFileMode(QFileDialog.AnyFile)
    if dialog.exec_(): 
        file_path = dialog.selectedFiles()[0] 
        app.exit()
        return file_path
    app.exit()
    return None

#Generate a hash of a file before querying database
def generate_file_hash(file_path, algorithm="sha256"):
    hasher = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(4096) #read in chunks for large files
            if not chunk:
                break
            hasher.update(chunk)
        hash_value = hasher.hexdigest()
    return hash_value

#Check file hash against virus total database
def check_file(client, file_path):
    try:
        file_hash = generate_file_hash(file_path)
        client.get_object(file_hash) #get_object is used because I am not uploading the file
    except APIError as e:
        if e.args[0] == "ClientError" and "404" in str(e):
            print("Nothing found in virustotal")
        else:
            print(f"An unexpected Error occured {e}")

