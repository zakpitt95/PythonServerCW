import os
import pickle
from cryptography.fernet import Fernet

class FileDump:

    #the path of the file
    def __init__(self):
        self.patientfilePath = os.getcwd()+"/patientrecords.txt"
        self.userfilePath = os.getcwd()+"/users.txt"
        self.key = b'7wAY2j0msyFzMJpOmb3lQUP4fxLD7mHWPJL83lCq-58='
        self.f = Fernet(self.key)

    def read_users(self):
        tempList = []
        with open(self.userfilePath, 'r') as userFile:
            for line in userFile:
                line = line.rstrip("\n")
                if line != "":
                    currentuser = self.f.decrypt(bytes(line, 'utf-8'))
                    unpickled = pickle.loads(currentuser)
                    tempList.append(unpickled)
            return tempList

    #reads from the file and returns a list of dictionaries
    def read_patients(self):
        tempList = [] 
        dictionary = {}
        with open(self.patientfilePath, 'r') as recordFile:
            for line in recordFile:
                if (line != "\n"):
                    line = line.rstrip("\n")
                    decrypted = self.f.decrypt(bytes(line, 'utf-8'))
                    actualLine = decrypted.decode('utf-8')                            
                    if (actualLine[:5] != 'notes'):
                        (key, value) = actualLine.split(" ", 1)
                        dictionary[key] = value
                    elif (actualLine[:5] == 'notes'):
                        key = actualLine[:5]
                        value= actualLine[6:]
                        dictionary[key] = value.rstrip("\n")
                elif (line in ['\n', '\r\n']):#if not line.strip():
                    tempList.append(dictionary)
                    dictionary = {}
            return tempList                

    def write_users(self, users):
        with open(self.userfilePath, 'w') as userFile:
            for u in users:
                pickled = pickle.dumps(u)
                encrypted = self.f.encrypt(pickled)
                userFile.write(encrypted.decode("utf-8"))
                userFile.write("\n")

    #overwrites the file with a list of dictionaries
    def write_patients(self, patients):
        with open(self.patientfilePath, 'w') as recordFile:
            for diction in patients:
                for key , value in diction.items():
                    token = self.f.encrypt(bytes((key +" "+ value),'utf-8'))
                    recordFile.write(token.decode("utf-8"))
                    recordFile.write("\n")
                recordFile.write("\n")


    