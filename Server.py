import socket
import sys
import collections
import pickle
import ssl
import cryptography
import bcrypt
from User import User
from FileDump import FileDump
import jwt
import time
import json
import logging
import os
import stat

logging.basicConfig(filename='log.log', level=logging.DEBUG ,format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%m-%d-%Y - %I:%M:%S %p')
#Set the log so that only the root user may edit or read it
#This means that the server must be run as root / with sudo
#A better way of doing this would be to give the server a user group and assign the log file that group
os.chown('log.log', 0, 0)
os.chmod('log.log', stat.S_IREAD | stat.S_IWRITE)
fd = FileDump()


#TODO: Populate from file on start

patients = fd.read_patients()
users = fd.read_users()

secretKey = 'secretServerKeyKeepThisSafeBabez'

#This is the format for all messages sent from the server to the client
def make_response(success, message, content):
    return pickle.dumps({
        "success" : success,
        "message" : message,
        "content" : content
    })

#Creates a JWT for the current User
def make_jwt(user):
    username = get_user(user)
    payload = {
        'username': username.username,
        'permissions' : username.permissions,
        'exp': int(time.time()) + 3600
    }
    return jwt.encode(payload, secretKey, 'HS256')

#Cerifies a provided JWT is valid
def verify_jwt(token, addr, user):
    try:
        token = jwt.decode(token, secretKey, algorithms=['HS256'])
        return True, token.get('username'), token.get('permissions')
    except jwt.exceptions.ExpiredSignatureError:
        logging.warning("%s: %s tried expired JWT", addr[0], user)
        return False
    except jwt.exceptions.InvalidSignatureError:
        logging.warning("%s: %s tried invalid JWT", addr[0], user)
        return False
    except jwt.exceptions.InvalidTokenError:
        logging.warning("%s: %s tried invalid JWT", addr[0], user)
        return False

#Verifies if a username exists
def username_exists(user):
    for u in users:
        if u.username == user:
            return True
    return False

#Returns a user, given a username
def get_user(user):
    for u in users:
        if u.username == user:
            return u
    return None

#Returns a patient, given an ID
def get_patient(id):
    index = 0
    for p in patients:
        if p.get("id") == id:
            return p, index
        index += 1
    return None, None

#Creates a user
def create_user(user, password, conn, addr):
    #Check if the username is available
    if not username_exists(user):
        hash = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())
        users.append(User(user, hash))
        logging.info('%s created account %s', addr[0], user)
        conn.send(make_response("true", "User Created", make_jwt(user)))
        fd.write_users(users)
        #Make User and return JWT
    else:
        conn.send(make_response("false", "Username not available", None))
        logging.info('%s tried to make a user that already exists', addr[0])
        #Dont make user, return error

def login(username, password, conn, addr):
#Check the username exists
    if not username_exists(username):
        conn.send(make_response("false", "Unrecognised Credentials", None))
        logging.info('%s Failed login to %s: non-existent username', addr[0], username)
    else:
        user = get_user(username)
        #Check the password
        if bcrypt.checkpw(bytes(password, 'utf-8'), user.passhash):
            conn.send(make_response("true", "Login Successful", make_jwt(username)))
            logging.info('%s logged into user %s', addr[0], username)
        else:
            conn.send(make_response("false", "Unrecognised Credentials", None))
            logging.warning('%s Failed login to %s: wrong password', addr[0], username)

def accept_connections(conn, addr):
    currentuser = None
    currentpermissions = None
    data = b''
    #Recieve the first few bytes, containing the length of the message
    data = conn.recv(16)
    recv_length = int(data[:10])
    #Receive the rest of the message
    while len(data) - 10 != recv_length:
        data += conn.recv(16)
    #Parse the received message
    received = pickle.loads(data[10:])
    request = received.get("type")

    #If we're logging in...
    if request == "LOGIN":
        body = received.get("body").split()
        login(body[0], body[1], conn, addr)
    #If we're signing up
    elif request == "SIGN_UP":
        body = received.get("body").split()
        create_user(body[0], body[1], conn, addr)
    else:
        #For everything else, check JWT is valid
        token = received.get("auth")
        valid, currentuser, currentpermissions = verify_jwt(token, addr, currentuser)
        #If the JWT is invalid, tell them off
        if not valid:
            logging.warning('%s: %s had an invalid JWT', addr[0], currentuser)
            conn.send(make_response("false", "Invalid JWT, Please re-log", None))

        #Permissions:
        #0 is basic - can only see patient records
        #1 is doctor/staff - can see and edit everyone
        #2 is auditor - can see everything, but cannot edit
        #3 is admin - can see and edit everything, including users
        
        #Get a record
        elif request == "GET_RECORD":
            target = received.get("body")
            record, indexT = get_patient(target)
            #Check if the user is a patient
            if currentpermissions == 0:
                #If they are, only return their patient record (if it exists)
                user_patient_id = get_user(currentuser).patientid
                if user_patient_id == -1 or user_patient_id != target:
                    conn.send(make_response("false", "No available records", None))
                else: 
                    record = get_patient(user_patient_id)
                    if record == None:
                        conn.send(make_response("false", "Patient does not exist", None))
                    else:
                        conn.send(make_response("true", "Here is the record:", record))
            else:
                #Otherwise, we can return any record
                if record == None:
                    conn.send(make_response("false", "User does not exist", None))
                    logging.warning('%s: %s tried to get a non-existent user', addr[0], currentuser)
                else:
                    conn.send(make_response("true", "Here is the record:", record))
                    logging.info('%s: %s successfully requested a record', addr[0], currentuser) 
        elif request == "GET_RECORDS":
            #Check if the user is a patient
            if (currentpermissions == 0):
                #If they are, only return their patient record (if it exists)
                user_patient_id = get_user(currentuser).patientid
                if user_patient_id == -1:
                    conn.send(make_response("false", "No available records", None))
                else: 
                    record = get_patient(user_patient_id)
                    if record == None:
                        conn.send(make_response("false", "Patient does not exist", None))
                    else:
                        conn.send(make_response("true", "Here is the record:", record))
            else:
                #Otherwise, return all records
                conn.send(make_response("true", "Here are the records:", patients))
            logging.info('%s: %s requested all records', addr[0], currentuser)
        elif request == "EDIT_RECORD":
            #Only admins and staff can edit records
            if currentpermissions != 1 and currentpermissions != 3:
                conn.send(make_response("false", "Insufficient Permissions", None))
            else:
                target = received.get("body")
                current_patient, index = get_patient(target.get("id"))
                #Check the patient exists
                if current_patient == None:
                    conn.send(make_response("false", "User does not exist", None))
                    logging.warning('%s: %s failed to edit a record', addr[0], currentuser)
                else:
                    patients[index] = target
                    conn.send(make_response("true", "New record:", patients[index]))
                    fd.write_patients(patients)
                    logging.info('%s: %s successfully edited a record', addr[0], currentuser)
        elif request == "DELETE_RECORD":
            #Only admins and staff can delete records
            if currentpermissions != 1 and currentpermissions != 3:
                conn.send(make_response("false", "Insufficient Permissions", None))
            else:
                target = received.get("body")
                current_patient, index = get_patient(target)
                #Check if the record exists
                if current_patient == None:
                    conn.send(make_response("false", "Record does not exist ", None))
                    logging.warning('%s: %s failed to delete a record', addr[0], currentuser)
                else:
                    patients.remove(current_patient)
                    conn.send(make_response("true", "Record Deleted", None))
                    fd.write_patients(patients)
                    logging.info('%s: %s deleted the record with id %s', addr[0], currentuser, current_patient.get('id'))
        elif request == "CHANGE_PERMS":
            #Only admins can change user permissions
            if currentpermissions != 3:
                conn.send(make_response("false", "Insufficient Permissions", None))
                logging.warning('%s: %s tried to edit users permissions', addr[0], currentuser)
            else:
                target = received.get("body")
                target_user = get_user(target.get("username"))
                #Check the target user exists
                if target_user == None:
                    conn.send(make_response("false", "User does not exist", None))
                    logging.warning('%s: %s failed to edit non-existent users permissions', addr[0], currentuser)
                else:
                    target_user.change_permissions(target.get("perms"))
                    conn.send(make_response("true", "User Permissions Updated", None))
                    fd.write_users(users)
                    logging.info('%s: %s changed permissions of a user', addr[0], currentuser)
        elif request == "MAKE_PATIENT":
            #Only staff and admins can make new records
            if currentpermissions != 1 and currentpermissions != 3:
                conn.send(make_response("false", "Insufficient Permissions", None))
                logging.warning('%s: %s tried to create patient', addr[0], currentuser)
            else:
                target = received.get("body")
                last = len(patients)
                lastID = int(patients[last - 1].get("id")) + 1
                #We know the last patient in the list will have the highest patient ID, so we use that + 1
                target["id"] = str(lastID)
                patients.append(target)
                conn.send(make_response("true", "New record:", patients[lastID - 1]))
                fd.write_patients(patients)
                logging.info('%s: %s made permissions', addr[0], currentuser)
        elif request == "GET_USERS":
            #Only admin and regulator can get users
            if currentpermissions != 3 and currentpermissions != 2:
                conn.send(make_response("false", "Insufficient Permissions", None))
                logging.warning('%s: %s tried to get users', addr[0], currentuser)
            else:
                usernames = []
                #So we only return the usernames!
                for u in users:
                    usernames.append(u.username)
                conn.send(make_response("true", "Here are the users:", usernames))
                logging.info('%s: %s got all users', addr[0], currentuser)
        elif request == "ASSIGN_PATIENT":
            #Only admins can assign patients to users
            if currentpermissions != 3:
                conn.send(make_response("false", "Insufficient Permissions", None))
                logging.warning('%s: %s tried to assign patient', addr[0], currentuser)
            else:
                target = received.get("body")
                targetuser = target.get("username")
                targetpatient = target.get("patientid")
                user = get_user(targetuser)
                user.patientid = targetpatient
                conn.send(make_response("true", "User updated", None))
                fd.write_users(users)
                logging.info('%s: %s assigned patient %s to user %s', addr[0], currentuser, targetpatient, targetuser)
        else:
            conn.send(make_response("false", "Unrecognised Request", None))
            logging.warning('%s: %s made an unrecognised request: %s', addr[0], currentuser, request)
    conn.close()

def main(args):
    logging.info('Server Starting')

    #Set up server, with TLS1.2 only
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'private.pem')
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 8081))
    sock.listen(5)

    serv = context.wrap_socket(sock, server_side=True)

    logging.info('Server Started')
    try:
        while True:
            try:
                conn, addr = serv.accept()
                accept_connections(conn, addr)
            except ssl.SSLError as e:
                logging.warning('%s had SSL error %s', addr[0], e)
                conn.close()
    except KeyboardInterrupt:
        #Cleanly exit when Ctrl + C
        logging.info('Server shut down')
        sock.close()
        try:
            conn.close()
        except UnboundLocalError:
            #Error only occurs when we Ctrl + C before connecting
            pass
        sys.exit()

if __name__ == '__main__':
    sys.exit(main(sys.argv))
