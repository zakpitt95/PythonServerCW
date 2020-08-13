import socket
import ssl
import sys
import pickle
import bcrypt
import jwt
import hashlib

lowerCheck = False
uppersCheck = False
lengthCheck = False
symbolCheck = False
numbersCheck = False
spaceCheck = True
logged_in = False
current_jwt = None


#Builds a request, serialising it with pickle and prefixing it with the length of the message
def make_request(req_type, auth, body):
	dictionary = {
		"type": req_type,
		"auth": auth,
		"body": body
	}
	to_send = pickle.dumps(dictionary)
	return (bytes(f"{len(to_send):<{10}}", 'utf-8')+to_send)

#Parses a response from the server, returning the success, message, and any content it may have
def handle_response(response):
	success = response.get("success")
	message = response.get("message")
	content = response.get("content")
	if success == "true":
		print("Success!")
	else:
		print("Failure.")
	print(message)
	if (message == "Here is the record:"):
		for k, v in content.items():
			print("{0} : {1}".format(k, v))
		print()
	elif message == "Here are the records:":
		for d in content:
			for k, v in d.items():
				print("{0} : {1}".format(k, v))
			print()
		print()
	elif message == "New record:":
		for k, v in content.items():
			print("{0} : {1}".format(k, v))
		print()
	elif message == "Here are the users:":
		for u in content:
			print(u)
		print()

def send_request(to_send):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Making TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    context.verify_mode = ssl.CERT_REQUIRED
    #Load our cert
    context.load_verify_locations("client-cert.pem")
    try:
        #Wrap socket to make it secure
        serv = context.wrap_socket(sock, server_hostname='localhost')
        serv.connect(('localhost', 8081))
        #Get the server's cert
        peercert = serv.getpeercert()
        #Check that the cert matches the host
        ssl.match_hostname(peercert, 'localhost')
    except ssl.SSLError as e:
        print(e)
        serv.close()
        return None
    else:
        #Get the server's certificate
        peercert = serv.getpeercert(True)
        #Make a fingerprint of their cert
        peersha256 = hashlib.sha256(peercert).hexdigest()
        clientcert = open("client-cert.pem", "r").read()
        clientcert = ssl.PEM_cert_to_DER_cert(clientcert)
        #Make a fingerprint of our cert
        clientsha256 = hashlib.sha256(clientcert).hexdigest()
        #Compare the two
        if (peersha256 == clientsha256):
            #Fingerprints match (cert is valid)
            serv.send(to_send)
            from_server = serv.recv(4096)
            serv.close()
            return pickle.loads(from_server)
        else:
            #Fingerprints dont match (cert is invalid)
			#TODO: raise and exception here
            serv.close()
            return None


def login_connect(username, password, exists):
	if exists:
		print("Trying to log in user " + username)
		to_send = make_request("LOGIN", None, username + " " + password)
	elif not exists:
		print("Trying to sign up user " + username)
		to_send = make_request("SIGN_UP", None, username + " " + password)
	received = send_request(to_send)
	if (received != None):
		status = received.get("success")
		if status == "true":
			global current_jwt
			current_jwt = received.get("content")
		elif status == "false":
			print(received.get("message"))
			loginmenu()
	else:
		loginmenu()


def mainmenu():
	print("Main Menu")
	global current_jwt
	options = input("Please Select One of the Following:\n 1- Get Specific Record\n 2- Get All Records\n 3- Edit A Record\n 4- Delete A Record\n 5- Change Permissions\n 6- Add Patient\n 7- Assign Patient to User\n 8- Logout\n")
	#Get a record by ID
	if options == "1":
		specificRecord = input("Specify user ID\n")
		handle_response(send_request(make_request("GET_RECORD", current_jwt, specificRecord)))
	#Get all available records
	elif options == "2":
		handle_response(send_request(make_request("GET_RECORDS", current_jwt, None)))
	#Edit a user
	elif options == "3":
		specificRecord = input("Select user to edit\n")
		response = send_request(make_request("GET_RECORD", current_jwt, specificRecord))
		handle_response(response)
		bodyContent = response.get("content")
		changesLeft = True
		while changesLeft == True:
			optionToChange = input("Select one of the following to update \n 0- First name \n 1- surname \n 2- birthday \n 3- department \n 4- notes \n 5- Finished edits\n")
			updatedValue = input("Enter new value to replace\n")
			if optionToChange == "0":
				bodyContent["firstname"] = updatedValue
				print(bodyContent)
			elif optionToChange == "1":
				bodyContent["surname"] = updatedValue
				print(bodyContent)
			elif optionToChange == "2":
				bodyContent["birthday"] = updatedValue
				print(bodyContent)
			elif optionToChange == "3":
				bodyContent["department"] = updatedValue
				print(bodyContent)
			elif optionToChange == "4":
				bodyContent["notes"] = updatedValue
				print(bodyContent)
			else:
				handle_response(send_request(make_request("EDIT_RECORD", current_jwt, bodyContent)))
				changesLeft = False
	#Delete a user
	elif options == "4":
		deletedUser = input("Select user to delete\n")
		handle_response(send_request(make_request("GET_RECORD", current_jwt, deletedUser)))
		doubleCheck = input("Are you sure you want to delete? \n [y/n] \n")
		if doubleCheck == "y":
			handle_response(send_request(make_request("DELETE_RECORD", current_jwt, deletedUser)))
		else:
			print("You have chosen not to delete this user \n")
	#CHange user permissions
	elif options == "5":
		handle_response(send_request(make_request("GET_USERS", current_jwt, None)))
		target_user = input("Select username to change\n")
		new_perms = input("Select new user permissions level:\n0 for Patient\n1 for Staff\n2 for Regulator\n")
		handle_response(send_request(make_request("CHANGE_PERMS", current_jwt, {"username" : target_user, "perms" : new_perms})))
	#Edit a patient record
	elif options == "6":
		firstname = input("Enter first name: \n")
		surname = input("Enter  surname: \n")
		birthday = input("Enter birthday: \n")
		department = input("Enter department name: \n")
		notes = input("Enter notes: \n")
		newUser = {
		"id": "",
		"firstname": firstname,
		"surname": surname,
		"birthdate": birthday,
		"department": department,
		"notes": notes
		}
		handle_response(send_request(make_request("MAKE_PATIENT", current_jwt, newUser)))
	#Associate a user with a patient record
	elif options == "7":
		handle_response(send_request(make_request("GET_USERS", current_jwt, None)))
		username = input("Select username to change\n")
		patientid = input("Enter patient ID:\n")
		handle_response(send_request(make_request("ASSIGN_PATIENT", current_jwt, {"username" : username, "patientid" : patientid})))
	#Log out
	elif options == "8":
		current_jwt = None
		loginmenu()
	mainmenu()

def loginmenu():
	print("Main Menu:")
	check = input("1 to Login\n2 to Sign Up\n3 to Exit\n")
	#Exit
	if check == "3":
		sys.exit(0)
	#Sign up
	if (check == "2" ):
		passCheck = False #change to true if password is strong 
		userCheck = False #change to true if username doesn't have spaces
		while userCheck ==  False:
			username = input("Enter desired username\n")
			space = [l for l in username if ord(l) == 32 ]#space
			if space:
				print("You cannot include spaces in your username")
			elif not space:
				spaceCheck = False
				userCheck = True

		#Password strength checks
		print("Your password must have at least:\nOne lowercase character,\nOne uppercase character,\nOne symbol,\nOne number,\nA minimum length of 8 characters\n")
		while passCheck == False:   
			password = input("Enter desired password\n")

			uppers = [l for l in password if ord(l) >= 65 and ord(l) <= 90] #uppercase
			lowers = [l for l in password if ord(l) >= 97 and ord(l) <= 122] #lowercase
			symbol = [l for l in password if ord(l) >= 33 and ord(l) <= 47] #symbol
			numbers = [l for l in password if ord(l) >= 48 and ord(l) <= 57] #symbol
			space = [l for l in password if ord(l) == 32 ]#space

			if not lowers:
				print("Password doesn't have a lowercase\n")
				lowerCheck = False
			elif lowers:
				lowerCheck = True
                
			if not uppers:
				print("Password doesn't have an uppercase\n")
				uppersCheck = False
			elif uppers:
				uppersCheck = True

			if len(password) < 8:
				print("Password is too short, must have at least 8 characters\n")
				lengthCheck = False
			elif len(password) >= 8:
				lengthCheck = True
                
			if not symbol:
				print("Password doesn't have symbols\n")
				symbolCheck = False
			elif symbol:
				symbolCheck = True

			if not numbers:
				print("Password doesn't have numbers\n")
				numbersCheck = False
			elif numbers:
				numbersCheck = True

			if space:
				print("You cannot include spaces in your password")
				spaceCheck = True
			elif not space:
				spaceCheck = False   

			if lowerCheck and uppersCheck and lengthCheck and symbolCheck and numbersCheck and not spaceCheck:
				passCheck = True

		login_connect(username, password, False)
            
	#Log in
	elif (check == "1"):
		username = input("enter your username\n")
		password = input("enter your password\n")
		login_connect(username, password, True)
    
	else:
		loginmenu()

def main(args):
	try:
		loginmenu()
		mainmenu()
	except KeyboardInterrupt:
		sys.exit()

if __name__ == '__main__':
	sys.exit(main(sys.argv))
