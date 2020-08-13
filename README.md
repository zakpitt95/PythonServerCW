# This is the coursework for SCC363 Security.
Project conducted by:

Abdulrazak Bahrami

Emre Ceyhan

Zak Pitt

Salman Farooq

Roo Thorp

## Important to Note:
Certificates must be located in the current directory before starting the server(which looks for cert.pem and private.pem), and the client (which looks for client-cert.pem)

The server uses os.chmod() to change the permissions on the log file. This call will fail if run on a non-unix OS.
