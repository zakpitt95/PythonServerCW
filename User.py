class User:

    def __init__(self, username, passhash):
        self.username = username
        self.passhash = passhash
        self.permissions = 0
        self.patientid = -1

    def assign_patient(self, id):
        self.patientid = id

    def change_permissions(self, perms):
        self.permissions = perms