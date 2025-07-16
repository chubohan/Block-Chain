from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, insurance_officer):
        self.id = id
        self.username = username
        self.insurance_officer = insurance_officer