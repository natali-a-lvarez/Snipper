# database models
from config import db

class Snippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    language = db.Column(db.String(80), nullable=False)
    code = db.Column(db.String(80), nullable=False)
 
    def to_json(self):
        return {
            "id": self.id,
            "language": self.language,
            "code": self.code
        }
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)    
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def to_json(self):
        return {
            "id": self.id,
            "email": self.email,
            "password": self.password
        }
