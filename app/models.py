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