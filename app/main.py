# main routes/endpoints
from flask import request, jsonify
from config import app,db
from models import Snippet, User
from cryptography.fernet import Fernet
from os import environ as env
import bcrypt, jwt, datetime
from dotenv import find_dotenv, load_dotenv

# TODO make GET /user available by token provided to user with POST /login

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
    
app.secret_key = env.get("FERNET_KEY")

fern = Fernet(app.secret_key)

# decrypt a snippet of code
def decryption(snippet):
    snippet = snippet.to_json()
    snippet['code'] = fern.decrypt(snippet['code']).decode()
    return snippet

# validate a jwt token
def validate_jwt(token):
    decoded = jwt.decode(token, env.get("JWT_SECRET"), algorithms=["HS256"])
    return decoded

#GET ALL SNIPPETS
@app.route('/snippet', methods={"GET"})
def get_snippets():
    snippets = Snippet.query.all()

    # converting to json since it is an object and decrypting
    json_snippets = list(map(decryption, snippets))

    return jsonify({"snippets": json_snippets}), 200


# GET ALL USERS(for testing purposes)
@app.route('/users', methods=["GET"])
def get_users():
    users = User.query.all()
    
    # converting to json since it is an object
    json_user = list(map(lambda x: x.to_json(), users))

    return jsonify({"users": json_user}), 200

# Log in a user (must add a body with credentials)
@app.route('/login', methods=['GET'])
def login_user():
    data = request.json

    # Getting the user based on body
    user = User.query.filter(User.email == data['email']).first()
    user = user.to_json()

    # Verify password
    password = data['password'].encode('utf-8')
    hashed_password = user['password'].encode('utf-8')
    valid_password = bcrypt.checkpw(password=password, hashed_password=user['password'].encode('utf-8'))

    # Getting JWT token if valid password
    if valid_password:
        # setting payload with user and expiration 
        payload = {"email": user['email'], "password": user['password'], "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=24)}
        jwt_token = jwt.encode(payload, env.get("JWT_SECRET"), algorithm="HS256")
        return jsonify({'token': jwt_token })   
    else:
        return jsonify({"message": "User not Authorized!"})

# GET a user with token (must add a header named token with token given at login)
@app.route("/user", methods=["GET"])
def get_user_with_token():
   try:
    # if token is still valid
    token = request.headers['token']
    validated_token = validate_jwt(token)
    return jsonify({"user": validated_token})
   except jwt.ExpiredSignatureError:
    # if not valid
    return jsonify({"message": "Token has expired, please login again."})
       
    
# GET by ID
@app.route('/snippet/<int:id>', methods=["GET"])
def get_snippet(id):
    snippet = Snippet.query.get_or_404(id)

    if not snippet:
        return jsonify({"message": "Snippet not found!"}), 404
    
    return jsonify(snippet.to_json()), 200 

# Create a snippet
@app.route('/snippet', methods=['POST'])
def create_snippet():
    data = request.json

    # encrypt code 
    data['code'] = fern.encrypt(bytes(data['code'], 'utf-8')).decode()

    new_snippet = Snippet(language=data['language'], code=data['code'])
    print(new_snippet)

    # adding it to our model
    db.session.add(new_snippet)
    db.session.commit()
    return jsonify({"message": "Snippet created successfully"})

# Create a USER
@app.route('/user', methods=['POST'])
def create_user():
    data = request.json

    # hash and salt password 
    bytes = data['password'].encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)

    new_user = User(email=data['email'], password=hash.decode('utf-8'))

    # adding it to our model
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"})


# DELETE snippet
@app.route('/snippet/<int:id>', methods={"DELETE"})
def delete_snippet(id):
    snippet = Snippet.query.get(id)

    if not snippet:
        return jsonify({"message": "Snippet not found!"}), 404
    
    db.session.delete(snippet)
    db.session.commit()
    return jsonify({"message": "Snippet Deleted!"}), 200

# DELETE User
@app.route('/user/<int:id>', methods={"DELETE"})
def delete_user(id):
    user = User.query.get(id)

    if not user:
        return jsonify({"message": "User not found!"}), 404
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User Deleted!"}), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)