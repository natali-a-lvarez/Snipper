# main routes/endpoints
from flask import Flask, request, jsonify, redirect, render_template, session, url_for
from config import app,db
from models import Snippet, User
from cryptography.fernet import Fernet
from os import environ as env
from dotenv import find_dotenv, load_dotenv
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
import json



ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app.secret_key = env.get("APP_SECRET_KEY")
fern = Fernet(env.get("FERNET_KEY"))


oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# decrypt a snippet of code
def decryption(snippet):
    snippet = snippet.to_json()
    snippet['code'] = fern.decrypt(snippet['code']).decode()
    return snippet

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@app.route("/")
def home():
    snippets = Snippet.query.all()
    # converting to json since it is an object and decrypting
    json_snippets = list(map(decryption, snippets))

    return render_template("home.html", session=session.get('user'), pretty=json.dumps(json_snippets))


# #GET ALL SNIPPETS
@app.route('/snippet', methods={"GET"})
def get_snippets():
    snippets = Snippet.query.all()

    # converting to json since it is an object and decrypting
    json_snippets = list(map(decryption, snippets))

    return jsonify({"snippets": json_snippets}), 200

    
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


# DELETE snippet
@app.route('/snippet/<int:id>', methods={"DELETE"})
def delete_snippet(id):
    snippet = Snippet.query.get(id)

    if not snippet:
        return jsonify({"message": "Snippet not found!"}), 404
    
    db.session.delete(snippet)
    db.session.commit()
    return jsonify({"message": "Snippet Deleted!"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))