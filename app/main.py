# main routes/endpoints
from flask import request, jsonify
from config import app,db
from models import Snippet


#GET ALL
@app.route('/snippet', methods={"GET"})
def get_snippets():
    snippets = Snippet.query.all()

    # converting to json since it is an object
    json_snippets = list(map(lambda x: x.to_json(), snippets))
    return jsonify({"snippets": json_snippets}), 200



# GET by ID
@app.route('/snippet/<int:id>', methods=["GET"])
def get_snippet(id):
    snippet = Snippet.query.get_or_404(id)

    if not snippet:
        return jsonify({"message": "Snippet not found!"}), 404
    
    return jsonify(snippet.to_json()), 200 

# Creaate a recipe
@app.route('/snippet', methods=['POST'])
def create_snippet():
    data = request.json
    new_snippet = Snippet(language=data['language'], code=data['code'])

    # adding it to our model
    db.session.add(new_snippet)
    db.session.commit()
    return jsonify({"message": "Snippet created successfully"})



if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)