from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import datetime
import hashlib
import pymongo



app = Flask(__name__)
jwt = JWTManager(app) # initialize JWTManager
app.config['JWT_SECRET_KEY'] = '38dd56f56d405e02ec0ba4be4607eaab'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1) # define the life span of the token

# Mongo DB_atlas connection
client = pymongo.MongoClient("mongodb+srv://test:Test123@cluster0.quohhhr.mongodb.net/?retryWrites=true&w=majority")
db = client["mydatabase"]
users_collection = db["users"]
templates_collection = db["templates"]

#registration
@app.route("/register", methods=["POST"])
def register():
    new_user = request.get_json() # store the json body request
    # Creating Hash of password to store in the database
    new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest() # encrpt password
    # Checking if user already exists
    doc = users_collection.find_one({"email": new_user["email"]}) # check if user exist
    # If not exists than create one
    if not doc:
        # Creating user
        users_collection.insert_one(new_user)
        return jsonify({'msg': 'User created successfully'}), 201
    else:
        return jsonify({'msg': 'Username already exists'}), 409

#user login
@app.route("/login", methods=["post"])
def login():
    # Getting the login Details from payload
    login_details = request.get_json() # store the json body request
    # Checking if user exists in database or not
    user_from_db = users_collection.find_one({'email': login_details['email']})  # search for user in database
    # If user exists
    if user_from_db:
        # Check if password is correct
        encrpted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
        if encrpted_password == user_from_db['password']:
            # Create JWT Access Token
            access_token = create_access_token(identity=user_from_db['email']) # create jwt token
            # Return Token
            return jsonify(access_token=access_token), 200
    return jsonify({'msg': 'The email or password is incorrect'}), 401

#Template creation
@app.route("/create", methods=["POST"])
@jwt_required()
def create_template():
    """Creating the template with respect to the user
    Returns:
        dict: Return the profile and template created
    """
    # Getting the user from access token
    current_user = get_jwt_identity() # Get the identity of the current user
    user_from_db = users_collection.find_one({'email' : current_user})
    
    # Checking if user exists
    if user_from_db:
        # Getting the template details from json
        template_details = request.get_json() # store the json body request
        # Viewing if templated already present in collection
        user_template = {'profile' : user_from_db["email"],  "template_name": template_details["template_name"],"subject":template_details["subject"],"body":template_details["body"]}
        doc = templates_collection.find_one(user_template) # check if user exist
        # Creating collection if not exists
        
        if not doc:
            templates_collection.insert_one(user_template)
            return jsonify({'msg': 'Template created successfully'}), 200
        # Returning message if template exists
        else: return jsonify({'msg': 'Template already exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404




@app.route("/get", methods=["GET"])
@jwt_required()
def get_template():
    """Get the templates of specefic user
    Returns:
        dict: Return the profile and template 
    """
    # Getting the user from access token
    current_user = get_jwt_identity() # Get the identity of the current user
    user_from_db = users_collection.find_one({'email' : current_user})
    # Checking if user exists
    if user_from_db:
        # Viewing if templated already present in collection
        user_template = {'profile' : user_from_db["email"]}
        return jsonify({"docs":list(db.templates.find(user_template, {"_id":0}))}), 200
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404



@app.route("/get/specific", methods=["GET"])
@jwt_required()
def get_specific_one():
    # Getting the user from access token
    current_user = get_jwt_identity() # Get the identity of the current user
    user_from_db = users_collection.find_one({'email' : current_user})
    
    # Checking if user exists
    if user_from_db:
        # Getting the template details from json
        template_details = request.get_json() # store the json body request
        # Viewing if templated already present in collection
        user_template = {'profile' : user_from_db["email"],  "template_name": template_details["template_name"]}
        doc= templates_collection.find_one(user_template)
        if doc:
            return jsonify({"docs":list(db.templates.find(user_template, {"_id":0}))}), 200
        else:
            return jsonify({"msg":"Template_name not exists on your profile"})
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404



@app.route("/update", methods=["PUT"])
@jwt_required()
def update_template():
    """Updating the template with respect to the user
    Returns:
        dict: Return the profile and template created
    """
    # Getting the user from access token
    current_user = get_jwt_identity() # Get the identity of the current user
    user_from_db = users_collection.find_one({'email' : current_user})
    
    # Checking if user exists
    if user_from_db:
        # Getting the template details from json
        template_details = request.get_json() # store the json body request
        # Viewing if templated already present in collection
        user_template = {'profile' : user_from_db["email"],  "template_name": template_details["old_template_name"],"subject":template_details["old_subject"],"body":template_details["old_body"]}
        doc = templates_collection.find_one(user_template) # check if user exist
        # Updating collection if not exists
        
        if doc:
            doc["template_name"] = template_details["new_template_name"]
            doc["subject"] = template_details["new_subject"]
            doc["body"] = template_details["new_body"]

            templates_collection.update_one(user_template, {"$set": {"template_name":doc["template_name"],"subject":doc["subject"],"body":doc["body"]}}, upsert=False)
            return jsonify({'msg': 'Template Updated successfully'}), 200
        # Returning message if template exists
        else: return jsonify({'msg': 'One of the Template detail not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404

        


@app.route("/delete", methods=["DELETE"])
@jwt_required()
def delete_template():
    """Creating the template with respect to the user
    Returns:
        dict: Return the profile and template created
    """
    # Getting the user from access token
    current_user = get_jwt_identity() # Get the identity of the current user
    user_from_db = users_collection.find_one({'email' : current_user})
    
    # Checking if user exists
    if user_from_db:
        # Getting the template details from json
        template_details = request.get_json() # store the json body request
        # Viewing if templated already present in collection
        user_template = {'profile' : user_from_db["email"],  "template_name": template_details["template_name"]}
        doc = templates_collection.find_one(user_template) # check if user exist
        # Creating collection if not exists
        
        if doc:
            templates_collection.delete_one(user_template)
            print("user_template ", user_template)
            return jsonify({'msg': 'Template Deleted Sucessfully'}), 404
        # Returning message if template exists
        else: return jsonify({'msg': 'Template_name not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404




if __name__ == '__main__':
            app.run(debug=True)    




