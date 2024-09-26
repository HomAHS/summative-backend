from pymongo import MongoClient
from cryptography.fernet import Fernet
from urllib.parse import quote_plus
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from bson import json_util
from smtplib import SMTP
import uuid

#STILL NEED TO ADD ERROR HANDLING ON FAILED
key = b'k8SYN9cfkSbhdUXivIjePBOFehJA7-yscCBRUH-zLvQ='
crypter = Fernet(key)


auth_key = "ls23ss345klma1hdu10sd7sjf"
refresh_key = "qsidwo3h3idjkq0wudetdw"

app = Flask(__name__)
CORS(app)

#reads the password from the textfile and decrypts it
def decrypt_password():
    with open("dbpassword.txt", "r") as f:
        encryped_password = f.read().encode()

    return crypter.decrypt(encryped_password).decode()

#adds a new user and encrypts password to the data base
def add_user(json):
    user = db["User"]
    user.insert_one(json)

#removes a user from the data base
def remove_user(json):
    user = db["User"]
    user.delete_one(json)

#logins into database server and selects the summative database to search
def login_database():
    password = quote_plus(decrypt_password())
    client = MongoClient(f"mongodb+srv://de3p:{password}@cluster0.x8yve.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    db = client["Summative"]
    return db

#used for calulating to index
def count_db(json):
    return db["User"].find(json)

#searches database
def search_db(json):
    return db["User"].find_one(json)

#checks if email exists or not
def check_email(json):
    account = db["User"].find_one({"email": json["email"]})
    if account != None:
        return True
    return False

#makes sure that that input arent left blank
#ADD SOME MORE INPUT SANTIZATION HERE
def check_inputs(json):
    if json["email"] or json["password"] != "":
        return True
    return False

#generates new token values
def create_new_token(id):
    refresh_token = jwt.encode({"id": id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)}, refresh_key, algorithm="HS256")
    access_token = jwt.encode({"id": id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, auth_key, algorithm="HS256")
    return access_token, refresh_token

#updates access token in the database for the user
def update_token(id):
    token = create_new_token(id)[0]
    db["User"].update_one({"id": id}, {"$set": {"token": token}})

#check for if the token is valid
def decode_token(token):
    try:
        # Decode the JWT token
        jwt.decode(token, auth_key, algorithms=["HS256"])
        return None
    except jwt.exceptions.InvalidTokenError:
        return jsonify({'error': 'Invalid token!'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired!'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 400


def send_email(email):
    server, port = ["smtp.gmail.com", 587]

    from_email = "prezdonaldtrump2024@gmail.com"
    password = "mryc azlr drvw rxwg"

    #change this to valid link
    user_data = db["User"].find_one({"email": email})
    token = user_data["token"]
    content = f"Heres the link to reseting your password: http://localhost:3333/reset?token={token}"
    to_email = email


    with SMTP(server, port) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(from_email, password)
        message = f"From: SUMMATIVE\nTo: {to_email}\nSubject: password reset link!\n\n{content}"
        try:
            smtp.sendmail(from_email, to_email, message)
            return jsonify({"message": "succsues!"}), 200
        except:
            return jsonify({"error": "invalid email"}), 401


#creates a new user
@app.route("/register", methods=["POST"])
def register():
    if check_inputs(request.json):
        if check_email(request.json) == False:
            hashed_password = crypter.encrypt(request.json["password"].encode())
            test_id = str(uuid.uuid4())
            access_token, refresh_token = create_new_token(test_id)
            user_data = {
                        "id": test_id,                
                        "name" : request.json["name"],
                        "email": request.json["email"],
                        "password": hashed_password.decode(), #hashed
                        "admin": False,
                        "ban": False,
                        "token": str(uuid.uuid4()),#for reset passworf,
                        "refreshToken": refresh_token
                        }
            
            add_user(user_data)
            del user_data["password"]
            return json_util.dumps({"user" : user_data, "accessToken": access_token, "refreshToken": refresh_token}), 201
    return jsonify({"error": "bad inputs"}), 400


#WORK HERE
#TEST THIS ON API
@app.route("/users/<user_id>", methods={"GET"})
def users(user_id):
    try:
        auth_token = request.headers.get("Authorization").split("Bearer ")[1]
    except:
        return {"error": "authorization header missing"}, 401
    

    result = decode_token(auth_token)
    if result == None:
        user_data = db["User"].find_one({"id": user_id})
        del user_data["password"]
        return json_util.dumps(user_data)
    else:
        return result

@app.route("/login", methods=["POST"])
def login():
    body = request.json

    account = search_db({"email": body["email"]})
    if account != None:
        request_password = crypter.decrypt(account["password"].encode()).decode()
        #FIX THIS RAW PASSWORD IS EXPOSED
        if request_password == body["password"]:
            account = search_db({"email": body["email"]})


            response = {"user": account, "accessToken": create_new_token(str(account["id"]))[0]}
            del response['user']["password"]
            return json_util.dumps(response), 201
    return jsonify({"error": "invalid login"}), 401

#SEE HOW THIS WILL WORK WITH POST OR SMMTHING
@app.route("/refresh", methods=["GET"])
def refresh():
    try:
        re_token = request.headers.get("Authorization").split("Bearer ")[1]
    except:
        return {"error": "authorization header missing"}, 401
    
    try:
        jwt.decode(re_token, refresh_key, algorithms=["HS256"])
    except:
        return jsonify({"error": "invalid token"})

    try:
        search = db["User"].find_one({"refreshToken": re_token})
    except:
        return jsonify({"error": "refreshToken attribute does not exist"}), 401
    if search != None:
        access, refresh = create_new_token(search["id"])
        db["User"].update_one({"id": search["id"]},{"$set": {"refreshToken": refresh}})
        response = db["User"].find_one({"id": search["id"]})
        del response["password"]
        return json_util.dumps({"user" : response, "refreshToken": refresh, "accessToken": access}), 200
    return jsonify({"error": "could not find user"}), 401

@app.route("/forgot", methods=["POST"])
def forgot():
    post = request.json

    try:
        status = send_email(post["email"])
        return status
    except:
        return jsonify({"error": "email does not exist!"}), 401


@app.route("/reset", methods=["POST"])
def reset():
    post = request.json
    #ERROR OCCURING HERE
    #ERROR: unhashable type: 'dict'
    password = crypter.encrypt(post["newPassword"].encode()).decode()

    try:
        
        user = db["User"].find_one({"token": post["token"]})
        if user != None:
            new_token = str(uuid.uuid4())
            db["User"].update_one({"id": user["id"]}, {"$set": {"password": password}})
            db["User"].update_one({"id": user["id"]}, {"$set": {"token": new_token}})
            return jsonify({"message": "password changed!"}), 200
    except Exception as e:
        print(e)
    
    return jsonify({"error" : "bad token"}), 401
    

if __name__ == "__main__":
    db = login_database()
    app.run(host="0.0.0.0", port=3333)
