from pymongo import MongoClient
from cryptography.fernet import Fernet
from urllib.parse import quote_plus
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from bson import json_util
from bson.objectid import ObjectId
from smtplib import SMTP
import uuid
import sys

#NOTES FOR NEXT TIME
#1. REMOVE SENSTIVE KEY VALUES FROM USER OBJECT ON RETURN FROM API
#2. PROB SHOULD ADD SMTP LOGIN TO .ENV FILE
#3. ADD /users AND CHECK ACCESS TOKEN FOR ADMIN
#4. ADD A PATCH AND DELETE ON /user/:id AND CHECK FOR ADMIN

#THE .ENV FILE KEY ORDER
#encryotion key
#acces token key
#refersh token key
#encrypted password
#mongo db link

all_passwords = None

try:
    with open(".env", "r") as f:
        all_passwords = f.read().split("\n")
except:
    print("failed to read .env file")
    sys.exit()

key = all_passwords[0].encode()
crypter = Fernet(key)

auth_key = all_passwords[1]
refresh_key = all_passwords[2]

app = Flask(__name__)
CORS(app)

#reads the password from the textfile and decrypts it
def decrypt_password():
    encryped_password = all_passwords[3].encode()

    return crypter.decrypt(encryped_password).decode()


#logins into database server and selects the summative database to search
def login_database():
    password = quote_plus(decrypt_password())
    split_db_url = all_passwords[4].split("!")
    client = MongoClient(split_db_url[0] + password + split_db_url[1])
    db = client["Summative"]
    return db

#checks if email exists or not
def check_email(json):
    account = db["User"].find_one({"email": json["email"]})
    if account != None:
        return True
    return False

#makes sure that that input arent left blank
#ADD SOME MORE INPUT SANTIZATION HERE
def check_inputs(json):
    if json["email"] and json["password"] and json["name"] != "":
        return True
    return False

#generates new token values
def create_new_token(id):
    refresh_token = jwt.encode({"id": id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)}, refresh_key, algorithm="HS256")
    access_token = jwt.encode({"id": id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, auth_key, algorithm="HS256")
    return access_token, refresh_token

#check for if the token is valid
def decode_token(token):
    try:
        # Decode the JWT token
        token_data = jwt.decode(token, auth_key, algorithms=["HS256"])
        return [None, token_data]
    except jwt.exceptions.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except Exception as e:
        return jsonify({'message': str(e)}), 400


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
            return jsonify({"message": "email sent!"}), 200
        except:
            return jsonify({"message": "invalid email"}), 401


#creates a new user
@app.route("/register", methods=["POST"])
def register():
    try:
        if check_inputs(request.json):
            if check_email(request.json) == False:
                hashed_password = crypter.encrypt(request.json["password"].encode())
                user_data = {
                
                            "name" : request.json["name"],
                            "email": request.json["email"],
                            "password": hashed_password.decode(), #hashed
                            "admin": False,
                            "ban": False,
                            "token": str(uuid.uuid4()),#for reset passworf,
                            "refreshToken": ""
                            }
                
                db["User"].insert_one(user_data)
                person = db["User"].find_one({"email": request.json["email"]})
                access_token, refresh_token = create_new_token(str(person["_id"]))
                db["User"].update_one({"_id" : person["_id"]}, {"$set": {"refreshToken": refresh_token}})
                person = db["User"].find_one({"_id": person["_id"]})
                del person["password"]
                return json_util.dumps({"user" : user_data, "accessToken": access_token, "refreshToken": refresh_token}), 201
    except:
        return jsonify({"message": "invalid request"}), 400
    return jsonify({"message": "name, email, and or password field is missing"}), 400


#THIS SHIT IS MESSY ASF FIX IT LATER
@app.route("/users/<user_id>", methods={"GET"})
def users(user_id):
    try:
        auth_token = request.headers.get("Authorization").split("Bearer ")[1]
    except:
        return {"message": "authorization header missing"}, 401
    result = decode_token(auth_token) #this is that one function

    #RIGHT HERE IF YOU DFONT SEE THIS SHIT
    try:
        if result[0] == None:
            object_id = result[1].get("id")
            if object_id == user_id:
                user_data = db["User"].find_one({"_id": ObjectId(result[1].get("id"))})
                del user_data["password"]
                return json_util.dumps(user_data)
            else:
                return jsonify({"message": "id dont match"}), 401
        else:
            return result #call that one function that check token and returns message
    except:
        return jsonify({"message": "bad id inside token"}), 401

@app.route("/login", methods=["POST"])
def login():
    body = request.json
    try:
        account = db["User"].find_one({"email": body["email"]})
        if account != None:
            request_password = crypter.decrypt(account["password"].encode()).decode()
            #FIX THIS RAW PASSWORD IS EXPOSED
            if request_password == body["password"]:
                account = db["User"].find_one({"email": body["email"]})
                response = {"user": account, "accessToken": create_new_token(str(account["_id"]))[0]}
                del response['user']["password"]
                return json_util.dumps(response), 201
    except:
        return jsonify({"message": "invalid request"}), 400
    return jsonify({"message": "invalid login"}), 401

#SEE HOW THIS WILL WORK WITH POST OR SMMTHING
@app.route("/refresh", methods=["GET"])
def refresh():
    try:
        re_token = request.headers.get("Authorization").split("Bearer ")[1]
    except:
        return {"message": "authorization header missing"}, 401
    
    try:
        jwt.decode(re_token, refresh_key, algorithms=["HS256"])
    except:
        return jsonify({"message": "invalid token"}), 401

    try:
        search = db["User"].find_one({"refreshToken": re_token})
    except:
        return jsonify({"error": "refreshToken attribute does not exist"}), 401
    try:
        if search != None:
            access, refresh = create_new_token(str(search["_id"]))
            db["User"].update_one({"_id": search["_id"]},{"$set": {"refreshToken": refresh}})
            response = db["User"].find_one({"_id": search["_id"]})
            del response["password"]
            return json_util.dumps({"user" : response, "refreshToken": refresh, "accessToken": access}), 200
    except:
        return jsonify({"message" : "invalid request"}), 401
    return jsonify({"message": "could not find user"}), 401

@app.route("/forgot", methods=["POST"])
def forgot():
    post = request.json

    try:
        status = send_email(post["email"])
        return status
    except:
        return jsonify({"message": "email does not exist!"}), 401


@app.route("/reset", methods=["POST"])
def reset():
    post = request.json
    try:
        if post['newPassword'] != "":
            password = crypter.encrypt(post["newPassword"].encode()).decode()    
            user = db["User"].find_one({"token": post["token"]})
            if user != None:
                new_token = str(uuid.uuid4())
                db["User"].update_one({"_id": user["_id"]}, {"$set": {"password": password}})
                db["User"].update_one({"_id": user["_id"]}, {"$set": {"token": new_token}})
                return jsonify({"message": "password changed!"}), 200
    except Exception as e:
        print(e)
    
    return jsonify({"error" : "bad token"}), 401
    

if __name__ == "__main__":
    db = login_database()
    app.run(host="0.0.0.0", port=3333)
