from pymongo import MongoClient
from cryptography.fernet import Fernet
from urllib.parse import quote_plus
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from bson import json_util
from smtplib import SMTP

#STILL NEED TO ADD ERROR HANDLING ON FAILED
key = b'k8SYN9cfkSbhdUXivIjePBOFehJA7-yscCBRUH-zLvQ='
crypter = Fernet(key)


secret_key = "ls23ss345klma1hdu10sd7sjf"

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
    refresh_token = jwt.encode({"id": id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=14)}, secret_key, algorithm="HS256")
    access_token = jwt.encode({"id": id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=20)}, secret_key, algorithm="HS256")
    return access_token, refresh_token

#updates access token in the database for the user
def update_token(id):
    token = create_new_token(id)[0]
    db["User"].update_one({"id": id}, {"$set": {"token": token}})

def refresh_tokens(id):
    auth, fresh = create_new_token(id)
    db["User"].update_one({"id": id}, {"$set": {"token": auth}})
    db["User"].update_one({"id": id}, {"$set": {"refreshToken": fresh}})

#check for if the token is valid
def decode_token(token, userdata):
    try:
        # Decode the JWT token
        jwt.decode(token, secret_key, algorithms=["HS256"])
        if token != userdata["token"]:
            return json_util.dumps({"error": "wrong user token"})
        return json_util.dumps({'payload': userdata}), 200
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
    token = user_data["refreshToken"]
    content = f"Heres the link to reseting your password: http://localhost:3333/refresh?refreshToken={token}"
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
            test = count_db({})
            num = 1
            for ii in test:
                num += 1
            access_token, refresh_token = create_new_token(num)
            user_data = {
                        "id": num,
                        "name" : request.json["name"],
                        "email": request.json["email"],
                        "password": hashed_password.decode(), #hashed
                        "admin": False,
                        "ban": False,
                        "token": access_token,
                        "refreshToken": refresh_token
                        }
            
            add_user(user_data)
            return json_util.dumps(user_data), 201
    return jsonify({"error": "bad inputs"}), 400

@app.route("/users/<user_id>", methods={"GET"})
def users(user_id):
    auth_token = request.headers.get("Authorization").split("Bearer ")[1]
    if auth_token == None:
        return {"error": "authorization header missing"}, 401
    
    print(auth_token)
    user_data = db["User"].find_one({"id": int(user_id)})
    return decode_token(auth_token, user_data)

@app.route("/login", methods=["POST"])
def login():
    body = request.json

    account = search_db({"email": body["email"]})
    if account != None:
        request_password = crypter.decrypt(account["password"].encode()).decode()
        #FIX THIS RAW PASSWORD IS EXPOSED
        if request_password == body["password"]:
            update_token(account["id"])
            account = search_db({"email": body["email"]})
            return json_util.dumps(account), 201
    return jsonify({"error": "invalid login"}), 401

#SEE HOW THIS WILL WORK WITH POST OR SMMTHING
@app.route("/refresh", methods=["POST"])
def refresh():
    post = request.json
    
    try:
        jwt.decode(post["refreshToken"], secret_key, algorithms=["HS256"])
    except:
        return jsonify({"error": "invalid token"})

    try:
        search = db["User"].find_one({"refreshToken": post["refreshToken"]})
    except:
        return jsonify({"error": "refreshToken attribute does not exist"}), 401
    if search != None:
        refresh_tokens(search["id"])
        db["User"].update_one({"id": search["id"]},{"$set": {"password": crypter.encrypt(str(post["newPassword"]).encode()).decode()}} )
        return json_util.dumps(db["User"].find_one({"id": search["id"]})), 200
    return jsonify({"error": "could not find user"}), 401

@app.route("/forgot", methods=["POST"])
def forgot():
    post = request.json

    try:
        status = send_email(post["email"])
        return status
    except:
        return jsonify({"error": "email does not exist!"}), 401

@app.router("/reset", methods=["POST"])
def reset():
    post = request.json
    try:
        jwt.decode(post["refreshToken"], secret_key, algorithms=["HS256"])
    except:
        return jsonify({"error": "invalid token"})
    
    db["User"].insert_one({"refreshToken": post["refreshToken"]}, {"$set": {"password": crypter.encrypt(str(post["password"]).encode()).decode()}})
    return jsonify({"message": "password changed!"})
    

if __name__ == "__main__":
    db = login_database()
    app.run(host="0.0.0.0", port=3333)
