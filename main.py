from pymongo import MongoClient
from cryptography.fernet import Fernet
from urllib.parse import quote_plus
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

userobj = {
    "username": None,
    "password": None,
}

def decrypt_password():
    key = b'k8SYN9cfkSbhdUXivIjePBOFehJA7-yscCBRUH-zLvQ='
    crypter = Fernet(key)
    with open("dbpassword.txt", "r") as f:
        encryped_password = f.read().encode()

    return crypter.decrypt(encryped_password).decode()

def add_user(database, json):
    user = database["User"]
    user.insert_one(json)

def remove_user(database, json):
    user = database["User"]
    user.delete_one(json)

def login_database():
    password = quote_plus(decrypt_password())
    client = MongoClient(f"mongodb+srv://de3p:{password}@cluster0.x8yve.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    db = client["Summative"]

    return db

@app.route("/api/newuser", methods=["POST"])
def new_user():
    add_user(db, request.json)
    return ""

if __name__ == "__main__":
    db = login_database()
    app.run(host="0.0.0.0", port=3333)