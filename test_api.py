import requests

login = {
    "name" : "vance",
    "email": "de3pvalorant@gmail.com",
    "password": "123password"
}

headers = {"Authorization": "Bearer "}

status = requests.post("http://localhost:3333/register", json=login)

print(status.content)
print(status.status_code)
print()

status = requests.post("http://localhost:3333/login", json=login)

print(status.content)
print(status.status_code)
print()

status = requests.post("http://localhost:3333/forgot", json={"email" : login["email"]})

print(status.content)
print(status.status_code)
print()