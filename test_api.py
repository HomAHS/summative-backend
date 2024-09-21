import requests

status = requests.post("http://localhost:3333/api/newuser", json={"hey": 2})

print(status.status_code)