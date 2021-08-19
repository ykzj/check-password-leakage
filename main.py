import base64
import hashlib
import requests
import json
import google.auth
import google.auth.transport.requests
from flask import Flask,Response
from flask import request as flask_request

# Scrypt hash salt
USER_CREDENTIALS_HASH_SALT = [
  48, 118, 42, 210, 63, 123, 161, 155, 248, 227, 66, 252, 161, 167, 141, 6,
  230, 107, 228, 219, 184, 79, 129, 83, 197, 3, 200, 219, 189, 222, 165, 32
]

# Scrypt hash parameters and constants
SCRYPT_HASH_CPU_MEM_COST = 1 << 12
SCRYPT_HASH_BLOCK_SIZE = 8
SCRYPT_HASH_PARALLELIZATION = 1
SCRYPT_MAX_MEMORY = 1024 * 1024 * 32
SCRYPT_HASH_KEY_LENGTH = 32

# getting the credentials and project details for gcp project
credentials, your_project_id = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])

#getting request object
auth_req = google.auth.transport.requests.Request()
credentials.refresh(auth_req) #refresh token
access_token = credentials.token
url = 'https://recaptchaenterprise.googleapis.com/v1beta1/projects/{}/assessments'.format(your_project_id)

headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'Authorization': 'Bearer ' + access_token
    }

def canonicalize_username(username):
  """Canonicalize a username which must be a UTF-8 encoded string."""
  if '@' in username:
    username = username[:username.rfind('@')]
  return username.lower().replace('.', '')

def process_credentials(username, password):
  """Process user credentials to be used with the credentials check service."""
  

  canonicalized_username = canonicalize_username(username)

  # Compute the salt by appending the username to the fixed hash salt.
  salt = bytes([ord(character) for character in list(canonicalized_username)] +
               USER_CREDENTIALS_HASH_SALT)

  # Compute the data to be hashed
  data = bytes(canonicalized_username + password, encoding='utf8')

  # Compute Scrypt hash using hashlib.
  scrypt_hash = hashlib.scrypt(
      password=data,
      salt=salt,
      n=SCRYPT_HASH_CPU_MEM_COST,
      r=SCRYPT_HASH_BLOCK_SIZE,
      p=SCRYPT_HASH_PARALLELIZATION,
      maxmem=SCRYPT_MAX_MEMORY,
      dklen=SCRYPT_HASH_KEY_LENGTH)
  return canonicalized_username, base64.b64encode(scrypt_hash)

app = Flask(__name__)

@app.route('/', methods=['POST', 'OPTIONS'])
def check_leakage():
    if flask_request.method == 'POST':
        content = flask_request.get_json()
        username = content['username']
        password = content['password']
        canonicalized_username,hashed_user_credentials = process_credentials(username, password)
        data = {'password_leak_verification': {
              'canonicalized_username': canonicalized_username,
              'hashed_user_credentials': hashed_user_credentials.decode('utf-8')
            }
          }
        post_data = json.dumps(data)
        r = requests.post(url, data=post_data, headers=headers)
        resp = r.json()
        return str(resp['passwordLeakVerification']['credentialsLeaked'])

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))