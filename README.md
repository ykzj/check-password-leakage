<walkthrough-project-setup>
</walkthrough-project-setup>

# GCP密码泄漏检测方案
## 概述
用户密码泄漏会给应用开发者带来以下潜在风险：
1. 账户接管：账户被恶意接管，导致用户无法正常登录
2. 欺诈交易：利用用户的支付信息进行欺诈交易，导致用户财产损失
3. 商誉损失：公布用户密码泄漏信息，导致开发者的商业信誉受损

通过谷歌云的[reCAPTCHA Enterprise](https://cloud.google.com/recaptcha-enterprise) 服务的密码泄漏检测功能，可以以API方式查询用户的密码是否泄漏，对存在泄漏可能的用户发出提醒，提醒用户及时更改密码。


## 原理
谷歌云reCAPTCHA Enterprise通过一个endpoint提供密码泄漏检测服务，开发者将规范化后的用户名和经过哈希处理的密码以POST方式提交到服务的endpoint，便可获得检测结果。

服务的Endpoint为： [https://recaptchaenterprise.googleapis.com/v1beta1/projects/<PROJECT_ID>/assessments](https://recaptchaenterprise.googleapis.com/v1beta1/projects/<PROJECT_ID>/assessments)

<PROJECT_ID>需替换成谷歌云项目的ID

提交的POST请求负载为JSON格式：

```json
{
  "password_leak_verification": {
    "canonicalized_username": "CANONICALIZED_USERNAME"
    "hashed_user_credentials": "HASHED_USER_CREDENTIALS"
  }
}
```

### 规范化用户名

规范化用户名对用户名进行下列处理：
1. 将用户名转换成小写

2. 删除域名部分

3. 删除用户名中所有的点(.)

例如:

  `canonicalize(foo.bar@COM) = foobar`

  `canonicalize(TEST@MAIL.COM) = test`

 Python代码如下：

```python
#!/usr/bin/env python3

def canonicalize_username(username):
  """Canonicalize a username which must be a UTF-8 encoded string."""
  if "@" in username:
    username = username[:username.rfind("@")]
  return username.lower().replace(".", "")
```

 

### 密码哈希

密码哈希通过下列公式进行计算：

`Scrypt(canonicalized_username + password + username_updated_salt)`

其中：username_updated_salt = canonicalized_username + fixed_salt，canonicalized_username为规范化用户名。

Python代码如下：

```python
#!/usr/bin/env python3
import base64
import hashlib

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

def process_credentials(username, password):
  """Process user credentials to be used with the credentials check service."""

  canonicalized_username = canonicalize_username(username)

  # Compute the salt by appending the username to the fixed hash salt.
  salt = bytes([ord(character) for character in list(canonicalized_username)] +
               USER_CREDENTIALS_HASH_SALT)

  # Compute the data to be hashed
  data = bytes(canonicalized_username + password, encoding="utf8")

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
```

## 实现

由于密码检测服务的endpoint需要通过认证后才能访问，我们可以构建一个Python应用，实现认证和信息处理。
```python
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

def check_leakage(username, password):
  canonicalized_username,hashed_user_credentials = process_credentials(username, password)
  data = {'password_leak_verification': {
            'canonicalized_username': canonicalized_username,
            'hashed_user_credentials': hashed_user_credentials.decode('utf-8')
            }
          }
  post_data = json.dumps(data)
  r = requests.post(url, data=post_data, headers=headers)
  resp = r.json()
  return resp['passwordLeakVerification']['credentialsLeaked']

if __name__ == '__main__':
    #从数据库中获取用户名和密码后
    check_leakage(<user>, <pass>)
```

## 完善

目前密码检测服务endpoint只支持一次验证一对用户名和密码，为了批量检测用户名和密码，我们可以构建一个新的服务端点，用来接收用户提交的用户名/密码数组，然后依次请求reCAPTCHA enterprise的服务端点。为此，我们可以构建一个[Cloud Run](https://cloud.google.com/run) 服务,用于对服务进行封装和完善。