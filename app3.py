from flask import Flask, redirect, url_for, request, session, jsonify
import requests
import os
import base64
import time
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Replace with your LinkedIn app details
CLIENT_ID = '78ev5030fefrhp'
CLIENT_SECRET = 'YMyOket1yTD8pzZe'
REDIRECT_URI = 'http://127.0.0.1:5000/login/linkedin/authorized'
AUTH_URL = 'https://www.linkedin.com/oauth/v2/authorization'
TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken'
USERINFO_URL = 'https://api.linkedin.com/v2/userinfo'
EMAIL_URL = 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))'
CURRENT_POSITION_URL = 'https://api.linkedin.com/v2/positions'

@app.route('/')
def home():
    return 'Welcome to LinkedIn OAuth 2.0 with Flask and OpenID Connect!'

@app.route('/login')
def login():
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email w_member_social',
        'state': base64.urlsafe_b64encode(os.urandom(24)).decode('ascii')
    }
    auth_url = requests.Request('GET', AUTH_URL, params=params).prepare().url
    return redirect(auth_url)

@app.route('/login/linkedin/authorized')
def authorized():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code:
        return 'No code provided'

    token_params = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    token_response = requests.post(TOKEN_URL, data=token_params)
    token_data = token_response.json()

    session['access_token'] = token_data['access_token']
    session['expires_at'] = time.time() + token_data['expires_in']
    print('Token data:', json.dumps(token_data, indent=2))
    print("##################################################")

    return redirect(url_for('profile'))

def token_is_expired():
    expires_at = session.get('expires_at')
    if not expires_at:
        return True
    return time.time() > expires_at

@app.route('/profile')
def profile():
    if token_is_expired():
        return redirect(url_for('login'))

    access_token = session.get('access_token')
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    print("fetching user profile")
    # Fetch user profile
    profile_response = requests.get(USERINFO_URL, headers=headers)
    profile_data = profile_response.json()

    print('Profile data:', json.dumps(profile_data, indent=2))
    print("##################################################")

    # print("fetching user email")
    # # Fetch user email
    # email_response = requests.get(EMAIL_URL, headers=headers)
    # email_data = email_response.json()
    # email = email_data['elements'][0]['handle~']['emailAddress']

    # print('Email:', json.dumps(email, indent=2))    
    # print("##################################################")

    print("fetching user current position")
    # Fetch current position
    position_response = requests.get(CURRENT_POSITION_URL, headers=headers)
    position_data = position_response.json()

    print('Position data:', json.dumps(position_data, indent=2))
    print("##################################################")

    # profile_data['email'] = email
    profile_data['current_position'] = position_data.get('positions', {}).get('elements', [])

    return jsonify(profile_data)

@app.route('/logout')
def logout():
    #get access token
    access_token = session.get('access_token')
    # Endpoint to revoke the token
    revoke_url = 'https://www.linkedin.com/oauth/v2/revoke'

    # Headers and payload for the request
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'token': access_token
    }

    # Sending the POST request to revoke the token
    response = requests.post(revoke_url, headers=headers, data=payload)
    print('Logout response:', response)
    print("##################################################")

    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
