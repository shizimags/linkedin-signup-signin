from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import secrets
import requests
import json
import time

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
app.config['SESSION_COOKIE_NAME'] = 'linkedin-login-session'

client_id = '78ev5030fefrhp'
client_secret = 'JsRHjvngGsN5CTY0'

# Setup OAuth
oauth = OAuth(app)
linkedin = oauth.register(
    'linkedin',
    client_id=client_id,
    client_secret=client_secret,
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    authorize_params={'scope': 'r_liteprofile r_emailaddress w_member_social'},
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    access_token_params=None,
    client_kwargs={'scope': 'r_liteprofile r_emailaddress w_member_social'},
)

@app.route('/')
def index():
    return 'Welcome to LinkedIn OAuth Login'

@app.route('/login')
def login():
    return linkedin.authorize_redirect(redirect_uri=url_for('authorized', _external=True))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/login/linkedin/authorized')
def authorized():
    try:
        token = linkedin.authorize_access_token()
        access_token = token['access_token']
        refresh_token = token.get('refresh_token')
        expires_in = token['expires_in']
        expires_at = time.time() + expires_in

        session['linkedin_token'] = access_token
        session['refresh_token'] = refresh_token
        session['expires_at'] = expires_at

        return redirect(url_for('profile'))
    except Exception as e:
        print('Error during authorization:', str(e))
        return 'Authorization failed.'

def refresh_access_token(refresh_token):
    url = 'https://www.linkedin.com/oauth/v2/accessToken'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret,
    }

    response = requests.post(url, headers=headers, data=data)
    response_data = response.json()

    if 'access_token' in response_data:
        access_token = response_data['access_token']
        expires_in = response_data['expires_in']
        expires_at = time.time() + expires_in
        return access_token, expires_at
    else:
        raise Exception('Failed to refresh access token.')

@app.route('/profile')
def profile():
    if 'linkedin_token' not in session or 'expires_at' not in session:
        return redirect(url_for('login'))

    access_token = session['linkedin_token']
    refresh_token = session.get('refresh_token')
    expires_at = session['expires_at']

    if time.time() > expires_at:
        if refresh_token:
            try:
                access_token, expires_at = refresh_access_token(refresh_token)
                session['linkedin_token'] = access_token
                session['expires_at'] = expires_at
            except Exception as e:
                print('Error during token refresh:', str(e))
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))

    url = 'https://api.linkedin.com/v2/userinfo `'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        return json.dumps(user_info, indent=4)
    else:
        return f"Failed to get user info: {response.status_code} {response.text}"

if __name__ == '__main__':
    app.run(debug=True)
