from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import secrets
import requests


app = Flask(__name__)
app.secret_key = 'random_secret_key'
app.config['SESSION_COOKIE_NAME'] = 'linkedin-login-session'

client_id='78ev5030fefrhp'
client_secret='JsRHjvngGsN5CTY0'

# Setup OAuth
oauth = OAuth(app)
linkedin = oauth.register(
    'linkedin',
    client_id=client_id,
    client_secret=client_secret,
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    authorize_params={'scope': 'openid profile email'},  # Include nonce
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    access_token_params=None,
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri='https://www.linkedin.com/oauth/openid/jwks',
)

@app.route('/')
def index():
    return 'Welcome to LinkedIn OAuth Login'

@app.route('/login')
def login():
    return linkedin.authorize_redirect(redirect_uri=url_for('authorized', _external=True))

@app.route('/logout')
def logout():
    session.pop('linkedin_token', None)
    return redirect(url_for('index'))

@app.route('/login/linkedin/authorized')
def authorized():
    print('Authorized')
    try:
        # Explicitly include client_secret in the token request
        print('Requesting token')

        # Extract the authorization code from the request
        code = request.args.get('code')
        if not code:
            raise Exception('Authorization code not found.')

        print('Authorization code:', code)
        
        # Define the parameters for the POST request
        url = 'https://www.linkedin.com/oauth/v2/accessToken'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': url_for('authorized', _external=True),
        }

        # Make the POST request
        response = requests.post(url, headers=headers, data=data)
        print('Response:', response.json())

        access_token = response.json()['access_token']
        
        print('Access token:', access_token)
        # Define the endpoint and headers
        url = 'https://api.linkedin.com/v2/userinfo'
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        # Make the GET request
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            user_info = response.json()
            print('User Info:', user_info)
        else:
            print('Failed to get user info:', response.status_code, response.text)
        
        
        return user_info
        

    except Exception as e:
        print('Error during authorization:', str(e))
        return 'Authorization failed.'


if __name__ == '__main__':
    app.run(debug=True)

