from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import secrets


app = Flask(__name__)
app.secret_key = 'random_secret_key'
app.config['SESSION_COOKIE_NAME'] = 'linkedin-login-session'

# Setup OAuth
oauth = OAuth(app)
linkedin = oauth.register(
    'linkedin',
    client_id='78ev5030fefrhp',
    client_secret='JsRHjvngGsN5CTY0',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    authorize_params={'scope': 'openid profile email', 'nonce': secrets.token_urlsafe(16)},  # Include nonce
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
    try:
        # Explicitly include client_secret in the token request
        token = linkedin.authorize_access_token(
            client_secret='JsRHjvngGsN5CTY0'
        )
        print('Token received:', token)
        
        resp = linkedin.get('https://api.linkedin.com/v2/me')
        user_info = resp.json()
        print('User Info:', user_info)
        
        resp_email = linkedin.get('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))')
        email_info = resp_email.json()
        print('Email Info:', email_info)
        
        return f'Logged in as: {user_info["localizedFirstName"]["localized"]["en_US"]} {email_info["elements"][0]["handle~"]["emailAddress"]}'
    except Exception as e:
        print('Error during authorization:', str(e))
        return 'Authorization failed.'

if __name__ == '__main__':
    app.run(debug=True)

