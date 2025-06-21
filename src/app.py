from flask import Flask, request, jsonify
import flask_cors
import pymongo
import yaml
from utils import *
import traceback
import jwt
import datetime
from functools import wraps


config = yaml.load(open("/src/config.yaml"), Loader=yaml.FullLoader)
users_db_creds = config['users_db_credentials']
client_web = pymongo.MongoClient(users_db_creds['service'], users_db_creds['port'], username=users_db_creds['username'], password=users_db_creds['password'])
users_db = client_web[users_db_creds['db']]
print('list of collections in users_db:', users_db.list_collection_names(), flush=True)

app = Flask(__name__)
cors = flask_cors.CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/check')
def home():
    return 'Hello, Flask!'


def authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            if len(auth_header.split()) != 2:
                return 'Bad authorization header', 400  
            bearer_token = auth_header.split()[1]
        try:
            data = jwt.decode(bearer_token, config['secret_key'], algorithms=["HS256"])
        except Exception as e:
            print('Error: ', e, flush=True)
            return jsonify({'error': e, 'status': False}), 401
        if not data:
            return jsonify({'error': 'Invalid token', 'status': False}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_user(request):
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token_arr = auth_header.split(" ")
            if len(auth_token_arr) == 2:
                auth_token = auth_token_arr[1]
                data = jwt.decode(auth_token, config['secret_key'], algorithms=["HS256"])
                if data:
                    email = data.get('email')
                    if email:
                        user = users_db['users'].find_one({'email': email})
                        if user:
                            user_data = {
                                '_id': str(user.get('_id')),
                                'username': user.get('username', ''),
                                'email': user.get('email', ''),
                                'password': user.get('password', ''),
                            }
                            return user_data
                        else:
                            print('User not found', flush=True)
                            return None
                    else:
                        print('Email not found in token', flush=True)
                        return None
    except Exception as e:
        print('Error: ', e, flush=True)
        return None

@app.route('/check_auth')
@flask_cors.cross_origin()
@authentication_required
def check_auth2():
    return 'Hello, Flask!'

@app.route('/api/signup', methods=['POST'])
@flask_cors.cross_origin()
def signup():
    try:
        payload = request.get_json()
        username = payload.get('username', '')
        email = payload.get('email', '')
        password = payload.get('password', '')
        if users_db['users'].find_one({'email': email}):
            return jsonify({'error': 'Username already exists', 'status': False}), 400
        else:
            hashed_password = generate_password_hash(password)
            users_db['users'].insert_one({
                'username': username,
                'email': email,
                'password': hashed_password
            })
            return jsonify({'message': 'User created successfully', 'status': True}), 201
    except Exception as e:
        print(f"Error during signup: {e}", flush=True)
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'status': False}), 500

@app.route('/api/login', methods=['POST'])
@flask_cors.cross_origin()
def login():
    try:
        payload = request.get_json()
        email = payload.get('email', '')
        password = payload.get('password', '')
        user = users_db['users'].find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            data = {
                'username': user['username'],
                'email': user['email'],
                'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            token = jwt.encode(data, config['secret_key'], algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode('utf-8')
            users_db['users'].update_one({'email': email}, {'$set': {'token': token}})
            return jsonify({'token': token, 'status': True, 'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid email or password', 'status': False}), 401
    except Exception as e:
        print(f"Error during login: {e}", flush=True)
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'status': False}), 500

@app.route('/api/logout', methods=['POST'])
@flask_cors.cross_origin()
@authentication_required
def logout():
    try:
        user = get_user(request)
        if user:
            users_db['users'].update_one({'email': user['email']}, {'$unset': {'token': ''}})
            return jsonify({'message': 'Logout successful', 'status': True}), 200
        else:
            return jsonify({'error': 'User not found', 'status': False}), 404
    except Exception as e:
        print(f"Error during logout: {e}", flush=True)
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'status': False}), 500

@app.route('/api/get_user', methods=['GET'])
@flask_cors.cross_origin()
@authentication_required
def get_user_api():
    try:
        user = get_user(request)
        if user:
            return jsonify({'user': user, 'status': True}), 200
        else:
            return jsonify({'error': 'User not found', 'status': False}), 404
    except Exception as e:
        print(f"Error during get_user: {e}", flush=True)
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'status': False}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
