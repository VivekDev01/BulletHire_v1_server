from flask import Flask, request, jsonify
import flask_cors
import pymongo
import yaml
from utils import *
import traceback
import jwt
import datetime

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
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing', 'status': False}), 401
        try:
            data = jwt.decode(token, config['secret_key'], algorithms=["HS256"])
            user = users_db['users'].find_one({'email': data['email']})
            if not user:
                return jsonify({'error': 'Invalid token', 'status': False}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired', 'status': False}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token', 'status': False}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/check_auth')
@flask_cors.cross_origin()
@authentication_required
def home():
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
            users_db['users'].update_one({'email': email}, {'$set': {'token': token}})
            return jsonify({'token': token, 'status': True, 'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid email or password', 'status': False}), 401
    except Exception as e:
        print(f"Error during login: {e}", flush=True)
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'status': False}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
