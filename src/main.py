from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi import Request, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import pymongo
import yaml
from utils import *
import traceback
import jwt
import datetime
from functools import wraps

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from hr_agent.create_jd import jd_create
from hr_agent.linkedin_post import post_jd_on_linkedin
from hr_agent.resume_selection import select_send_email
from hr_agent.question_generation import generate_questions
from hr_agent.linkedin_auth import router as linkedin_router

config = yaml.load(open("/src/config.yaml"), Loader=yaml.FullLoader)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config['frontend_url']],  # Frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(linkedin_router)

users_db_creds = config['users_db_credentials']
client_web = pymongo.MongoClient(users_db_creds['service'], users_db_creds['port'], username=users_db_creds['username'], password=users_db_creds['password'])
users_db = client_web[users_db_creds['db']]

data_db_credentials = config['data_db_credentials']
client_data = pymongo.MongoClient(data_db_credentials['service'], data_db_credentials['port'], username=data_db_credentials['username'], password=data_db_credentials['password'])
data_db = client_data[data_db_credentials['db']]

def authentication_required(request: Request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or len(auth_header.split()) != 2:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Bad authorization header')
    bearer_token = auth_header.split()[1]
    try:
        data = jwt.decode(bearer_token, config['secret_key'], algorithms=["HS256"])
    except Exception as e:
        print('Error: ', e, flush=True)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    if not data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    return data

def get_user(token_data):
    email = token_data.get('email')
    if not email:
        return None
    user = users_db['users'].find_one({'email': email})
    if user:
        return {
            '_id': str(user.get('_id')),
            'username': user.get('username', ''),
            'email': user.get('email', ''),
            'password': user.get('password', ''),
        }
    return None

@app.get('/check')
def home():
    return 'Hello, FastAPI!'

@app.get('/check_auth')
def check_auth2(dep=Depends(authentication_required)):
    return {'message': 'Hello, FastAPI!', 'user': dep}

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
@app.post('/api/signup')
def signup(signup_request: SignupRequest):
    try:
        payload = signup_request.dict()
        username = payload.get('username', '')
        email = payload.get('email', '')
        password = payload.get('password', '')
        if users_db['users'].find_one({'email': email}):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Email already exists')
        hashed_password = generate_password_hash(password)
        users_db['users'].insert_one({
            'username': username,
            'email': email,
            'password': hashed_password
        })
        return {'message': 'User created successfully', 'status': True}, 201
    except Exception as e:
        print(f"Error during signup: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')

class LoginRequest(BaseModel):
    email: str
    password: str
@app.post('/api/login')
def login(login_request: LoginRequest):
    try:
        email = login_request.email
        password = login_request.password
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
            return JSONResponse(status_code=200, content={'token': token, 'status': True})
        else:
            return JSONResponse(status_code=401, content={'error': 'Invalid email or password', 'status': False})
    except Exception as e:
        print(f"Error during login: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')

@app.post('/api/logout')
def logout(token_data: dict = Depends(authentication_required)):
    try:
        user = get_user(token_data)
        if user:
            users_db['users'].update_one({'email': user['email']}, {'$unset': {'token': ''}})
            return {'message': 'Logout successful', 'status': True}, 200
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    except Exception as e:
        print(f"Error during logout: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')

@app.get('/api/get_user')
def get_user_api(token_data: dict = Depends(authentication_required)):
    try:
        user = get_user(token_data)
        if user:
            return JSONResponse(status_code=200, content={'user': user, 'status': True})
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    except Exception as e:
        print(f"Error during get_user: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')

# job description creation and management
class jd_data(BaseModel):
    role : str
    location : str
    skills : str
    experience : int
    education : str
    link: str
@app.post("/create_jd")
def create_job_description(data: jd_data, dep=Depends(authentication_required)):
    jd_id = uuid.uuid4().hex
    data.link = f"/job/{jd_id}/apply"
    jd = jd_create(data)
    user_data = get_user(dep)
    if not user_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")
    payload = {
        "_id": jd_id,
        "jd": jd,
        "role": data.role,
        "location": data.location,
        "skills": data.skills,
        "experience": data.experience,
        "education": data.education,
        "link": data.link,
        "user_id": user_data['_id'],
        "created_at": datetime.datetime.utcnow()
    }
    data_db['job_descriptions'].insert_one(payload)
    return JSONResponse(status_code=200, content={"message": 'Job description created successfully', "job_id": jd_id})

@app.get("/get_jd/{jd_id}")
def get_job_description(jd_id: str, dep=Depends(authentication_required)):
    try:
        job = data_db['job_descriptions'].find_one({"_id": jd_id})
        if job:
            return JSONResponse(status_code=200, content={"job": job})
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job description not found")
    except Exception as e:
        return JSONResponse(status_code=500, content=str(e))

@app.post("/post_on_linkedin")
def post_on_linkedin(jd:str, dep=Depends(authentication_required)):
    try:
        response = post_jd_on_linkedin(jd)
        return JSONResponse(status_code=200, content={"response": response})
    except Exception as e:
        return JSONResponse(status_code=500, content=str(e))

@app.post("/select_candidates")
def select_candidates(jd:str, dep=Depends(authentication_required)):
    try:
        response = select_send_email(jd)
        return JSONResponse(status_code=200, content={'response': response})
    except Exception as e:
        return JSONResponse(status_code=500, content=str(e))

class KeywordRequest(BaseModel):
    keywords: str
@app.post("/create_questions")
def create_questions(request: KeywordRequest, dep=Depends(authentication_required)):
    try:
        response = generate_questions(request.keywords)
        return JSONResponse(status_code=200, content={"response": response})
    except Exception as e:
        return JSONResponse(status_code=500, content=str(e))
