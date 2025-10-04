from fastapi.responses import JSONResponse
from fastapi import FastAPI, File, Request, HTTPException, status, Depends, UploadFile, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uuid
import pymongo
import yaml
from utils import *
import traceback
import jwt
from datetime import datetime, timedelta
import pytz
from functools import wraps
from bson import ObjectId
import os
import random
from typing import Optional
import redis
import requests
from jinja2 import Environment, FileSystemLoader
import boto3


# oAuth
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

r = redis.Redis(host=os.getenv('redis_host'), port=os.getenv('redis_port'), db=0, decode_responses=True)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL_DEVELOPMENT"), os.getenv("FRONTEND_URL_PRODUCTION")],  # Frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# oAuth
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))

oAuth_config = Config(environ=os.environ)
oauth = OAuth(oAuth_config)

oauth.register(
    name='google',
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# DynamoDB
dynamodb = boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION'), aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
users_table = dynamodb.Table('Users')
job_descriptions_table = dynamodb.Table('JobDescriptions')
posts_table = dynamodb.Table('Posts')

# S3 Bucket
S3 = boto3.client('s3', region_name=os.getenv('AWS_REGION'), aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))

# Create TTL index on 'expires_at' field to auto-delete unverified users after 10 minutes
# users_table.create_global_secondary_index(
#     IndexName='expires_at_index',
#     KeySchema=[
#         {
#             'AttributeName': 'expires_at',
#             'KeyType': 'HASH'
#         }
#     ],
#     Projection={
#         'ProjectionType': 'ALL'
#     },
#     TimeToLiveSpecification={
#         'Enabled': True,
#         'AttributeName': 'expires_at'
#     }
# )

# app.mount("/media", StaticFiles(directory=uploads_directory), name="media")

IST = pytz.timezone("Asia/Kolkata")

# OAuth login route
@app.get('/auth/login')
async def auth_login(request: Request):
    redirect_uri = request.url_for('auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

# OAuth callback route
@app.get('/auth/callback')
async def auth_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')

        if not user_info:
            user_info = await oauth.google.parse_id_token(request, token)
        
        email = user_info['email']
        username = user_info.get('name', email.split('@')[0])

        user = users_table.get_item(Key={'email': email}).get('Item')
        if not user:
            _id = str(uuid.uuid4())
            users_table.put_item(Item={
                'username': username,
                'email': email,
                'password': None,
                'oauth_provider': 'google',
                '_id': _id
            })

        payload = {
            '_id': str(user['_id']) if user else '',
            'email': email,
            'username': username,
            'date': datetime.utcnow().isoformat()
        }
        jwt_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        frontend_redirect = f"{os.getenv('FRONTEND_URL_DEVELOPMENT')}/auth/complete"
        return RedirectResponse(f"{frontend_redirect}?token={jwt_token}")
        
    except Exception as e:
        print(f"OAuth callback error: {e}")
        traceback.print_exc() 
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OAuth callback failed")

def authentication_required(request: Request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or len(auth_header.split()) != 2:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Bad authorization header')
    bearer_token = auth_header.split()[1]
    try:
        data = jwt.decode(bearer_token, SECRET_KEY, algorithms=["HS256"])
        user = users_table.get_item(Key={'email': data.get('email')}).get('Item')
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')
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
    user = users_table.get_item(Key={'email': email}).get('Item')
    if user:
        return {
            '_id': str(user.get('_id')),
            'username': user.get('username', ''),
            'email': user.get('email', ''),
            'password': user.get('password', ''),
            'phone': user.get('phone', ''),
            'profilePicture': user.get('profilePicture', ''),
            'resume': user.get('resume', ''),
            'experience': user.get('experience', []),
            'skills': user.get('skills', []),
            'courses': user.get('courses', []),
            'certifications': user.get('certifications', [])
        }
    return None

@app.get('/check')
def home():
    return 'Hello, FastAPI!'

@app.get('/check_auth')
def check_auth2(dep=Depends(authentication_required)):
    return {'message': 'Hello, FastAPI!', 'user': dep}

def send_verification_email(email: str, code: str, username: str):
    template_file = "verification_mail_template.html.jinja"
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template(template_file)
    html_content = template.render(username=username, code=code, year=datetime.now().year)

    res = requests.post(f"{os.getenv('mail_service_url')}/api/send_email", json={
        'to_email': email,
        'subject': 'Email Verification for BulletHire',
        'body': html_content
    })
    if res.status_code != 200:
        print(f"Failed to send email: {res.text}", flush=True)

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
@app.post('/api/signup')
def signup(signup_request: SignupRequest, background_tasks: BackgroundTasks):
    try:
        payload = signup_request.dict()
        username = payload.get('username', '')
        email = payload.get('email', '')
        password = payload.get('password', '')
        if users_table.get_item(Key={'email': email}).get('Item'):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Email already exists')
        hashed_password = generate_password_hash(password)

        expiration_time = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        verification_code = str(generate_verification_code())

        background_tasks.add_task(send_verification_email, email, verification_code, username)

        # r.setex(f"{email}_verification_code", 600, verification_code)
        r.set(f"{email}_verification_code", verification_code, ex=600)

        users_table.put_item(Item={
            '_id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'password': hashed_password,
            'is_verified': False,
            'expires_at': expiration_time
        })
        return {'message': 'User created successfully', 'status': True}, 201
    except Exception as e:
        print(f"Error during signup: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')

class VerificationRequest(BaseModel):
    email: str
    code: str
@app.post('/api/verify-email')
def verify_email(verification_request: VerificationRequest):
    try:
        email = verification_request.email
        code = verification_request.code
        user = users_table.get_item(Key={'email': email}).get('Item')
        if user and r.get(f"{email}_verification_code") == code:
            users_table.update_item(
                Key={'email': email},
                UpdateExpression='SET is_verified = :is_verified REMOVE expires_at',
                ExpressionAttributeValues={':is_verified': True}
            )
            r.delete(f"{email}_verification_code")
            return {'message': 'Email verified successfully', 'status': True}
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid verification code')
    except Exception as e:
        print(f"Error during verification: {e}", flush=True)
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
        user = users_table.get_item(Key={'email': email}).get('Item')
        if user and check_password_hash(user['password'], password):
            data = {
                '_id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            token = jwt.encode(data, SECRET_KEY, algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode('utf-8')
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
            users_table.update_item(
                Key={'email': user['email']},
                UpdateExpression='REMOVE token'
            )
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
# class jd_data(BaseModel):
#     role : str
#     location : str
#     skills : str
#     experience : int
#     education : str
#     link: str
# @app.post("/create_jd")
# def create_job_description(data: jd_data, dep=Depends(authentication_required)):
#     jd_id = uuid.uuid4().hex
#     data.link = f"/job/{jd_id}/apply"
#     # job_description = jd_create(data)
#     job_description = ''
#     user_data = get_user(dep)
#     if not user_data:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")
#     payload = {
#         "_id": jd_id,
#         "job_description": job_description,
#         "role": data.role,
#         "location": data.location,
#         "skills": data.skills,
#         "experience": data.experience,
#         "education": data.education,
#         "link": data.link,
#         "user_id": user_data['_id'],
#         "created_at": datetime.datetime.utcnow(),        
#         "posted": False
#     }
#     data_db['job_descriptions'].insert_one(payload)
#     return JSONResponse(status_code=200, content={"message": 'Job description created successfully', "job_id": jd_id})

@app.get("/get_jd/{jd_id}")
def get_job_description(jd_id: str, dep=Depends(authentication_required)):
    try:
        response = job_descriptions_table.get_item(Key={'jd_id': jd_id})
        job = response.get('Item')
        print('job', job, flush=True)
        if job:
            if 'posted' in job and job['posted']:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Job description already posted")
            job['experience'] = int(job['experience']) if 'experience' in job else None
            job['created_at'] =  str(job['created_at']) if 'created_at' in job else None
            return JSONResponse(status_code=200, content={"job": job})
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job description not found")
    except Exception as e:
        print(f"Error fetching job description: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class FinalizeJDRequest(BaseModel):
    job_description: str
@app.post('/finalize_jd/{jd_id}')
def finalize_job_description(jd_id: str, request: FinalizeJDRequest, dep=Depends(authentication_required)):
    try:
        job = job_descriptions_table.get_item(Key={'jd_id': jd_id}).get('Item')
        if job:
            job['job_description'] = request.job_description
            job_descriptions_table.update_item(
                Key={'jd_id': jd_id},
                UpdateExpression="SET job_description = :job_description",
                ExpressionAttributeValues={":job_description": request.job_description}
            )
            user_data = get_user(dep)
            post_id = str(uuid.uuid4())
            post = {
                "_id": post_id,
                "user": {
                        "_id": user_data['_id'],
                        "username": user_data.get('username', ''),
                        "email": user_data.get('email', ''),
                        },
                "post_type": "job",
                "jd_id": jd_id,
                "created_at": datetime.utcnow().isoformat(),
                "content": request.job_description,
                "interactions":{
                    "likes": [],
                    "comments": [],
                    "shares": []
                },
            }
            posts_table.put_item(Item=post)
            job_descriptions_table.update_item(
                Key={'jd_id': jd_id},
                UpdateExpression="SET posted = :posted",
                ExpressionAttributeValues={":posted": True}
            )
            return JSONResponse(status_code=200, content={"message": "Job is posted successfully"})
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job description not found")
    except Exception as e:
        print(f"Error finalizing job description: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

@app.get('/get_posts')
def get_posts(dep=Depends(authentication_required)):
    try:
        all_posts = []
        response = posts_table.scan()
        posts_cursor = response.get('Items', [])
        for post in posts_cursor:
            for comment in post['interactions']['comments']:
                comment['user_id'] = str(comment['user_id'])
                comment['created_at'] = str(comment['created_at'])
                comment['_id'] = str(comment['_id'])
                comment['likes'] = [str(like) for like in comment['likes']]
                for reply in comment['replies']:
                    reply['user_id'] = str(reply['user_id'])
                    reply['created_at'] = str(reply['created_at'])
                    reply['_id'] = str(reply['_id'])
            all_posts.append(post)
        if all_posts:
            return JSONResponse(status_code=200, content={"posts": all_posts, "message": "Posts fetched successfully"})
        else:
            return JSONResponse(status_code=204, content={"message": "No posts found", "posts": []})
    except Exception as e:
        print(f"Error fetching posts: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

# @app.post("/post_on_linkedin")
# def post_on_linkedin(job_description:str, dep=Depends(authentication_required)):
#     try:
#         response = post_jd_on_linkedin(job_description)
#         return JSONResponse(status_code=200, content={"response": response})
#     except Exception as e:
#         print(f"Error posting on LinkedIn: {e}", flush=True)
#         traceback.print_exc()
#         return JSONResponse(status_code=500, content=str(e))

# @app.post("/select_candidates")
# def select_candidates(job_description:str, dep=Depends(authentication_required)):
#     try:
#         response = select_send_email(job_description)
#         return JSONResponse(status_code=200, content={'response': response})
#     except Exception as e:
#         print(f"Error selecting candidates: {e}", flush=True)
#         traceback.print_exc()
#         return JSONResponse(status_code=500, content=str(e))

# class KeywordRequest(BaseModel):
#     keywords: str
# @app.post("/create_questions")
# def create_questions(request: KeywordRequest, dep=Depends(authentication_required)):
#     try:
#         response = generate_questions(request.keywords)
#         return JSONResponse(status_code=200, content={"response": response})
#     except Exception as e:
#         print(f"Error creating questions: {e}", flush=True)
#         traceback.print_exc()
#         return JSONResponse(status_code=500, content=str(e))

class LikePostRequest(BaseModel):
    post_id: str
@app.post('/like_post')
def like_post(request: LikePostRequest, dep=Depends(authentication_required)):
    try:
        post_id = request.post_id
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        response = posts_table.get_item(Key={'_id': post_id})
        post = response.get('Item')
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
        
        if user_data['_id'] in post['interactions']['likes']:
            posts_table.update_item(
                Key={'_id': post_id},
                UpdateExpression="DELETE interactions.likes :user_id",
                ExpressionAttributeValues={":user_id": user_data['_id']}
            )
            return JSONResponse(status_code=200, content={"message": "Post unliked successfully"})

        posts_table.update_item(
            Key={'_id': post_id},
            UpdateExpression="ADD interactions.likes :user_id",
            ExpressionAttributeValues={":user_id": user_data['_id']}
        )
        return JSONResponse(status_code=200, content={"message": "Post liked successfully"})
    except Exception as e:
        print(f"Error liking post: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class CommentPostRequest(BaseModel):
    post_id: str
    comment: str
@app.post('/comment_post')
def comment_post(request: CommentPostRequest, dep=Depends(authentication_required)):
    try:
        post_id = request.post_id
        comment = request.comment
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        response = posts_table.get_item(Key={'_id': post_id})
        post = response.get('Item')
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment_id = uuid.uuid4().hex
        posts_table.update_item(
            Key={'_id': post_id},
            UpdateExpression="ADD interactions.comments :comment",
            ExpressionAttributeValues={":comment": {"_id": comment_id, "user_id": user_data['_id'], "username": user_data['username'], "comment": comment, "created_at": datetime.utcnow().isoformat(), 'likes': [], 'replies': []}}
        )
        return JSONResponse(status_code=200, content={"message": "Comment added successfully"})
    except Exception as e:
        print(f"Error commenting on post: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))


class LikeCommentRequest(BaseModel):
    post_id: str
    comment_id: str
@app.post('/like_comment')
def like_comment(request: LikeCommentRequest, dep=Depends(authentication_required)):
    try:
        post_id = request.post_id
        comment_id = request.comment_id
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        response = posts_table.get_item(Key={'_id': post_id})
        post = response.get('Item')
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment = next((c for c in post['interactions']['comments'] if c['_id'] == comment_id), None)
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")

        if user_data['_id'] in comment['likes']:
            posts_table.update_item(
                Key={'_id': post_id},
                UpdateExpression="DELETE interactions.comments.$[c].likes :user_id",
                ExpressionAttributeValues={":user_id": user_data['_id']},
                ArrayFilters=[{"c._id": comment_id}]
            )
            return JSONResponse(status_code=200, content={"message": "Comment unliked successfully"})

        posts_table.update_item(
            Key={'_id': post_id},
            UpdateExpression="ADD interactions.comments.$[c].likes :user_id",
            ExpressionAttributeValues={":user_id": user_data['_id']},
            ArrayFilters=[{"c._id": comment_id}]
        )
        return JSONResponse(status_code=200, content={"message": "Comment liked successfully"})
    except Exception as e:
        print(f"Error liking comment: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class ReplyCommentRequest(BaseModel):
    post_id: str
    comment_id: str
    reply: str
@app.post('/reply_comment')
def reply_comment(request: ReplyCommentRequest, dep=Depends(authentication_required)):
    try:
        post_id = request.post_id
        comment_id = request.comment_id
        reply = request.reply
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        response = posts_table.get_item(Key={'_id': post_id})
        post = response.get('Item')
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment = next((c for c in post['interactions']['comments'] if c['_id'] == comment_id), None)
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")

        reply_id = uuid.uuid4().hex
        posts_table.update_item(
            Key={'_id': post_id},
            UpdateExpression="ADD interactions.comments.$[c].replies :reply",
            ExpressionAttributeValues={":reply": {"_id": reply_id, "user_id": user_data['_id'], "username": user_data['username'], "reply": reply, "created_at": datetime.utcnow().isoformat()}},
            ArrayFilters=[{"c._id": comment_id}]
        )
        return JSONResponse(status_code=200, content={"message": "Reply added successfully"})
    except Exception as e:
        print(f"Error replying to comment: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))


class deleteCommentRequest(BaseModel):
    post_id: str
    comment_id: str
@app.delete('/delete_comment')
def delete_comment(request: deleteCommentRequest, dep=Depends(authentication_required)):
    try:
        post_id = request.post_id
        comment_id = request.comment_id
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        response = posts_table.get_item(Key={'_id': post_id})
        post = response.get('Item')
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment = next((c for c in post['interactions']['comments'] if c['_id'] == comment_id), None)
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")

        if comment['user_id'] != user_data['_id']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can only delete your own comments")

        posts_table.update_item(
            Key={'_id': post_id},
            UpdateExpression="DELETE interactions.comments.$[c]",
            ArrayFilters=[{"c._id": comment_id}]
        )
        return JSONResponse(status_code=200, content={"message": "Comment deleted successfully"})
    except Exception as e:
        print(f"Error deleting comment: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

@app.post('/upload_profile')
async def upload_profile(file: UploadFile = File(...), dep=Depends(authentication_required)):
    try:
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file uploaded"
            )

        allowed_content_types = ['image/jpeg', 'image/png']
        allowed_extensions = ['jpg', 'jpeg', 'png']
        file_extension = file.filename.split('.')[-1].lower()

        if file.content_type not in allowed_content_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. Only JPEG and PNG are allowed."
            )

        if file_extension not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file extension. Only .jpg, .jpeg, and .png are allowed."
            )

        filename = f"{uuid.uuid4().hex}.{file_extension}"

        # store in s3 bucket
        s3_key = f"profile_pictures/{user_data['_id']}/{filename}"
        S3.upload_fileobj(file.file, os.getenv('AWS_S3_PROFILE_PICTURE_BUCKET_NAME'), s3_key, ExtraArgs={'ContentType': file.content_type, 'ACL': 'public-read'})
        media_url = f"https://{os.getenv('AWS_S3_PROFILE_PICTURE_BUCKET_NAME')}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{s3_key}"
        users_table.update_item(
            Key={'email': user_data['email']},
            UpdateExpression='SET profilePicture = :profilePicture',
            ExpressionAttributeValues={':profilePicture': media_url}
        )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Profile picture uploaded successfully",
                "success": True,
                "url": media_url
            }
        )
    except Exception as e:
        print(f"Error uploading profile picture: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.post('/upload_resume')
async def upload_resume(file: UploadFile = File(...), dep=Depends(authentication_required)):
    try:
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file uploaded"
            )

        allowed_content_types = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        allowed_extensions = ['pdf', 'doc', 'docx']
        file_extension = file.filename.split('.')[-1].lower()

        if file.content_type not in allowed_content_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. Only PDF and Word documents are allowed."
            )

        if file_extension not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file extension. Only .pdf, .doc, and .docx are allowed."
            )

        filename = file.filename 
        if not filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File name cannot be empty"
            )
        # relative_path = f"{user_data['_id']}/resumes/{filename}" 
        # absolute_path = os.path.join(uploads_directory, relative_path)
        # os.makedirs(os.path.dirname(absolute_path), exist_ok=True)

        # with open(absolute_path, "wb") as f:
        #     f.write(await file.read())

        # media_url = f"/media/{relative_path}"
        # users_db['users'].update_one(
        #     {'_id': ObjectId(user_data['_id'])},
        #     {'$set': {'resume': media_url}}
        # )

        # store in s3 bucket
        s3_key = f"resumes/{user_data['_id']}/{filename}"
        S3.upload_fileobj(file.file, os.getenv('AWS_S3_RESUME_BUCKET_NAME'), s3_key, ExtraArgs={'ContentType': file.content_type, 'ACL': 'public-read'})
        media_url = f"https://{os.getenv('AWS_S3_RESUME_BUCKET_NAME')}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{s3_key}"
        users_table.update_item(
            Key={'id': user_data['_id']},
            UpdateExpression='SET resume = :resume',
            ExpressionAttributeValues={':resume': media_url}
        )
        users_table.update_item(
            Key={'id': user_data['_id']},
            UpdateExpression='SET resume = :resume',
            ExpressionAttributeValues={':resume': media_url}
        )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Resume uploaded successfully",
                "success": True,
                "url": media_url
            }
        )
    except Exception as e:
        print(f"Error uploading resume: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post('/add_experience')
async def add_experience(request: Request, dep=Depends(authentication_required)):
    try:
        data = await request.json()
        experience = data.get('experience')
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")
        
        users_table.update_item(
            Key={'id': user_data['_id']},
            UpdateExpression='SET experience = :experience',
            ExpressionAttributeValues={':experience': experience}
        )

        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error adding experience: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post('/add_skill')
async def add_skill(request: Request, dep=Depends(authentication_required)):
    try:
        data = await request.json()
        skill = data.get('skill')
        if not skill:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Skill is empty")
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status=status.HTTP_401_UNAUTHORIZED, detail="user not authenticated")
        
        users_table.update_item(
            Key={'_id': user_data['_id']},
            UpdateExpression="ADD skills :skill",
            ExpressionAttributeValues={":skill": {skill}}
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error adding a skill: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False})


@app.post('/remove_skill')
async def remove_skill(request: Request, dep=Depends(authentication_required)):
    try:
        data = await request.json()
        skill = data.get('skill')
        if not skill:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Skill is empty")
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status=status.HTTP_401_UNAUTHORIZED, detail="user not authenticated")
        
        users_table.update_item(
            Key={'_id': user_data['_id']},
            UpdateExpression="DELETE skills :skill",
            ExpressionAttributeValues={":skill": {skill}}
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error adding a skill: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False})

@app.post('/add_course')
async def add_course(request: Request, dep=Depends(authentication_required)):
    try:
        data = await request.json()
        courses = data.get('courses')
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")
        
        users_table.update_item(
            Key={'_id': user_data['_id']},
            UpdateExpression='SET courses = :courses',
            ExpressionAttributeValues={':courses': courses}
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error adding courses: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.post('/add_certification')
async def add_certification(request: Request, dep=Depends(authentication_required)):
    try:
        data = await request.json()
        certifications = data.get('certifications')
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        users_table.update_item(
            Key={'_id': user_data['_id']},
            UpdateExpression='SET certifications = :certifications',
            ExpressionAttributeValues={':certifications': certifications}
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error adding certifications: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

        users_table.update_item(
            Key={'_id': user_data['_id']},
            UpdateExpression='SET certifications = :certifications',
            ExpressionAttributeValues={':certifications': certifications}
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error adding certifications: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post('/edit_user_data')
async def edit_user_data(request: Request, dep=Depends(authentication_required)):
    try:
        data = await request.json()
        userData = data.get('userData', {})
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")
        
        update_expression = "SET " + ", ".join([f"{key} = :{key}" for key in userData.keys()])
        expression_attribute_values = {f":{key}": value for key, value in userData.items()}

        users_table.update_item(
            Key={'_id': user_data['_id']},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values
        )

        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error updating user data: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})



class Applicant(BaseModel):
    id: str
    name: str
    email: str
    resumeScore: Optional[int] = None
    oaScore: Optional[int] = None
    resumeFile: Optional[str] = None
    resumeFileName: Optional[str] = None
    college: str
    degree: str
    experience: int


def generate_dummy_candidates(job_id: str):
    """Generate realistic dummy candidate data"""
    
    # Sample names
    first_names = [
        "Arjun", "Priya", "Rahul", "Sneha", "Vikram", "Ananya", "Rohan", "Kavya",
        "Aaditya", "Ishita", "Siddharth", "Meera", "Karthik", "Riya", "Abhishek",
        "Pooja", "Nikhil", "Shreya", "Varun", "Divya", "Akash", "Nandini",
        "Raj", "Sakshi", "Arun", "Kritika", "Shubham", "Tanvi", "Harsh", "Ritika"
    ]
    
    last_names = [
        "Sharma", "Patel", "Singh", "Kumar", "Gupta", "Agarwal", "Joshi", "Shah",
        "Reddy", "Iyer", "Nair", "Malhotra", "Chopra", "Bansal", "Mehta",
        "Verma", "Sinha", "Tiwari", "Mishra", "Pandey", "Saxena", "Arora"
    ]
    
    # Sample colleges
    colleges = [
        "IIT Delhi", "IIT Bombay", "IIT Madras", "IIT Kanpur", "IIT Kharagpur",
        "NIT Trichy", "NIT Warangal", "BITS Pilani", "VIT Vellore", "SRM Chennai",
        "Delhi University", "Mumbai University", "Anna University", "IIIT Hyderabad",
        "MIT Manipal", "PES University", "RV College of Engineering", "BMS College",
        "Jadavpur University", "Pune University", "NITK Surathkal", "IIIT Bangalore"
    ]
    
    # Sample degrees
    degrees = [
        "B.Tech Computer Science", "B.Tech Information Technology", "B.Tech Electronics",
        "B.E Computer Science", "B.E Information Science", "MCA", "M.Tech CSE",
        "B.Tech Software Engineering", "B.Tech Data Science", "BCA", "M.Sc Computer Science",
        "B.Tech Artificial Intelligence", "B.Tech Cybersecurity"
    ]
    
    # Generate 15-25 random candidates
    num_candidates = random.randint(15, 25)
    candidates = []
    
    for i in range(num_candidates):
        first_name = random.choice(first_names)
        last_name = random.choice(last_names)
        name = f"{first_name} {last_name}"
        email = f"{first_name.lower()}.{last_name.lower()}@{random.choice(['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'])}"
        
        # Random resume score (70% chance of having a score)
        resume_score = random.randint(45, 95) if random.random() < 0.7 else None
        
        # Random OA score (60% chance of having attended)
        oa_score = random.randint(30, 100) if random.random() < 0.6 else None
        
        # Resume file (85% chance of having uploaded)
        has_resume = random.random() < 0.85
        resume_file = f"https://example.com/resumes/{uuid.uuid4()}.pdf" if has_resume else None
        resume_file_name = f"{first_name}_{last_name}_Resume.pdf" if has_resume else None
        
        candidate = Applicant(
            id=str(uuid.uuid4()),
            name=name,
            email=email,
            resumeScore=resume_score,
            oaScore=oa_score,
            resumeFile=resume_file,
            resumeFileName=resume_file_name,
            college=random.choice(colleges),
            degree=random.choice(degrees),
            experience=random.randint(0, 8)
        )
        
        candidates.append(candidate)
    
    return candidates


@app.get("/api/fetchapplicants/{job_id}")
async def fetch_applicants(job_id: str, dep=Depends(authentication_required)):
    try:
        candidates = generate_dummy_candidates(job_id)
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "candidates": [candidate.model_dump() for candidate in candidates]
            }
        )

    except Exception as e:
        print(f"Error updating fetch applicants: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

@app.get('/get_jobs')
def get_jobs(dep=Depends(authentication_required)):
    try:
        all_jobs = []
        posts = posts_table.scan().get("Items", [])

        for post in posts:
            jd_id = post.get('jd_id')
            job = job_descriptions_table.get_item(Key={'jd_id': jd_id}).get('Item')    
            job['user'] = post.get('user', {})
            job['experience'] = int(job['experience']) if 'experience' in job else None
            job['created_at'] =  str(post['created_at']) if 'created_at' in post else None
            all_jobs.append(job)
        if all_jobs:
            return JSONResponse(status_code=200, content={"jobs": all_jobs})
        else:
            return JSONResponse(status_code=404, content={"message": "No jobs found"})
    except Exception as e:
        print(f"Error fetching jobs: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class OTPRequest(BaseModel):
    phone: str

@app.post('/send_otp')
async def send_otp(request: OTPRequest, dep=Depends(authentication_required)):
    try:
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        phone = int(request.phone)
        if not (1000000000 <= phone <= 9999999999):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number")

        otp = str(random.randint(100000, 999999))
        print(f"Sending OTP {otp} to {phone}", flush=True)

        r.set(f"{phone}_verification_code", otp, ex=600)

        return JSONResponse(status_code=200, content={"message": "OTP sent successfully"})
    except Exception as e:
        print(f"Error sending OTP: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

class applyRequest(BaseModel):
    jobId: str
@app.post('/api/apply')
def apply(request: applyRequest, dep=Depends(authentication_required)):
    try:
        user_id = dep.get('_id')
        email = dep.get('email')
        job_id = request.jobId
        print(job_id, flush=True)
        response = job_descriptions_table.get_item(Key={'job_id': job_id})
        job = response.get('Item')
        if not job:
            return JSONResponse(status_code=404, content={"message": "Job not found"})
        if not 'applicants' in job:
            job['applicants'] = []
        if email in job['applicants']:
            return JSONResponse(status_code=400, content={"message": "You have already applied for this job"})
        job_descriptions_table.update_item(
            Key={'job_id': job_id},
            UpdateExpression="ADD applicants :email",
            ExpressionAttributeValues={":email": email}
        )
        return JSONResponse(status_code=200, content={"message": "Applied successfully"})
    except Exception as e:
        print(f"Error applying for job: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})