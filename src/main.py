from fastapi.responses import JSONResponse
from fastapi import FastAPI, File, Request, HTTPException, status, Depends, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uuid
import pymongo
import yaml
from utils import *
import traceback
import jwt
import datetime
from functools import wraps
from bson import ObjectId
import os

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

payloads_directory = config['payloads_directory']
uploads_directory = config['uploads_directory']

app.mount("/media", StaticFiles(directory=uploads_directory), name="media")

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
                '_id': user['_id'],
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
        "created_at": datetime.datetime.utcnow(),        
        "posted": False
    }
    data_db['job_descriptions'].insert_one(payload)
    return JSONResponse(status_code=200, content={"message": 'Job description created successfully', "job_id": jd_id})

@app.get("/get_jd/{jd_id}")
def get_job_description(jd_id: str, dep=Depends(authentication_required)):
    try:
        job = data_db['job_descriptions'].find_one({"_id": jd_id})
        if job:
            if job['posted']:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Job description already posted")
            job['created_at'] =  str(job['created_at']) if 'created_at' in job else None
            return JSONResponse(status_code=200, content={"job": job})
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job description not found")
    except Exception as e:
        print(f"Error fetching job description: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class FinalizeJDRequest(BaseModel):
    jd: str
@app.post('/finalize_jd/{jd_id}')
def finalize_job_description(jd_id: str, request: FinalizeJDRequest, dep=Depends(authentication_required)):
    try:
        job = data_db['job_descriptions'].find_one({"_id": jd_id})
        if job:
            job['jd'] = request.jd
            data_db['job_descriptions'].update_one({"_id": jd_id}, {"$set": {"jd": request.jd}})
            user_data = get_user(dep)
            post = {
                "user": {
                        "_id": user_data['_id'],
                        "username": user_data.get('username', ''),
                        "email": user_data.get('email', ''),
                        },
                "post_type": "job",
                "jd_id": jd_id,
                "created_at": datetime.datetime.utcnow(),
                "content": request.jd,
                "interactions":{
                    "likes": [],
                    "comments": [],
                    "shares": []
                },

            }
            data_db['posts'].insert_one(post)
            data_db['job_descriptions'].update_one({"_id": jd_id}, {"$set": {"posted": True}})
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
        posts_cursor = data_db['posts'].find({}).sort("created_at", -1)
        for post in posts_cursor:
            post['_id'] = str(post['_id'])
            post['created_at'] = str(post['created_at'])
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
            return JSONResponse(status_code=200, content={"posts": all_posts})
        else:
            return JSONResponse(status_code=404, content={"message": "No posts found"})
    except Exception as e:
        print(f"Error fetching posts: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

@app.post("/post_on_linkedin")
def post_on_linkedin(jd:str, dep=Depends(authentication_required)):
    try:
        response = post_jd_on_linkedin(jd)
        return JSONResponse(status_code=200, content={"response": response})
    except Exception as e:
        print(f"Error posting on LinkedIn: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

@app.post("/select_candidates")
def select_candidates(jd:str, dep=Depends(authentication_required)):
    try:
        response = select_send_email(jd)
        return JSONResponse(status_code=200, content={'response': response})
    except Exception as e:
        print(f"Error selecting candidates: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class KeywordRequest(BaseModel):
    keywords: str
@app.post("/create_questions")
def create_questions(request: KeywordRequest, dep=Depends(authentication_required)):
    try:
        response = generate_questions(request.keywords)
        return JSONResponse(status_code=200, content={"response": response})
    except Exception as e:
        print(f"Error creating questions: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content=str(e))

class LikePostRequest(BaseModel):
    post_id: str
@app.post('/like_post')
def like_post(request: LikePostRequest, dep=Depends(authentication_required)):
    try:
        post_id = request.post_id
        user_data = get_user(dep)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")

        post = data_db['posts'].find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
        
        if user_data['_id'] in post['interactions']['likes']:
            data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$pull": {"interactions.likes": user_data['_id']}})
            return JSONResponse(status_code=200, content={"message": "Post unliked successfully"})

        data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$addToSet": {"interactions.likes": user_data['_id']}})
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

        post = data_db['posts'].find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment_id = uuid.uuid4().hex
        data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$push": {"interactions.comments": {"_id": comment_id, "user_id": user_data['_id'], "username": user_data['username'],"comment": comment, "created_at": datetime.datetime.utcnow(), 'likes': [], 'replies': []}}})
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

        post = data_db['posts'].find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment = next((c for c in post['interactions']['comments'] if c['_id'] == comment_id), None)
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")

        if user_data['_id'] in comment['likes']:
            data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$pull": {"interactions.comments.$[c].likes": user_data['_id']}}, array_filters=[{"c._id": comment_id}])
            return JSONResponse(status_code=200, content={"message": "Comment unliked successfully"})

        data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$addToSet": {"interactions.comments.$[c].likes": user_data['_id']}}, array_filters=[{"c._id": comment_id}])
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

        post = data_db['posts'].find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment = next((c for c in post['interactions']['comments'] if c['_id'] == comment_id), None)
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")

        reply_id = uuid.uuid4().hex
        data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$push": {"interactions.comments.$[c].replies": {"_id": reply_id, "user_id": user_data['_id'], "username": user_data['username'], "reply": reply, "created_at": datetime.datetime.utcnow()}}}, array_filters=[{"c._id": comment_id}])
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

        post = data_db['posts'].find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

        comment = next((c for c in post['interactions']['comments'] if c['_id'] == comment_id), None)
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")

        if comment['user_id'] != user_data['_id']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can only delete your own comments")

        data_db['posts'].update_one({"_id": ObjectId(post_id)}, {"$pull": {"interactions.comments": {"_id": comment_id}}})
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
        relative_path = f"{user_data['_id']}/profile_picture/{filename}" 
        absolute_path = os.path.join(uploads_directory, relative_path)
        os.makedirs(os.path.dirname(absolute_path), exist_ok=True)

        with open(absolute_path, "wb") as f:
            f.write(await file.read())

        media_url = f"/media/{relative_path}"
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$set': {'profilePicture': media_url}}
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
        relative_path = f"{user_data['_id']}/resumes/{filename}" 
        absolute_path = os.path.join(uploads_directory, relative_path)
        os.makedirs(os.path.dirname(absolute_path), exist_ok=True)

        with open(absolute_path, "wb") as f:
            f.write(await file.read())

        media_url = f"/media/{relative_path}"
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$set': {'resume': media_url}}
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
        
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$set': {'experience': experience}}
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
        
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$addToSet': {'skills': skill}}
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
        
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$pull': {'skills': skill}}
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
        
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$set': {'courses': courses}}
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
        
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$set': {'certifications': certifications}}
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
        
        users_db['users'].update_one(
            {'_id': ObjectId(user_data['_id'])},
            {'$set': userData}
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        print(f"Error updating user data: {e}", flush=True)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.get("/api/fetchapplicants/{job_id}")
async def fetch_applicants(job_id: str, dep=Depends(authentication_required)) -> List[Applicant]:
    try:
        candidates = generate_dummy_candidates(job_id)
        return JSONResponse(status_code=200, content={"success": True, 'candidates': candidates})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
