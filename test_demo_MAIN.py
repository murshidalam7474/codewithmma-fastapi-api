# from fastapi import FastAPI, Depends, HTTPException, Query, status, BackgroundTasks, Request
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from sqlalchemy.orm import Session
# from typing import List, Optional, Dict, Any
# from pydantic import BaseModel, EmailStr, validator, HttpUrl
# from database import engine, Topic, Problem, User, VerificationToken
# from sqlalchemy.orm import sessionmaker
# from fastapi.middleware.cors import CORSMiddleware
# from datetime import datetime, timedelta
# from passlib.context import CryptContext
# import secrets
# import string
# import jose
# from jose import JWTError, jwt
# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# import httpx
# from fastapi.responses import RedirectResponse
# from starlette.config import Config

# # Security config
# SECRET_KEY = "3d2f1e7b9a8c4d6f0b1e2c3a5f7d9b8e6c4a2f1e7b9d0c3a5f7b8e6d4c2a1f0"  # Change this to a secure random string in production
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 72

# # Google OAuth Config
# GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID"
# GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
# GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"
# GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
# GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
# GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# # Password hashing context
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # OAuth2 scheme
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# # Pydantic models for request/response
# class ProblemBase(BaseModel):
#     title: str
#     difficulty: str
#     link: str
#     description: Optional[str] = None
#     question: Optional[str] = None
#     solution: Optional[str] = None

# class ProblemCreate(ProblemBase):
#     pass

# class ProblemResponse(ProblemBase):
#     id: int
#     topic_id: int
    
#     class Config:
#         orm_mode = True

# class TopicBase(BaseModel):
#     title: str
#     slug: str
#     description: str
#     icon_name: str
#     color: str

# class TopicCreate(TopicBase):
#     pass

# class TopicResponse(TopicBase):
#     id: int
#     problem_counts: dict
    
#     class Config:
#         orm_mode = True

# # User models
# class UserBase(BaseModel):
#     email: EmailStr
#     username: str

# class UserCreate(UserBase):
#     password: str
#     confirm_password: str
    
#     @validator('confirm_password')
#     def passwords_match(cls, v, values):
#         if 'password' in values and v != values['password']:
#             raise ValueError('passwords do not match')
#         return v

# class UserLogin(BaseModel):
#     username_or_email: str
#     password: str

# class UserUpdate(BaseModel):
#     email: Optional[EmailStr] = None
#     username: Optional[str] = None
#     current_password: Optional[str] = None
#     new_password: Optional[str] = None
#     confirm_new_password: Optional[str] = None
    
#     @validator('confirm_new_password')
#     def passwords_match(cls, v, values):
#         if 'new_password' in values and v != values['new_password']:
#             raise ValueError('new passwords do not match')
#         return v

# class UserOAuthData(BaseModel):
#     email: EmailStr
#     username: Optional[str] = None
#     picture: Optional[HttpUrl] = None
#     provider: str
#     provider_user_id: str

# class UserResponse(UserBase):
#     id: int
#     is_verified: bool
#     created_at: datetime
    
#     class Config:
#         orm_mode = True

# class Token(BaseModel):
#     access_token: str
#     token_type: str

# class TokenData(BaseModel):
#     username: Optional[str] = None

# # Create FastAPI app
# app = FastAPI(title="LeetCode Problems API")

# # Add CORS middleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # Allows all origins
#     allow_credentials=True,
#     allow_methods=["*"],  # Allows all methods
#     allow_headers=["*"],  # Allows all headers
# )

# # Dependency to get DB session
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# # Authentication helpers
# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def get_password_hash(password):
#     return pwd_context.hash(password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# def get_user(db: Session, username_or_email: str):
#     user = db.query(User).filter(User.username == username_or_email).first()
#     if not user:
#         user = db.query(User).filter(User.email == username_or_email).first()
#     return user

# def get_user_by_email(db: Session, email: str):
#     return db.query(User).filter(User.email == email).first()

# def authenticate_user(db: Session, username_or_email: str, password: str):
#     user = get_user(db, username_or_email)
#     if not user:
#         return False
#     if not verify_password(password, user.hashed_password):
#         return False
#     return user

# def create_or_get_oauth_user(db: Session, user_data: UserOAuthData):
#     # Check if user exists with this email
#     user = get_user_by_email(db, user_data.email)
    
#     if user:
#         # Update OAuth info if needed
#         user.oauth_provider = user_data.provider
#         user.oauth_provider_user_id = user_data.provider_user_id
#         db.commit()
#         return user
    
#     # Create new user
#     username = user_data.username
#     if not username:
#         # Generate username from email if not provided
#         username = user_data.email.split('@')[0]
        
#         # Check if username exists, append a number if it does
#         base_username = username
#         counter = 1
#         while db.query(User).filter(User.username == username).first():
#             username = f"{base_username}{counter}"
#             counter += 1
    
#     # Create a random password for OAuth users
#     random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    
#     # Create the user
#     new_user = User(
#         username=username,
#         email=user_data.email,
#         hashed_password=get_password_hash(random_password),
#         is_verified=True,  # OAuth users are considered verified
#         oauth_provider=user_data.provider,
#         oauth_provider_user_id=user_data.provider_user_id
#     )
    
#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)
#     return new_user

# # Token dependency
# async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception
#     user = get_user(db, username_or_email=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user

# async def get_current_verified_user(current_user: User = Depends(get_current_user)):
#     if not current_user.is_verified:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Email not verified"
#         )
#     return current_user

# # Email verification functions
# def generate_verification_token():
#     return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

# def send_verification_email(email: str, username: str, token: str):
#     # In a real-world scenario, you would configure this with your SMTP server details
#     # For now, we'll just print the verification link
#     verification_link = f"http://yourdomain.com/verify-email?token={token}"
#     print(f"Verification link for {email}: {verification_link}")
    
#     # Uncomment and configure this for actual email sending
#     '''
#     msg = MIMEMultipart()
#     msg['From'] = 'your-email@example.com'
#     msg['To'] = email
#     msg['Subject'] = 'Verify your LeetCode Problems account'
    
#     body = f"""
#     Hello {username},
    
#     Please verify your email by clicking the link below:
#     {verification_link}
    
#     This link will expire in 24 hours.
    
#     Thank you,
#     LeetCode Problems Team
#     """
    
#     msg.attach(MIMEText(body, 'plain'))
    
#     with smtplib.SMTP('smtp.youremailprovider.com', 587) as server:
#         server.starttls()
#         server.login('your-email@example.com', 'your-password')
#         server.send_message(msg)
#     '''

# # Authentication routes
# @app.post("/signup", response_model=UserResponse)
# def signup(user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
#     # Check if username already exists
#     if db.query(User).filter(User.username == user.username).first():
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Username already registered"
#         )
    
#     # Check if email already exists
#     if db.query(User).filter(User.email == user.email).first():
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Email already registered"
#         )
    
#     # Create new user
#     hashed_password = get_password_hash(user.password)
#     db_user = User(
#         username=user.username,
#         email=user.email,
#         hashed_password=hashed_password,
#         is_verified=False
#     )
#     db.add(db_user)
#     db.commit()
#     db.refresh(db_user)
    
#     # Create verification token
#     token_string = generate_verification_token()
#     token = VerificationToken(
#         token=token_string,
#         expires_at=datetime.utcnow() + timedelta(hours=24),
#         user_id=db_user.id
#     )
#     db.add(token)
#     db.commit()
    
#     # Send verification email in background
#     background_tasks.add_task(send_verification_email, db_user.email, db_user.username, token_string)
    
#     return db_user

# @app.get("/verify-email")
# def verify_email(token: str, db: Session = Depends(get_db)):
#     token_record = db.query(VerificationToken).filter(VerificationToken.token == token).first()
#     if not token_record:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Invalid verification token"
#         )
    
#     if token_record.expires_at < datetime.utcnow():
#         # Delete expired token
#         db.delete(token_record)
#         db.commit()
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Verification token has expired"
#         )
    
#     # Mark user as verified
#     user = db.query(User).filter(User.id == token_record.user_id).first()
#     user.is_verified = True
    
#     # Delete the token
#     db.delete(token_record)
#     db.commit()
    
#     return {"message": "Email verified successfully. You can now log in."}

# @app.post("/token", response_model=Token)
# def login_for_access_token(form_data: UserLogin, db: Session = Depends(get_db)):
#     user = authenticate_user(db, form_data.username_or_email, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username/email or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
    
#     if not user.is_verified:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Please verify your email before logging in"
#         )
    
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user.username}, expires_delta=access_token_expires
#     )
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.get("/auth/google/login")
# async def google_login():
#     """Generate Google OAuth login URL"""
#     params = {
#         "client_id": GOOGLE_CLIENT_ID,
#         "response_type": "code",
#         "scope": "openid email profile",
#         "redirect_uri": GOOGLE_REDIRECT_URI,
#         "prompt": "select_account",
#     }
    
#     # Construct the auth URL with parameters
#     auth_url = f"{GOOGLE_AUTH_URL}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    
#     # Redirect the user to Google's auth page
#     return RedirectResponse(url=auth_url)

# @app.get("/auth/google/callback")
# async def google_callback(request: Request, db: Session = Depends(get_db)):
#     """Handle the Google OAuth callback"""
#     # Get the authorization code from the request
#     code = request.query_params.get("code")
#     if not code:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Code not found in request"
#         )
    
#     # Exchange the code for a token
#     async with httpx.AsyncClient() as client:
#         token_response = await client.post(
#             GOOGLE_TOKEN_URL,
#             data={
#                 "client_id": GOOGLE_CLIENT_ID,
#                 "client_secret": GOOGLE_CLIENT_SECRET,
#                 "code": code,
#                 "grant_type": "authorization_code",
#                 "redirect_uri": GOOGLE_REDIRECT_URI,
#             },
#         )
    
#     if token_response.status_code != 200:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Failed to exchange code for token"
#         )
    
#     # Parse the token response
#     token_data = token_response.json()
#     access_token = token_data.get("access_token")
    
#     # Use the access token to get user info
#     async with httpx.AsyncClient() as client:
#         user_response = await client.get(
#             GOOGLE_USER_INFO_URL,
#             headers={"Authorization": f"Bearer {access_token}"},
#         )
    
#     if user_response.status_code != 200:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Failed to get user info"
#         )
    
#     # Parse the user info
#     google_user = user_response.json()
    
#     # Create or get the user
#     oauth_data = UserOAuthData(
#         email=google_user["email"],
#         username=google_user.get("name"),
#         picture=google_user.get("picture"),
#         provider="google",
#         provider_user_id=google_user["id"]
#     )
    
#     user = create_or_get_oauth_user(db, oauth_data)
    
#     # Generate JWT token for the user
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user.username}, expires_delta=access_token_expires
#     )
    
#     # Redirect to front-end with token
#     # In a real app, you'd redirect to your frontend with the token
#     # For demo purposes, we'll return the token directly
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.get("/users/me", response_model=UserResponse)
# def read_users_me(current_user: User = Depends(get_current_verified_user)):
#     return current_user

# @app.put("/users/me", response_model=UserResponse)
# def update_user(
#     user_update: UserUpdate,
#     current_user: User = Depends(get_current_verified_user),
#     db: Session = Depends(get_db)
# ):
#     # Check if trying to update password
#     if user_update.new_password:
#         if not user_update.current_password:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Current password is required to update password"
#             )
        
#         if not verify_password(user_update.current_password, current_user.hashed_password):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Current password is incorrect"
#             )
        
#         current_user.hashed_password = get_password_hash(user_update.new_password)
    
#     # Update email if provided
#     if user_update.email and user_update.email != current_user.email:
#         # Check if email already exists
#         if db.query(User).filter(User.email == user_update.email).first():
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Email already registered"
#             )
#         current_user.email = user_update.email
#         current_user.is_verified = False
        
#         # Create new verification token
#         token_string = generate_verification_token()
#         token = VerificationToken(
#             token=token_string,
#             expires_at=datetime.utcnow() + timedelta(hours=24),
#             user_id=current_user.id
#         )
#         db.add(token)
#         db.commit()
        
#         # Send verification email
#         send_verification_email(current_user.email, current_user.username, token_string)
    
#     # Update username if provided
#     if user_update.username and user_update.username != current_user.username:
#         # Check if username already exists
#         if db.query(User).filter(User.username == user_update.username).first():
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Username already registered"
#             )
#         current_user.username = user_update.username
    
#     # Update the record
#     db.commit()
#     db.refresh(current_user)
#     return current_user

# # API Endpoints from your original code
# @app.get("/topics/", response_model=List[TopicResponse])
# def read_topics(
#     search: Optional[str] = None,
#     skip: int = 0, 
#     limit: int = 100,
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_verified_user)
# ):
#     query = db.query(Topic)
    
#     if search:
#         query = query.filter(
#             (Topic.title.ilike(f"%{search}%")) | 
#             (Topic.description.ilike(f"%{search}%")) 
#         )
    
#     topics = query.offset(skip).limit(limit).all()
    
#     # Add problem counts for each topic
#     response_topics = []
#     for topic in topics:
#         easy_count = sum(1 for p in topic.problems if p.difficulty.capitalize() == "Easy")
#         medium_count = sum(1 for p in topic.problems if p.difficulty.capitalize() == "Medium")
#         hard_count = sum(1 for p in topic.problems if p.difficulty.capitalize() == "Hard")
        
#         topic_dict = {
#             "id": topic.id,
#             "title": topic.title,
#             "slug": topic.slug,
#             "description": topic.description,
#             "icon_name": topic.icon_name,
#             "color": topic.color,
#             "problem_counts": {
#                 "easy": easy_count,
#                 "medium": medium_count,
#                 "hard": hard_count
#             }
#         }
#         response_topics.append(topic_dict)
    
#     return response_topics

# @app.get("/topics/{slug}", response_model=TopicResponse)
# def read_topic(slug: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_verified_user)):
#     topic = db.query(Topic).filter(Topic.slug == slug).first()
#     if topic is None:
#         raise HTTPException(status_code=404, detail="Topic not found")
    
#     # Get problem counts
#     easy_count = sum(1 for p in topic.problems if p.difficulty.capitalize() == "Easy")
#     medium_count = sum(1 for p in topic.problems if p.difficulty.capitalize() == "Medium")
#     hard_count = sum(1 for p in topic.problems if p.difficulty.capitalize() == "Hard")
    
#     # Create response
#     response = {
#         "id": topic.id,
#         "title": topic.title,
#         "slug": topic.slug,
#         "description": topic.description,
#         "icon_name": topic.icon_name,
#         "color": topic.color,
#         "problem_counts": {
#             "easy": easy_count,
#             "medium": medium_count,
#             "hard": hard_count
#         }
#     }
    
#     return response

# @app.get("/topics/{slug}/problems", response_model=List[ProblemResponse])
# def read_topic_problems(
#     slug: str, 
#     difficulty: Optional[str] = None,
#     search: Optional[str] = None,
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_verified_user)
# ):
#     topic = db.query(Topic).filter(Topic.slug == slug).first()
#     if topic is None:
#         raise HTTPException(status_code=404, detail="Topic not found")
    
#     query = db.query(Problem).filter(Problem.topic_id == topic.id)
    
#     if difficulty:
#         query = query.filter(Problem.difficulty == difficulty)
    
#     if search:
#         query = query.filter(Problem.title.ilike(f"%{search}%"))
    
#     problems = query.all()
#     return problems

# @app.get("/problems/{problem_id}", response_model=ProblemResponse)
# def read_problem(
#     problem_id: int, 
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_verified_user)
# ):
#     problem = db.query(Problem).filter(Problem.id == problem_id).first()
#     if problem is None:
#         raise HTTPException(status_code=404, detail="Problem not found")
#     return problem

# @app.get("/problems/{problem_id}/solution")
# def get_problem_solution(
#     problem_id: int, 
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_verified_user)
# ):
#     problem = db.query(Problem).filter(Problem.id == problem_id).first()
#     if problem is None:
#         raise HTTPException(status_code=404, detail="Problem not found")
    
#     if problem.solution:
#         return {"solution": problem.solution}
#     else:
#         return {"solution": "No solution available for this problem."}

# # Additional endpoints for creating data (for admin purposes)
# @app.post("/topics/", response_model=TopicResponse)
# def create_topic(
#     topic: TopicCreate, 
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_verified_user)
# ):
#     db_topic = Topic(**topic.dict())
#     db.add(db_topic)
#     db.commit()
#     db.refresh(db_topic)
    
#     # Format response with empty problem counts
#     response = {
#         **db_topic.__dict__,
#         "problem_counts": {"easy": 0, "medium": 0, "hard": 0}
#     }
#     return response

# @app.post("/topics/{slug}/problems", response_model=ProblemResponse)
# def create_problem(
#     slug: str, 
#     problem: ProblemCreate, 
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_verified_user)
# ):
#     topic = db.query(Topic).filter(Topic.slug == slug).first()
#     if topic is None:
#         raise HTTPException(status_code=404, detail="Topic not found")
    
#     db_problem = Problem(**problem.dict(), topic_id=topic.id)
#     db.add(db_problem)
#     db.commit()
#     db.refresh(db_problem)
#     return db_problem

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)