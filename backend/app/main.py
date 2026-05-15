from app.email_service import send_email
from fastapi import FastAPI, Depends, HTTPException, Body, Request ,status, UploadFile, File
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session,joinedload
from app.database import SessionLocal, init_db
from app.models import User, Event, Project, Notification
from app.auth_utils import hash_password, verify_password, create_access_token, create_refresh_token, get_current_user, verify_token
from .schemas import (
    UserCreate, UserLogin, TokenResponse, ResetPasswordSchema, 
    RegisterResponse, UserResponse, EventCreate, EventResponse,
    ProjectCreate, ProjectUpdate, ProjectResponse,
    NotificationResponse, NotificationCreate, UpcomingEventSummary, UpcomingTasksResponse,
    ProfileUpdate,
    AIChatRequest, AIChatResponse, ReminderSuggestRequest, ReminderSuggestResponse,
    NaturalLanguageTaskRequest, NaturalLanguageTaskResponse
)
from app.ai_service import get_ai_service
import time, secrets, json, os, uuid
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


init_db()
app = FastAPI(title="Full Auth API with Roles and Reset Token")

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

if os.environ.get("FRONTEND_URL"):
    origins.append(os.environ.get("FRONTEND_URL"))

origins.extend([
    "https://remindly.vercel.app",
    "https://remindly-app.vercel.app",
    "https://frontend-iota-six-97.vercel.app"
])

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create uploads directory for profile pictures (using /tmp for Vercel compatibility)
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
print(f"[INFO] Upload directory: {UPLOAD_DIR}")

# Mount static files for serving uploads
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Dependency DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Health check
@app.get("/health")
def health_check():
    return {"status": "Backend is running"}

@app.post("/register", response_model=RegisterResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        if db.query(User).filter(User.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already exists")
        
        hashed_pw = hash_password(user.password)
        full_name = f"{user.first_name} {user.last_name}"
        
        new_user = User(
            email=user.email,
            hashed_password=hashed_pw,
            full_name=full_name
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        return RegisterResponse(
            msg="User created successfully",
            user=UserResponse.from_orm(new_user)
        )
    except Exception as e:
        import traceback
        traceback.print_exc() 
        raise HTTPException(status_code=500, detail=str(e))

# Login
@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if db_user.is_active != 1:
        raise HTTPException(status_code=403, detail="User inactive")
    if not verify_password(user.password, db_user.hashed_password):
        db_user.failed_login_attempts += 1
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Reset failed attempts
    db_user.failed_login_attempts = 0
    db_user.last_login = int(time.time())
    
    access_token = create_access_token({"sub": db_user.email})
    refresh_token = create_refresh_token({"sub": db_user.email})
    db_user.refresh_token = refresh_token
    db.commit()
    
    return {"access_token": access_token, "refresh_token": refresh_token}

# Logout
@app.post("/logout")
def logout(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    email = verify_token(refresh_token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user or db_user.refresh_token != refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not valid")
    db_user.refresh_token = None
    db.commit()
    return {"msg": f"User {email} has been logged out successfully"}

# Refresh token
@app.post("/refresh", response_model=TokenResponse)
def refresh_token(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    email = verify_token(refresh_token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user or db_user.refresh_token != refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not valid")
    
    new_access_token = create_access_token({"sub": email})
    new_refresh_token = create_refresh_token({"sub": email})
    db_user.refresh_token = new_refresh_token
    db.commit()
    return {"access_token": new_access_token, "refresh_token": new_refresh_token}

# Request reset token
@app.post("/request-reset")
def request_reset(email: str = Body(...), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    reset_token = secrets.token_urlsafe(32)
    db_user.reset_token = reset_token
    db_user.reset_token_expiry = int(time.time()) + 3600
    db.commit()
    return {"msg": "Reset token generated", "reset_token": reset_token}

# Reset password
@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.reset_token == data.reset_token).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    if db_user.reset_token_expiry < int(time.time()):
        raise HTTPException(status_code=400, detail="Reset token expired")
    
    db_user.hashed_password = hash_password(data.new_password)
    db_user.reset_token = None
    db_user.reset_token_expiry = None
    db.commit()
    return {"msg": f"Password for {db_user.email} has been reset successfully"}

# User route
@app.get("/user-dashboard")
def user_dashboard(current_user: User = Depends(lambda: get_current_user(required_roles=["user"]))):
    return {"msg": f"Welcome to user dashboard, {current_user.email}"}

# Admin route
@app.get("/admin-dashboard")
def admin_dashboard(current_user: User = Depends(lambda: get_current_user(required_roles=["admin"]))):
    return {"msg": f"Welcome to admin dashboard, {current_user.email}"}

@app.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.from_orm(current_user)

@app.put("/profile", response_model=UserResponse)
async def update_profile(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update user profile. Accepts partial updates.
    Fields: first_name, last_name, date_of_birth, phone_number, country, city, profile_picture
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Validate with Pydantic
    try:
        profile_data = ProfileUpdate(**body)
    except Exception as e:
         raise HTTPException(status_code=422, detail=str(e))

    # Re-fetch user from database to ensure it's in current session
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get provided fields from Pydantic model
    update_data = profile_data.dict(exclude_unset=True)
    
    allowed_fields = ['first_name', 'last_name', 'date_of_birth', 'phone_number', 'country', 'city', 'profile_picture']
    
    for field in allowed_fields:
        if field in update_data:
            setattr(user, field, update_data[field])
    
    # Update full_name if first_name or last_name changed
    if 'first_name' in update_data or 'last_name' in update_data:
        first = update_data.get('first_name') or user.first_name or ''
        last = update_data.get('last_name') or user.last_name or ''
        user.full_name = f"{first} {last}".strip()
    
    try:
        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    return UserResponse.from_orm(user)



@app.post("/upload-profile-picture")
async def upload_profile_picture(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload a profile picture. Returns the URL of the uploaded image.
    Accepts: image/jpeg, image/png, image/gif, image/webp
    """
    # Validate file type
    allowed_types = ["image/jpeg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid file type. Allowed: {', '.join(allowed_types)}"
        )
    
    # Re-fetch user from database to ensure it's in current session
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate unique filename
    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    filename = f"profile_{user.id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    # Save file
    try:
        contents = await file.read()
        with open(filepath, "wb") as f:
            f.write(contents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    # Update user's profile picture URL
    profile_url = f"/uploads/{filename}"
    user.profile_picture = profile_url
    
    try:
        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()
        # Clean up uploaded file on error
        if os.path.exists(filepath):
            os.remove(filepath)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    return {"url": profile_url, "message": "Profile picture uploaded successfully"}


@app.post("/events", response_model=EventResponse)
async def create_event(
    payload: Optional[EventCreate] = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create event. Accepts direct EventCreate or wrapped { payload: {...} }.
    If end_date is omitted, it will be set equal to start_date (single-day event).
    If all_day is true, times are defaulted to 00:00 - 23:59 when missing.
    Returns EventResponse with optional project_name.
    """
    # Normalize input (fast-path if payload parsed by FastAPI)
    data_obj = None
    if payload is not None:
        data_obj = payload.dict()
    else:
        try:
            body_json = await request.json()
        except Exception:
            body_json = None

        if body_json is None:
            raise HTTPException(status_code=400, detail="No JSON body received")

        if isinstance(body_json, dict) and "payload" in body_json and isinstance(body_json["payload"], dict):
            data_obj = body_json["payload"]
        elif isinstance(body_json, dict):
            data_obj = body_json
        else:
            raise HTTPException(status_code=422, detail="Invalid JSON body for event")

        try:
            payload = EventCreate.parse_obj(data_obj)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid body for EventCreate: {str(e)}")
        data_obj = payload.dict()

    # Ensure start_date exists
    if not payload.start_date:
        raise HTTPException(status_code=422, detail="start_date is required")

    # If end_date missing, set to start_date (single-day event)
    if not payload.end_date:
        payload.end_date = payload.start_date

    # If all_day, fill times if missing
    if payload.all_day:
        if not payload.start_time:
            payload.start_time = "00:00"
        if not payload.end_time:
            payload.end_time = "23:59"

    # Validate project_id ownership if provided (nullable allowed)
    project = None
    if payload.project_id is not None:
        project = db.query(Project).filter(Project.id == payload.project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if project.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="You cannot attach event to a project you don't own")

    # Create Event
    new_event = Event(
        title=payload.title,
        description=payload.description,
        start_date=payload.start_date,
        end_date=payload.end_date,
        start_time=payload.start_time,
        end_time=payload.end_time,
        all_day=payload.all_day,
        guest=payload.guest,
        location=payload.location,
        meeting_type=payload.meeting_type,
        project_id=payload.project_id,
        user_id=current_user.id,
    )

    db.add(new_event)
    try:
        db.commit()
        db.refresh(new_event)
        if new_event.project_id:
            db.refresh(new_event, ['project'])
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")
    event_with_relations = db.query(Event).options(
        joinedload(Event.user),
        joinedload(Event.project)
    ).filter(Event.id == new_event.id).first()

    resp = EventResponse.from_orm(event_with_relations).dict()
    resp["participants"] = len([g.strip() for g in (event_with_relations.guest or "").split(",") if g.strip()])
    resp["project_name"] = event_with_relations.project.name if event_with_relations.project else None
    resp["project_color"] = event_with_relations.project.color if event_with_relations.project else None
    
    # Tambahkan organizer info
    resp["organizer_id"] = event_with_relations.user.id
    resp["organizer_name"] = event_with_relations.user.full_name or event_with_relations.user.email
    resp["organizer_email"] = event_with_relations.user.email
    
    return resp


@app.get("/events")
def get_events(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Gunakan joinedload untuk mengambil data user dan project sekaligus
    # Sort by start_date and start_time (earliest first)
    events = db.query(Event).options(
        joinedload(Event.user),
        joinedload(Event.project)
    ).filter(Event.user_id == current_user.id).order_by(
        Event.start_date.asc(),
        Event.start_time.asc()
    ).all()
    
    out = []
    for e in events:
        d = EventResponse.from_orm(e).dict()
        
        # Project info langsung dari relationship yang sudah di-join
        d["project_name"] = e.project.name if e.project else "No Project"
        d["project_color"] = e.project.color if e.project else "#337AF7"  # Default color

        # participants: hitung dari guest CSV
        if e.guest:
            d["participants"] = len([x for x in (e.guest or "").split(",") if x.strip()])
        else:
            d["participants"] = 0

        # Tambahkan organizer info
        d["organizer_id"] = e.user.id
        d["organizer_name"] = e.user.full_name or e.user.email
        d["organizer_email"] = e.user.email

        # Guest list
        d["guest_list"] = [g.strip() for g in (e.guest or "").split(",") if g.strip()] if e.guest else []

        # Time display
        if e.start_time and e.end_time:
            d["time_display"] = f"{e.start_time} - {e.end_time}"
        elif e.all_day:
            d["time_display"] = "All day"
        else:
            d["time_display"] = "No time specified"

        out.append(d)
    return out

# Edit Event
@app.put("/events/{event_id}", response_model=EventResponse)
async def update_event(
    event_id: int,
    payload: Optional[EventCreate] = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update event. Accepts direct EventCreate or wrapped { payload: {...} }.
    Returns updated EventResponse with project info.
    """
    # Cari event yang akan diupdate
    event = db.query(Event).filter(Event.id == event_id, Event.user_id == current_user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Normalize input (sama seperti create event)
    data_obj = None
    if payload is not None:
        data_obj = payload.dict()
    else:
        try:
            body_json = await request.json()
        except Exception:
            body_json = None

        if body_json is None:
            raise HTTPException(status_code=400, detail="No JSON body received")

        if isinstance(body_json, dict) and "payload" in body_json and isinstance(body_json["payload"], dict):
            data_obj = body_json["payload"]
        elif isinstance(body_json, dict):
            data_obj = body_json
        else:
            raise HTTPException(status_code=422, detail="Invalid JSON body for event")

        try:
            payload = EventCreate.parse_obj(data_obj)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid body for EventCreate: {str(e)}")
        data_obj = payload.dict()

    # Validasi project_id ownership jika diubah
    project = None
    if payload.project_id is not None:
        project = db.query(Project).filter(Project.id == payload.project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if project.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="You cannot attach event to a project you don't own")

    # Update fields
    if payload.title is not None:
        event.title = payload.title
    if payload.description is not None:
        event.description = payload.description
    if payload.start_date is not None:
        event.start_date = payload.start_date
    if payload.end_date is not None:
        event.end_date = payload.end_date
    if payload.start_time is not None:
        event.start_time = payload.start_time
    if payload.end_time is not None:
        event.end_time = payload.end_time
    if payload.all_day is not None:
        event.all_day = payload.all_day
    if payload.guest is not None:
        event.guest = payload.guest
    if payload.location is not None:
        event.location = payload.location
    if payload.meeting_type is not None:
        event.meeting_type = payload.meeting_type
    
    # Handle project_id explicitly - allow setting to None (remove from project)
    # Check if project_id was provided in the request (including null)
    if 'project_id' in data_obj:
        event.project_id = payload.project_id  # Can be None to remove from project

    # Jika all_day true, pastikan times ada
    if event.all_day:
        if not event.start_time:
            event.start_time = "00:00"
        if not event.end_time:
            event.end_time = "23:59"

    try:
        db.commit()
        # Refresh dengan join untuk mendapatkan project data
        event_with_relations = db.query(Event).options(
            joinedload(Event.user),
            joinedload(Event.project)
        ).filter(Event.id == event_id).first()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

    # Build response dari data yang sudah di-join
    resp = EventResponse.from_orm(event_with_relations).dict()
    resp["participants"] = len([g.strip() for g in (event_with_relations.guest or "").split(",") if g.strip()])
    resp["project_name"] = event_with_relations.project.name if event_with_relations.project else None
    resp["project_color"] = event_with_relations.project.color if event_with_relations.project else None
    
    # Tambahkan organizer info
    resp["organizer_id"] = event_with_relations.user.id
    resp["organizer_name"] = event_with_relations.user.full_name or event_with_relations.user.email
    resp["organizer_email"] = event_with_relations.user.email
    
    return resp


# Delete Event
@app.delete("/events/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_event(
    event_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete event by ID. Only the event owner can delete.
    """
    event = db.query(Event).filter(Event.id == event_id, Event.user_id == current_user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    try:
        db.delete(event)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

    return

@app.get("/events/{event_id}", response_model=EventResponse)
def get_event_detail(
    event_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get detailed information for a specific event.
    Returns complete event data including project information.
    """
    # Gunakan joinedload untuk mengambil data user dan project sekaligus
    event = db.query(Event).options(
        joinedload(Event.user),
        joinedload(Event.project)
    ).filter(
        Event.id == event_id, 
        Event.user_id == current_user.id
    ).first()
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Build detailed response
    resp = EventResponse.from_orm(event).dict()
    
    # Project info langsung dari relationship
    resp["project_name"] = event.project.name if event.project else None
    resp["project_color"] = event.project.color if event.project else None
    resp["project_id"] = event.project_id
    
    # Tambahkan informasi user/organizer
    resp["organizer_id"] = event.user.id
    resp["organizer_name"] = event.user.full_name or event.user.email
    resp["organizer_email"] = event.user.email
    resp["organizer_profile_picture"] = event.user.profile_picture
    
    # Parse guest list and resolve to user objects with profile pictures
    if event.guest:
        guest_raw = event.guest or ""
        guest_emails = [g.strip() for g in guest_raw.split(",") if g.strip()]
        
        # Look up users by email to get profile pictures
        guest_list = []
        for email in guest_emails:
            user = db.query(User).filter(User.email == email).first()
            if user:
                guest_list.append({
                    "email": user.email,
                    "full_name": user.full_name or user.email,
                    "profile_picture": user.profile_picture
                })
            else:
                # Non-registered guest
                guest_list.append({
                    "email": email,
                    "full_name": email,
                    "profile_picture": None
                })
        
        resp["guest_list"] = guest_list
        resp["participants"] = len(guest_list)
    else:
        resp["guest_list"] = []
        resp["participants"] = 0
    
    # Format waktu untuk display
    if event.start_time and event.end_time:
        resp["time_display"] = f"{event.start_time} - {event.end_time}"
    elif event.all_day:
        resp["time_display"] = "All day"
    else:
        resp["time_display"] = "No time specified"
    
    return resp

# Get events by date range (optional enhancement)
@app.get("/events/range")
def get_events_by_date_range(
    start_date: str,
    end_date: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get events within a date range for the current user.
    Useful for calendar views.
    """
    events = db.query(Event).options(
    joinedload(Event.user),
    joinedload(Event.project)
).filter(Event.user_id == current_user.id).all()

    
    out = []
    for e in events:
        d = EventResponse.from_orm(e).dict()
        # project info
        proj = None
        proj = e.project

        d["project_name"] = proj.name if proj else None
        d["project_color"] = proj.color if proj else None

        # participants
        if e.guest:
            d["participants"] = len([x for x in (e.guest or "").split(",") if x.strip()])
        else:
            d["participants"] = 0

        # Tambahkan organizer info
        d["organizer_id"] = e.user.id
        d["organizer_name"] = e.user.full_name or e.user.email
        d["organizer_email"] = e.user.email

        out.append(d)
    return out


@app.get("/projects", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    projects = db.query(Project).filter(Project.user_id == current_user.id).order_by(Project.created_at.desc()).all()
    results = []
    for p in projects:
        meeting_count = db.query(Event).filter(Event.project_id == p.id).count()
        resp = ProjectResponse.from_orm(p)
        resp.meetings = meeting_count
        results.append(resp)
    return results

# Create project
@app.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        body_json = await request.json()
    except Exception:
        body_json = None


    if body_json is None:
        raise HTTPException(status_code=400, detail="No JSON body received")

    if isinstance(body_json, dict) and "payload" in body_json and isinstance(body_json["payload"], dict):
        data = body_json["payload"]
    else:
        data = body_json

 
    try:
        payload = ProjectCreate.parse_obj(data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid body for ProjectCreate: {str(e)}")

    existing = db.query(Project).filter(Project.user_id == current_user.id, Project.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Project name already exists")

    new_project = Project(
        name=payload.name,
        color=payload.color,
        meetings=0,
        user_id=current_user.id
    )
    db.add(new_project)
    try:
        db.commit()
        db.refresh(new_project)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

    resp = ProjectResponse.from_orm(new_project)
    resp.meetings = 0
    return resp
    

@app.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int, include_events: Optional[bool] = False, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Gunakan joinedload untuk mengambil project dengan events dan relations
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == current_user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Jika include_events True, ambil events dengan semua relations
    events = []
    if include_events:
        events = db.query(Event).options(
            joinedload(Event.user),
            joinedload(Event.project)
        ).filter(Event.project_id == project.id).order_by(Event.start_date).all()

    # Build response
    resp = ProjectResponse.from_orm(project)
    resp.meetings = len(events)
    
    if include_events:
        event_responses = []
        for event in events:
            event_data = EventResponse.from_orm(event).dict()
            
            # Tambahkan project info dari relationship yang sudah di-join
            event_data["project_name"] = project.name  # Langsung dari project yang sudah diambil
            event_data["project_color"] = project.color  # Langsung dari project yang sudah diambil
            
            # Participants count
            if event.guest:
                event_data["participants"] = len([g.strip() for g in (event.guest or "").split(",") if g.strip()])
            else:
                event_data["participants"] = 0
            
            # Organizer info
            event_data["organizer_id"] = event.user.id
            event_data["organizer_name"] = event.user.full_name or event.user.email
            event_data["organizer_email"] = event.user.email
            
            # Guest list
            if event.guest:
                event_data["guest_list"] = [g.strip() for g in (event.guest or "").split(",") if g.strip()]
            else:
                event_data["guest_list"] = []
            
            # Time display
            if event.start_time and event.end_time:
                event_data["time_display"] = f"{event.start_time} - {event.end_time}"
            elif event.all_day:
                event_data["time_display"] = "All day"
            else:
                event_data["time_display"] = "No time specified"
            
            event_responses.append(EventResponse(**event_data))
        
        resp.events = event_responses
    
    return resp

@app.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        body_json = await request.json()
    except Exception:
        body_json = None

    if body_json is None:
        raise HTTPException(status_code=400, detail="No JSON body received")

    if isinstance(body_json, dict) and "payload" in body_json and isinstance(body_json["payload"], dict):
        data = body_json["payload"]
    else:
        data = body_json

    try:
        payload = ProjectUpdate.parse_obj(data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid body for ProjectUpdate: {str(e)}")

    project = db.query(Project).filter(Project.id == project_id, Project.user_id == current_user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if payload.name and payload.name != project.name:
        exists = db.query(Project).filter(Project.user_id == current_user.id, Project.name == payload.name).first()
        if exists:
            raise HTTPException(status_code=400, detail="Project name already exists")

    updated = False
    if payload.name is not None:
        project.name = payload.name
        updated = True
    if payload.color is not None:
        project.color = payload.color
        updated = True

    if not updated:
        db.refresh(project)
        resp = ProjectResponse.from_orm(project)
        resp.meetings = db.query(Event).filter(Event.project_id == project.id).count()
        return resp

    try:
        db.commit()
        db.refresh(project)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")


    resp = ProjectResponse.from_orm(project)
    resp.meetings = db.query(Event).filter(Event.project_id == project.id).count()
    return resp

@app.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == current_user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        db.delete(project)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

    return


@app.get("/projects/{project_id}/events", response_model=List[EventResponse])
def get_project_events(project_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == current_user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    events = db.query(Event).filter(Event.project_id == project.id).order_by(Event.start_date).all()
    return [EventResponse.from_orm(e) for e in events]


@app.get("/users", response_model=List[UserResponse])
def list_users_for_suggestions(
    query: Optional[str] = None,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    q = db.query(User)
    if query:
        q = q.filter(
            (User.email.ilike(f"%{query}%")) |
            (User.full_name.ilike(f"%{query}%"))
        )
    users = q.order_by(User.full_name).limit(limit).all()
    return [UserResponse.from_orm(u) for u in users]


# =============================================================================
# NOTIFICATION ENDPOINTS - AI-Powered Reminders
# =============================================================================

@app.get("/notifications/upcoming", response_model=UpcomingTasksResponse)
async def get_upcoming_tasks_with_ai(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get upcoming events for TODAY with AI-generated reminder messages.
    
    This endpoint uses Mistral LLM to generate personalized reminders
    for each upcoming event scheduled for today.
    
    Performance optimized:
    - Uses in-memory caching for AI responses
    - Parallel AI calls for multiple events
    
    Returns:
        UpcomingTasksResponse with AI-generated content
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    
    # Get today's date only
    today = datetime.now().date()
    today_str = today.strftime("%Y-%m-%d")
    
    # Query events for today only
    events = db.query(Event).options(
        joinedload(Event.project)
    ).filter(
        Event.user_id == current_user.id,
        Event.start_date == today_str
    ).order_by(Event.start_time).all()
    
    # Get AI service
    ai_service = get_ai_service()
    
    # Prepare event data for parallel processing
    event_data_list = []
    for event in events:
        event_date = datetime.strptime(event.start_date, "%Y-%m-%d").date()
        days_until = (event_date - today).days
        event_data_list.append({
            "event": event,
            "days_until": days_until
        })
    
    # Generate AI reminders in parallel using ThreadPoolExecutor
    def generate_reminder_for_event(event_data):
        """Wrapper function to generate reminder for a single event."""
        event = event_data["event"]
        days_until = event_data["days_until"]
        return ai_service.generate_reminder_message(
            event_id=event.id,
            event_title=event.title,
            event_date=event.start_date,
            days_until=days_until,
            event_time=event.start_time,
            event_description=event.description,
            project_name=event.project.name if event.project else None
        )
    
    # Run AI calls in parallel
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=10) as executor:
        ai_reminders = await asyncio.gather(*[
            loop.run_in_executor(executor, generate_reminder_for_event, ed)
            for ed in event_data_list
        ])
    
    # Build response with AI-generated reminders
    upcoming_events = []
    events_for_summary = []
    
    for i, event_data in enumerate(event_data_list):
        event = event_data["event"]
        days_until = event_data["days_until"]
        ai_reminder = ai_reminders[i] if i < len(ai_reminders) else None
        
        upcoming_events.append(UpcomingEventSummary(
            event_id=event.id,
            title=event.title,
            start_date=event.start_date,
            end_date=event.end_date,
            start_time=event.start_time,
            end_time=event.end_time,
            days_until=days_until,
            project_name=event.project.name if event.project else None,
            location=event.location,
            ai_reminder=ai_reminder
        ))
        
        events_for_summary.append({
            "title": event.title,
            "days_until": days_until
        })
    
    # Generate overall AI summary (also cached)
    ai_summary = ai_service.generate_summary(events_for_summary, today_str)
    
    return UpcomingTasksResponse(
        total_events=len(upcoming_events),
        upcoming_events=upcoming_events,
        ai_summary=ai_summary
    )


@app.get("/notifications", response_model=List[NotificationResponse])
def get_notifications(
    unread_only: bool = False,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get all notifications for the current user.
    
    Args:
        unread_only: If True, return only unread notifications
        limit: Maximum number of notifications to return
        
    Returns:
        List of NotificationResponse objects
    """
    query = db.query(Notification).options(
        joinedload(Notification.event)
    ).filter(
        Notification.user_id == current_user.id
    )
    
    if unread_only:
        query = query.filter(Notification.is_read == False)
    
    notifications = query.order_by(Notification.created_at.desc()).limit(limit).all()
    
    result = []
    for notif in notifications:
        resp = NotificationResponse.from_orm(notif)
        if notif.event:
            resp.event_title = notif.event.title
            resp.event_date = notif.event.start_date
        result.append(resp)
    
    return result


@app.get("/notifications/count")
def get_unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get the count of unread notifications for the current user.
    
    Returns:
        Dictionary with unread count
    """
    count = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).count()
    
    return {"unread_count": count}


@app.post("/notifications", response_model=NotificationResponse, status_code=status.HTTP_201_CREATED)
def create_notification(
    payload: NotificationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a new notification for the current user.
    
    This can be used to manually create notifications or
    by background jobs for automated reminders.
    
    Args:
        payload: NotificationCreate schema with notification details
        
    Returns:
        Created NotificationResponse
    """
    # Validate event_id if provided
    if payload.event_id:
        event = db.query(Event).filter(
            Event.id == payload.event_id,
            Event.user_id == current_user.id
        ).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
    
    new_notification = Notification(
        user_id=current_user.id,
        event_id=payload.event_id,
        title=payload.title,
        message=payload.message,
        notification_type=payload.notification_type,
        expires_at=payload.expires_at
    )
    
    db.add(new_notification)
    try:
        db.commit()
        db.refresh(new_notification)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")
    
    return NotificationResponse.from_orm(new_notification)


@app.patch("/notifications/{notification_id}/read")
def mark_notification_as_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Mark a notification as read.
    
    Args:
        notification_id: ID of the notification to mark as read
        
    Returns:
        Success message
    """
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()
    
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification.is_read = True
    db.commit()
    
    return {"msg": "Notification marked as read"}


@app.patch("/notifications/read-all")
def mark_all_notifications_as_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Mark all notifications as read for the current user.
    
    Returns:
        Count of notifications marked as read
    """
    count = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).update({"is_read": True})
    
    db.commit()
    
    return {"msg": f"{count} notifications marked as read"}


@app.delete("/notifications/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_notification(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete a notification.
    
    Args:
        notification_id: ID of the notification to delete
    """
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()
    
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    db.delete(notification)
    db.commit()
    
    return


# =============================================================================
# AI CHAT ENDPOINTS - Schedule Assistant
# =============================================================================

@app.post("/ai/chat", response_model=AIChatResponse)
async def ai_chat(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    AI Chat endpoint for schedule assistance.
    
    Returns either:
    - Chat response with clarifying questions
    - Schedule proposal with structured JSON data
    - Error response if AI service fails
    """
    # Parse body manually to avoid pydantic issues
    try:
        body = await request.json()
        message = body.get("message", "")
        timezone = body.get("timezone", "Asia/Jakarta")
        conversation_history = body.get("conversation_history")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid request body: {str(e)}")
    
    if not message:
        raise HTTPException(status_code=422, detail="Message is required")
    
    ai = get_ai_service()
    
    # Fetch user's upcoming events for context (next 30 days)
    today = datetime.now().date()
    end_date = today + timedelta(days=30)
    
    user_events = db.query(Event).filter(
        Event.user_id == current_user.id,
        Event.start_date >= today.strftime("%Y-%m-%d"),
        Event.start_date <= end_date.strftime("%Y-%m-%d")
    ).order_by(Event.start_date, Event.start_time).limit(20).all()
    
    # Convert to dict format for AI
    events_data = []
    for event in user_events:
        events_data.append({
            "title": event.title,
            "start_date": event.start_date,
            "start_time": event.start_time,
            "end_time": event.end_time,
            "location": event.location,
            "description": event.description
        })
    
    # Convert conversation history to dict format
    history = None
    if conversation_history:
        history = [{"role": m.get("role", "user"), "content": m.get("content", "")} for m in conversation_history]
    
    result = ai.chat_with_schedule_assistant(
        user_message=message,
        conversation_history=history,
        timezone=timezone,
        user_events=events_data
    )
    
    # Handle error responses
    if result.get("type") == "error":
        return AIChatResponse(
            type="error",
            message=result.get("message", "AI service is temporarily unavailable.")
        )
    
    # Handle schedule proposal
    if result.get("type") == "schedule_proposal":
        return AIChatResponse(
            type="schedule_proposal",
            message=result.get("message", "Here's your proposed schedule:"),
            schedule=result.get("schedule")
        )
    
    # Regular chat response
    return AIChatResponse(
        type="chat",
        message=result.get("message", "I'm here to help with your schedule.")
    )


@app.post("/ai/suggest-alternative-times")
async def suggest_alternative_times(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get AI-suggested alternative times when a schedule conflict is detected.
    
    Request body:
    - conflicting_event_title: Title of the conflicting event
    - conflicting_start: Start time of conflicting event (HH:MM)
    - conflicting_end: End time of conflicting event (HH:MM)
    - date: Date of the event (YYYY-MM-DD)
    - duration_minutes: Duration of the new event in minutes
    
    Returns suggested non-conflicting time slots.
    Now considers current time to avoid suggesting past time slots.
    """
    # Parse request body manually
    try:
        request_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid JSON body: {str(e)}")
    
    ai = get_ai_service()
    
    conflicting_event_title = request_data.get("conflicting_event_title", "")
    conflicting_start = request_data.get("conflicting_start", "")
    conflicting_end = request_data.get("conflicting_end", "")
    date = request_data.get("date", "")
    duration_minutes = request_data.get("duration_minutes", 60)
    
    # Get current time and date for filtering past suggestions
    now = datetime.now()
    current_time = now.strftime("%H:%M")
    current_date = now.strftime("%Y-%m-%d")
    
    # Get user's other events on that day for context
    existing_events = []
    if date:
        events_on_date = db.query(Event).filter(
            Event.user_id == current_user.id,
            Event.start_date == date
        ).all()
        
        for event in events_on_date:
            existing_events.append({
                "title": event.title,
                "start_time": event.start_time,
                "end_time": event.end_time
            })
    
    result = ai.suggest_alternative_times(
        conflicting_event_title=conflicting_event_title,
        conflicting_start=conflicting_start,
        conflicting_end=conflicting_end,
        date=date,
        duration_minutes=duration_minutes,
        existing_events=existing_events,
        current_time=current_time,
        current_date=current_date
    )
    
    return result


@app.post("/ai/parse-task", response_model=NaturalLanguageTaskResponse)
def parse_natural_language_task(
    task_request: NaturalLanguageTaskRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Parse natural language input into structured task/event data.
    
    Returns either:
    - Parsed task data ready to create
    - Clarification request if details are missing
    - Error response if parsing fails
    """
    ai = get_ai_service()
    
    # Use provided date or current date
    current_date = task_request.current_date or datetime.now().strftime("%Y-%m-%d")
    
    result = ai.parse_natural_language_task(
        user_input=task_request.user_input,
        current_date=current_date
    )
    
    # Handle error responses
    if result.get("type") == "error":
        return NaturalLanguageTaskResponse(
            type="error",
            message=result.get("message", "AI service is temporarily unavailable.")
        )
    
    # Handle clarification requests
    if result.get("type") == "clarification":
        return NaturalLanguageTaskResponse(
            type="clarification",
            message=result.get("message")
        )
    
    # Return parsed task data
    return NaturalLanguageTaskResponse(
        type="task",
        data=result.get("data")
    )


@app.post("/events/{event_id}/invite")
def invite_guests_to_event(
    event_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    event = db.query(Event).filter(
        Event.id == event_id,
        Event.user_id == current_user.id
    ).first()

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    if not event.guest:
        raise HTTPException(status_code=400, detail="Guest list is empty")

  

    ai_invite = get_ai_service()
    email_content = ai_invite.generate_invitation_email(
        event_title=event.title,
        event_date=event.start_date,
        event_time=event.start_time,
        meeting_type=event.meeting_type,
        location=event.location,
        meeting_link=event.location,
        organizer_name=current_user.full_name or current_user.email,
        description=event.description
    )

    guest_emails = [e.strip() for e in event.guest.split(",") if e.strip()]


    failed = []

    for email in guest_emails:
        try:
            send_email(
                to=email,
                subject=email_content["subject"],
                body=email_content["body"]
                
            )
        except Exception:
            failed.append(email)

    # Optional log notification
    notif = Notification(
        user_id=current_user.id,
        event_id=event.id,
        title=email_content["subject"],
        message=f"Invitation sent to {len(guest_emails)} guests",
        notification_type="invitation"
    )
    db.add(notif)
    db.commit()

    return {
        "sent": len(guest_emails) - len(failed),
        "failed": failed
    }