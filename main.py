from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
import openai
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import paypalrestsdk
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os
import uvicorn

app = FastAPI()

# Configuration via environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OpenAI API key setup
openai.api_key = os.getenv("OPENAI_API_KEY")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

paypalrestsdk.configure({
    "mode": os.getenv("PAYPAL_MODE", "live"),
    "client_id": os.getenv("AYAGp8vTgF38pWCEdHPCkB6osrpUkCpjyQr5QykffSrZ9TmKuX8_rtEjzxcHsXflOvFxdG01BRtDiPeh"),
    "client_secret": os.getenv("EBPvVksQvcPwdlA6Y_307aKflyrUBtKJDaQSM_X47SJHK17DpcdOYqREtQ1cTH36hSL-9JzYQh6WWNRx")
})

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
users_db = {}
script_storage = {}

class User(BaseModel):
    username: str
    password: str
    is_pro: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class AuditionRequest(BaseModel):
    script: str
    role: str

class PaymentRequest(BaseModel):
    user_id: str
    amount: float

class ScriptStorageRequest(BaseModel):
    user_id: str
    script_name: str
    script_content: str

@app.get("/")
async def root():
    return {"message": "Hello, FastAPI with ChatGPT is running!"}

@app.post("/api/register")
async def register(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = pwd_context.hash(user.password)
    users_db[user.username] = {"password": hashed_password, "is_pro": False}
    return {"message": "User registered"}

@app.post("/api/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode(
        {"sub": form_data.username, "exp": datetime.utcnow() + access_token_expires},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/audition")
async def generate_audition(request: AuditionRequest, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["sub"]
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not users_db.get(user_id, {}).get("is_pro", False):
        raise HTTPException(status_code=403, detail="Pro account required")
    
    if not openai.api_key:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured")
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": f"You are auditioning for the role of {request.role}. Provide a response based on the given script."},
                {"role": "user", "content": request.script}
            ],
            max_tokens=150
        )
        return {"response": response.choices[0].message["content"]}
    except openai.error.OpenAIError as e:
        raise HTTPException(status_code=500, detail=f"ChatGPT error: {str(e)}")

@app.post("/api/webhook/paypal")
async def paypal_webhook(request: Request):
    payload = await request.json()
    event_type = payload.get("event_type")
    resource = payload.get("resource", {})
    
    if event_type == "PAYMENT.SALE.COMPLETED":
        user_id = resource.get("custom_id")
        if user_id in users_db:
            users_db[user_id]["is_pro"] = True
            return {"message": "User upgraded to Pro"}
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "Webhook received"}

@app.get("/api/check_pro_status")
def check_pro_status(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["sub"]
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"is_pro": users_db.get(user_id, {}).get("is_pro", False)}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

