from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
import openai
from fastapi.security import OAuth2PasswordBearer
import paypalrestsdk
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

app = FastAPI()

# Authentication and Security
SECRET_KEY = "YOUR_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# PayPal Configuration
paypalrestsdk.configure({
    "mode": "live",  # Change to "sandbox" for testing
    "client_id": "AYAGp8vTgF38pWCEdHPCkB6osrpUkCpjyQr5QykffSrZ9TmKuX8_rtEjzxcHsXflOvFxdG01BRtDiPeh",
    "client_secret": "EBPvVksQvcPwdlA6Y_307aKflyrUBtKJDaQSM_X47SJHK17DpcdOYqREtQ1cTH36hSL-9JzYQh6WWNRx"
})

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dummy Databases
users_db = {}
script_storage = {}

# Models
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

# PayPal Webhook
@app.post("/api/webhook/paypal")
async def paypal_webhook(request: Request):
    payload = await request.json()
    event_type = payload.get("event_type")
    resource = payload.get("resource", {})

    if event_type == "PAYMENT.SALE.COMPLETED":
        user_id = resource.get("custom_id")  # Custom field for mapping users

        if user_id in users_db:
            users_db[user_id]["is_pro"] = True
            return {"message": "User upgraded to Pro"}
        else:
            raise HTTPException(status_code=404, detail="User not found")

    return {"message": "Webhook received"}

# Check Pro Status
@app.get("/api/check_pro_status")
def check_pro_status(token: str = Depends(oauth2_scheme)):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    return {"is_pro": users_db.get(user_id, {}).get("is_pro", False)}

# Root Endpoint
@app.get("/")
async def root():
    return {"message": "Hello, FastAPI is running!"}
