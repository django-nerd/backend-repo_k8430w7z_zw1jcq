import os
import json
import hmac
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

from database import db

from dotenv import load_dotenv
load_dotenv()

# Simple JWT (HS256) without external deps
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, default=str, separators=(',', ':')).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def jwt_decode(token: str, secret: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64url_decode(payload_b64))
        # exp check
        if 'exp' in payload:
            exp = datetime.fromisoformat(payload['exp']) if isinstance(payload['exp'], str) else datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                raise ValueError("Token expired")
        return payload
    except Exception as e:
        raise ValueError(str(e))

# Simple password hashing without external deps (demo purposes)
PWD_SALT = os.getenv("PWD_SALT", "salt")

def hash_password(password: str) -> str:
    return hashlib.sha256((password + PWD_SALT).encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt_encode(to_encode, JWT_SECRET)

# FastAPI app
app = FastAPI(title="E-commerce API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Pydantic models
class Address(BaseModel):
    full_name: str
    line1: str
    line2: Optional[str] = None
    city: str
    state: str
    postal_code: str
    country: str
    phone: Optional[str] = None

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    is_admin: bool = False

class UserUpdate(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProductCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    category_id: Optional[str] = None
    category_name: Optional[str] = None
    images: List[str] = []
    brand: Optional[str] = None
    count_in_stock: int = 0

class ProductUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = Field(None, ge=0)
    category_id: Optional[str] = None
    category_name: Optional[str] = None
    images: Optional[List[str]] = None
    brand: Optional[str] = None
    count_in_stock: Optional[int] = None

class ReviewCreate(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None

class CartItem(BaseModel):
    product_id: str
    title: str
    image: Optional[str] = None
    price: float
    qty: int = Field(..., ge=1)

class CartUpdate(BaseModel):
    items: List[CartItem]

class OrderItem(BaseModel):
    product_id: str
    title: str
    image: Optional[str] = None
    price: float
    qty: int

class OrderCreate(BaseModel):
    items: List[OrderItem]
    shipping_address: Address
    total_amount: float
    currency: str = "usd"
    payment_intent_id: Optional[str] = None

class PaymentIntentRequest(BaseModel):
    amount: float
    currency: str = "usd"

# Dependencies
async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt_decode(token, JWT_SECRET)
        user_id: str = payload.get("sub")
        if not user_id:
            raise ValueError("No sub")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(user: dict):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")

# Auth
@app.post("/api/auth/register", response_model=UserPublic)
def register(payload: UserCreate):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use")
    doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(doc)
    return {"id": str(res.inserted_id), "name": doc["name"], "email": doc["email"], "is_admin": False}

@app.post("/api/auth/login")
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer", "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "is_admin": user.get("is_admin", False)}}

# Users
@app.get("/api/users/me", response_model=UserPublic)
def get_me(current_user: dict = Depends(get_current_user)):
    return {"id": str(current_user["_id"]), "name": current_user["name"], "email": current_user["email"], "is_admin": current_user.get("is_admin", False)}

@app.put("/api/users/me", response_model=UserPublic)
def update_me(body: UserUpdate, current_user: dict = Depends(get_current_user)):
    update: Dict[str, Any] = {}
    if body.name is not None:
        update["name"] = body.name
    if body.password is not None:
        update["password_hash"] = hash_password(body.password)
    if not update:
        return {"id": str(current_user["_id"]), "name": current_user["name"], "email": current_user["email"], "is_admin": current_user.get("is_admin", False)}
    update["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": current_user["_id"]}, {"$set": update})
    user = db["user"].find_one({"_id": current_user["_id"]})
    return {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "is_admin": user.get("is_admin", False)}

@app.get("/api/admin/users")
def admin_users(current_user: dict = Depends(get_current_user)):
    require_admin(current_user)
    users = []
    for u in db["user"].find():
        users.append({"id": str(u["_id"]), "name": u["name"], "email": u["email"], "is_admin": u.get("is_admin", False)})
    return {"users": users}

# Categories
@app.get("/api/categories")
def get_categories():
    cats = []
    for c in db["category"].find():
        cats.append({"id": str(c["_id"]), "name": c["name"], "slug": c["slug"], "description": c.get("description")})
    return {"categories": cats}

# Products
@app.post("/api/products")
def create_product(body: ProductCreate, current_user: dict = Depends(get_current_user)):
    require_admin(current_user)
    doc = body.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = db["product"].insert_one(doc)
    return {"id": str(res.inserted_id), **{k: v for k, v in doc.items() if k != "_id"}}

@app.put("/api/products/{product_id}")
def update_product(product_id: str, body: ProductUpdate, current_user: dict = Depends(get_current_user)):
    require_admin(current_user)
    update = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    update["updated_at"] = datetime.now(timezone.utc)
    db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": update})
    prod = db["product"].find_one({"_id": ObjectId(product_id)})
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    prod["id"] = str(prod.pop("_id"))
    return prod

@app.delete("/api/products/{product_id}")
def delete_product(product_id: str, current_user: dict = Depends(get_current_user)):
    require_admin(current_user)
    db["product"].delete_one({"_id": ObjectId(product_id)})
    return {"success": True}

@app.get("/api/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None, sort: Optional[str] = None, page: int = 1, limit: int = 12):
    query: Dict[str, Any] = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"brand": {"$regex": q, "$options": "i"}},
        ]
    if category:
        query["$or"] = query.get("$or", []) + [{"category_name": {"$regex": f"^{category}$", "$options": "i"}}]
    sort_spec = None
    if sort == "price_asc":
        sort_spec = [("price", 1)]
    elif sort == "price_desc":
        sort_spec = [("price", -1)]
    elif sort == "newest":
        sort_spec = [("created_at", -1)]

    skip = max(page - 1, 0) * limit
    cursor = db["product"].find(query)
    total = db["product"].count_documents(query)
    if sort_spec:
        cursor = cursor.sort(sort_spec)
    items = []
    for p in cursor.skip(skip).limit(limit):
        p["id"] = str(p.pop("_id"))
        items.append(p)
    return {"items": items, "page": page, "limit": limit, "total": total}

@app.get("/api/products/{product_id}")
def get_product(product_id: str):
    p = db["product"].find_one({"_id": ObjectId(product_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    p["id"] = str(p.pop("_id"))
    reviews = []
    for r in db["review"].find({"product_id": product_id}).sort([("created_at", -1)]):
        r["id"] = str(r.pop("_id"))
        reviews.append(r)
    p["reviews"] = reviews
    return p

@app.post("/api/products/{product_id}/reviews")
def add_review(product_id: str, body: ReviewCreate, current_user: dict = Depends(get_current_user)):
    existing = db["review"].find_one({"product_id": product_id, "user_id": str(current_user["_id"])})
    if existing:
        raise HTTPException(status_code=400, detail="You already reviewed this product")
    doc = {
        "product_id": product_id,
        "user_id": str(current_user["_id"]),
        "user_name": current_user["name"],
        "rating": body.rating,
        "comment": body.comment,
        "created_at": datetime.now(timezone.utc)
    }
    db["review"].insert_one(doc)
    pipeline = [
        {"$match": {"product_id": product_id}},
        {"$group": {"_id": "$product_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
    ]
    agg = list(db["review"].aggregate(pipeline))
    if agg:
        db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": {"rating": round(agg[0]["avg"], 2), "num_reviews": agg[0]["count"]}})
    return {"success": True}

# Cart
@app.get("/api/cart")
def get_cart(current_user: dict = Depends(get_current_user)):
    cart = db["cart"].find_one({"user_id": str(current_user["_id"])}) or {"items": []}
    return {"items": cart.get("items", [])}

@app.post("/api/cart")
def set_cart(payload: CartUpdate, current_user: dict = Depends(get_current_user)):
    db["cart"].update_one(
        {"user_id": str(current_user["_id"])},
        {"$set": {"items": [i.model_dump() for i in payload.items], "updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
    return {"success": True}

# Payments (dummy intent without external deps; still returns usable structure)
@app.post("/api/payments/intent")
def payment_intent(payload: PaymentIntentRequest, current_user: dict = Depends(get_current_user)):
    client_secret = f"dummy_secret_{int(datetime.now().timestamp())}"
    intent_id = f"pi_dummy_{int(datetime.now().timestamp())}"
    return {"client_secret": client_secret, "id": intent_id}

# Orders
@app.post("/api/orders")
def create_order(payload: OrderCreate, current_user: dict = Depends(get_current_user)):
    doc = {
        "user_id": str(current_user["_id"]),
        "items": [i.model_dump() for i in payload.items],
        "shipping_address": payload.shipping_address.model_dump(),
        "total_amount": payload.total_amount,
        "currency": payload.currency,
        "payment_intent_id": payload.payment_intent_id,
        "payment_status": "pending",
        "status": "created",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["order"].insert_one(doc)
    db["cart"].delete_one({"user_id": str(current_user["_id"])})
    return {"id": str(res.inserted_id)}

@app.get("/api/orders")
def my_orders(current_user: dict = Depends(get_current_user)):
    orders = []
    for o in db["order"].find({"user_id": str(current_user["_id"]) }).sort([("created_at", -1)]):
        o["id"] = str(o.pop("_id"))
        orders.append(o)
    return {"orders": orders}

@app.get("/api/orders/{order_id}")
def order_detail(order_id: str, current_user: dict = Depends(get_current_user)):
    o = db["order"].find_one({"_id": ObjectId(order_id)})
    if not o or (o.get("user_id") != str(current_user["_id"]) and not current_user.get("is_admin")):
        raise HTTPException(status_code=404, detail="Order not found")
    o["id"] = str(o.pop("_id"))
    return o

@app.get("/api/admin/orders")
def admin_orders(current_user: dict = Depends(get_current_user)):
    require_admin(current_user)
    result = []
    for o in db["order"].find().sort([("created_at", -1)]):
        o["id"] = str(o.pop("_id"))
        result.append(o)
    return {"orders": result}

# Images (not enabled without Cloudinary deps)
@app.post("/api/images/upload")
def upload_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    require_admin(current_user)
    raise HTTPException(status_code=500, detail="Image upload not configured in this environment")

# Health + test
@app.get("/")
def root():
    return {"message": "E-commerce API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "collections": []
    }
    try:
        if db is not None:
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
    except Exception as e:
        response["error"] = str(e)[:120]
    return response

@app.get('/seed/init')
def seed():
    existing_admin = db['user'].find_one({ 'email': 'admin@example.com' })
    if not existing_admin:
        db['user'].insert_one({
            'name': 'Admin',
            'email': 'admin@example.com',
            'password_hash': hash_password('Admin@123'),
            'is_admin': True,
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc),
        })
    categories = [
        { 'name': 'Electronics', 'slug': 'electronics', 'description': 'Devices and gadgets' },
        { 'name': 'Fashion', 'slug': 'fashion', 'description': 'Clothing and accessories' },
        { 'name': 'Home', 'slug': 'home', 'description': 'Home and kitchen' },
    ]
    for c in categories:
        if not db['category'].find_one({ 'slug': c['slug'] }):
            db['category'].insert_one({ **c, 'created_at': datetime.now(timezone.utc), 'updated_at': datetime.now(timezone.utc) })
    sample_products = [
        { 'title': 'Wireless Headphones', 'description': 'Noise-cancelling over-ear', 'price': 129.99, 'category_name': 'Electronics', 'images': ['https://images.unsplash.com/photo-1518443952240-67bd5bbb4920?q=80&w=1200&auto=format&fit=crop'], 'brand': 'Acme', 'count_in_stock': 50 },
        { 'title': 'Smartwatch', 'description': 'Fitness tracking with GPS', 'price': 199.50, 'category_name': 'Electronics', 'images': ['https://images.unsplash.com/photo-1518384401463-d3876163c195?q=80&w=1200&auto=format&fit=crop'], 'brand': 'Acme', 'count_in_stock': 30 },
        { 'title': 'Cotton T-Shirt', 'description': '100% cotton, unisex', 'price': 19.99, 'category_name': 'Fashion', 'images': ['https://images.unsplash.com/photo-1520975928316-56c65f62fb9f?q=80&w=1200&auto=format&fit=crop'], 'brand': 'Basic', 'count_in_stock': 200 },
        { 'title': 'Sneakers', 'description': 'Comfort walking shoes', 'price': 69.00, 'category_name': 'Fashion', 'images': ['https://images.unsplash.com/photo-1546421845-6471bdcf3edf?q=80&w=1200&auto=format&fit=crop'], 'brand': 'Runner', 'count_in_stock': 80 },
        { 'title': 'Blender', 'description': 'Powerful kitchen blender', 'price': 89.90, 'category_name': 'Home', 'images': ['https://images.unsplash.com/photo-1603241108335-431969444f65?q=80&w=1200&auto=format&fit=crop'], 'brand': 'HomePro', 'count_in_stock': 40 },
    ]
    for p in sample_products:
        if not db['product'].find_one({ 'title': p['title'] }):
            db['product'].insert_one({ **p, 'created_at': datetime.now(timezone.utc), 'updated_at': datetime.now(timezone.utc), 'rating': 0, 'num_reviews': 0 })
    return { 'ok': True }
