"""
Database Schemas for E-commerce

Each Pydantic model represents a MongoDB collection.
Collection name is the lowercase of the class name.
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

class Address(BaseModel):
    full_name: str
    line1: str
    line2: Optional[str] = None
    city: str
    state: str
    postal_code: str
    country: str
    phone: Optional[str] = None

class Review(BaseModel):
    user_id: str
    user_name: str
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None
    created_at: Optional[datetime] = None

class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: Optional[str] = None
    is_admin: bool = False
    addresses: List[Address] = []

class Category(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None

class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    category_id: Optional[str] = None
    category_name: Optional[str] = None
    images: List[str] = []
    brand: Optional[str] = None
    count_in_stock: int = 0
    rating: float = 0
    num_reviews: int = 0

class CartItem(BaseModel):
    product_id: str
    title: str
    image: Optional[str] = None
    price: float
    qty: int = Field(..., ge=1)

class OrderItem(BaseModel):
    product_id: str
    title: str
    image: Optional[str] = None
    price: float
    qty: int

class Order(BaseModel):
    user_id: str
    items: List[OrderItem]
    shipping_address: Address
    payment_intent_id: Optional[str] = None
    payment_status: str = "pending"
    total_amount: float
    currency: str = "usd"
    status: str = "created"  # created, paid, shipped, delivered, cancelled

