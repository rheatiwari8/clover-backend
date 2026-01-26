from fastapi import Header, HTTPException
from pydantic import BaseModel
from datetime import datetime
from pymongo import MongoClient
from fastapi import FastAPI
from dotenv import load_dotenv
from fastapi import Depends
import os

load_dotenv()
app = FastAPI()

MONGO_URI = os.getenv("MONGO_URI")
API_KEY = os.getenv("API_KEY")

client = MongoClient(MONGO_URI)
db = client["cloverdb"]
orders_collection = db["orders"]

class Order(BaseModel):
    cloverOrderId: str
    amount: float
    createdAt: datetime

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

@app.get("/")
def root():
    return {"message": "Backend is running"}

@app.post("/orders")
def create_order(order: Order, _=Depends(verify_api_key)):
    orders_collection.insert_one(order.dict())
    return {"success": True}


@app.get("/orders/{order_id}")
def get_order(order_id: str, _=Depends(verify_api_key)):
    order = orders_collection.find_one(
        {"cloverOrderId": order_id},
        {"_id": 0}
    )

    if not order:
        return {"error": "Order not found"}

    return order
