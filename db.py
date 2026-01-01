# db.py
from pymongo import MongoClient
import os

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["system_klasifikasi"]

def get_collection(name):
    return db[name]
