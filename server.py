from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import os

app = Flask(__name__)

# MongoDB Atlas 연결 문자열 (환경변수 MONGO_URI로 설정 권장)
MONGO_URI = "mongodb+srv://admin:admin@cluster0.3mojim2.mongodb.net/mydatabase?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI)
db = client.mydatabase
users_collection = db.users

@app.route("/")
def home():
    return "Hello from Flask with MongoDB!"

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "아이디와 비밀번호를 모두 입력하세요."}), 400

    # 이미 존재하는 아이디인지 확인
    if users_collection.find_one({"username": username}):
        return jsonify({"success": False, "message": "이미 존재하는 아이디입니다."}), 409

    # 비밀번호 해시 처리
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # DB에 저장
    users_collection.insert_one({
        "username": username,
        "password": hashed_pw
    })

    return jsonify({"success": True, "message": "회원가입 성공!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "아이디와 비밀번호를 모두 입력하세요."}), 400

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "등록된 아이디가 없습니다."}), 404

    # 비밀번호 검증
    if bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"success": True, "message": "로그인 성공!"})
    else:
        return jsonify({"success": False, "message": "비밀번호가 올바르지 않습니다."}), 401

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)