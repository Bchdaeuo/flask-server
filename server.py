from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt, base64, os

app = Flask(__name__)

# MongoDB Atlas 연결 문자열
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
    nickname = data.get("nickname")  # 여기 추가

    if not username or not password:
        return jsonify({"success": False, "message": "아이디와 비밀번호를 모두 입력하세요."}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"success": False, "message": "이미 존재하는 아이디입니다."}), 409

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_pw_str = base64.b64encode(hashed_pw).decode('utf-8')

    users_collection.insert_one({
        "username": username,
        "password": hashed_pw_str,
        "nickname": nickname if nickname else username
    })

    return jsonify({"success": True, "message": "회원가입 성공!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "존재하지 않는 사용자입니다."}), 404

    stored_hash_str = user["password"]
    try:
        stored_hash = base64.b64decode(stored_hash_str.encode("utf-8"))
    except Exception:
        return jsonify({"success": False, "message": "해시 디코딩 오류"}), 500

    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        nickname = user.get("nickname", username)
        return jsonify({"success": True, "message": "로그인 성공!", "nickname": nickname}), 200
    else:
        return jsonify({"success": False, "message": "비밀번호가 일치하지 않습니다."}), 401

@app.route("/delete_account", methods=["POST"])
def delete_account():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "아이디와 비밀번호를 모두 입력하세요."}), 400

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "존재하지 않는 사용자입니다."}), 404

    stored_hash_str = user["password"]
    try:
        stored_hash = base64.b64decode(stored_hash_str.encode("utf-8"))
    except Exception:
        return jsonify({"success": False, "message": "해시 디코딩 오류"}), 500

    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return jsonify({"success": False, "message": "비밀번호가 일치하지 않습니다."}), 401

    result = users_collection.delete_one({"username": username})
    if result.deleted_count == 1:
        return jsonify({"success": True, "message": "회원 탈퇴 완료."})
    else:
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다."}), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
