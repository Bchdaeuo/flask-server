from flask import Flask, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt, base64, os, psutil

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")

# MongoDB Atlas 연결
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client.mydatabase
users_collection = db.users


@app.route("/")
def home():
    return "로그인 및 회원가입 인증 서버가 원활히 작동하고 있습니다."


# 회원가입
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    nickname = data.get("nickname")

    if not username or not password:
        return jsonify({"success": False, "message": "아이디와 비밀번호를 모두 입력하세요."}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"success": False, "message": "이미 존재하는 아이디입니다."}), 409

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    hashed_pw_str = base64.b64encode(hashed_pw).decode("utf-8")

    users_collection.insert_one({
        "username": username,
        "password": hashed_pw_str,
        "nickname": nickname if nickname else username
    })

    return jsonify({"success": True, "message": "회원가입 성공!"})


# 로그인
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "존재하지 않는 사용자입니다."}), 404

    stored_hash_str = user["password"]
    stored_hash = base64.b64decode(stored_hash_str.encode("utf-8"))

    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        nickname = user.get("nickname", username)

        # ✅ 세션에 사용자 정보 저장
        session["user_id"] = str(user["_id"])
        session["username"] = username
        session["nickname"] = nickname

        return jsonify({
            "success": True,
            "message": "로그인 성공!",
            "nickname": nickname
        }), 200
    else:
        return jsonify({"success": False, "message": "비밀번호가 일치하지 않습니다."}), 401


# 로그인 상태 확인
@app.route("/check_session", methods=["GET"])
def check_session():
    if "user_id" in session:
        return jsonify({
            "logged_in": True,
            "username": session.get("username"),
            "nickname": session.get("nickname")
        })
    else:
        return jsonify({"logged_in": False})


# 로그아웃
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "로그아웃 완료"})


# 회원 탈퇴
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
    stored_hash = base64.b64decode(stored_hash_str.encode("utf-8"))

    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return jsonify({"success": False, "message": "비밀번호가 일치하지 않습니다."}), 401

    users_collection.delete_one({"username": username})

    # 세션 비우기
    session.clear()

    return jsonify({"success": True, "message": "회원 탈퇴 완료."})

# 서버 상태 확인
@app.route("/status", methods=["GET"])
def status():
    server_status = {
        "server": "online",
        "message": "로그인 및 회원가입 서버가 정상 작동 중입니다."
    }

    try:
        client.admin.command("ping")
        server_status["database"] = "online"
    except Exception as e:
        server_status["database"] = "offline"
        server_status["db_error"] = str(e)

    return jsonify(server_status)

# 서버 사용량 확인
@app.route("/metrics")
def metrics():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()

    return jsonify({
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "sent_MB": round(net.bytes_sent / 1024 / 1024, 2),
        "recv_MB": round(net.bytes_recv / 1024 / 1024, 2)
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
