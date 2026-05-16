from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Разрешаем запросы с твоего домена
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# База данных пользователей (в памяти)
users = {
    "maloshko": {
        "password": "maksjmka2607", 
        "role": "admin", "sub": True, "balance": 0,
        "bio": "Основатель Nova Sounds",
        "avatar": "https://i.pinimg.com/736x/a8/12/1a/a8121a93f55099f6655c4d0a1b8c005f.jpg",
        "banner": "https://images.wallpapersden.com/image/download/gradient-blue-purple-abstract_bGltaGaUmZqaraWkpJRmbmdlrWZlbWU.jpg"
    }
}

# Список песен
tracks = [
    {"id": 1, "title": "Night City", "artist": "CyberM", "url": "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3"},
    {"id": 2, "title": "Nova Energy", "artist": "Nova Music", "url": "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-2.mp3"}
]

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    return jsonify({"status": "success", "data": tracks})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    if username in users:
        return jsonify({"status": "error", "message": "Ник занят"}), 400
    users[username] = {
        "password": data.get('password'), "role": "user", "sub": False, 
        "balance": 0, "bio": "", "avatar": "", "banner": ""
    }
    return jsonify({"status": "success", "message": "Успешная регистрация!"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = users.get(data.get('username'))
    if user and user['password'] == data.get('password'):
        return jsonify({"status": "success", "user": {**user, "username": data.get('username')}})
    return jsonify({"status": "error", "message": "Неверный пароль"}), 401

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    data = request.json
    username = data.get('username')
    if username in users:
        users[username].update({"bio": data.get('bio'), "avatar": data.get('avatar'), "banner": data.get('banner')})
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@app.route('/api/admin/users', methods=['POST'])
def get_admin_users():
    if users.get(request.json.get('admin_username'), {}).get('role') == 'admin':
        return jsonify({"status": "success", "users": {k: {"role": v["role"], "sub": v["sub"]} for k, v in users.items()}})
    return jsonify({"status": "error"}), 403

@app.route('/api/admin/add_track', methods=['POST'])
def add_track():
    data = request.json
    if users.get(data.get('admin_username'), {}).get('role') == 'admin':
        tracks.append({"id": len(tracks)+1, "title": data.get('title'), "artist": data.get('artist'), "url": data.get('url')})
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 403

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
