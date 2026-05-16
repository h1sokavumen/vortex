from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

users = {
    "maloshko": {
        "password": "maksjmka2607", "role": "admin", "sub": True, "balance": 0,
        "bio": "Основатель Nova Sounds",
        "avatar": "https://i.pinimg.com/736x/a8/12/1a/a8121a93f55099f6655c4d0a1b8c005f.jpg",
        "banner": "https://images.wallpapersden.com/image/download/gradient-blue-purple-abstract_bGltaGaUmZqaraWkpJRmbmdlrWZlbWU.jpg"
    }
}

tracks = [{"id": 1, "title": "Night City", "artist": "CyberM", "url": "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3"}]

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    return jsonify({"status": "success", "data": tracks})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = users.get(data.get('username'))
    if user and user['password'] == data.get('password'):
        return jsonify({"status": "success", "user": {**user, "username": data.get('username')}})
    return jsonify({"status": "error", "message": "Ошибка данных"}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    u = data.get('username')
    if u in users: return jsonify({"status": "error", "message": "Ник занят"}), 400
    users[u] = {"password": data.get('password'), "role": "user", "sub": False, "balance": 0, "bio": "", "avatar": "", "banner": ""}
    return jsonify({"status": "success"})

# ПОИСК ПОЛЬЗОВАТЕЛЯ
@app.route('/api/user/<username>', methods=['GET'])
def get_user(username):
    user = users.get(username)
    if user:
        return jsonify({"status": "success", "user": {
            "username": username, "bio": user['bio'], "avatar": user['avatar'], 
            "banner": user['banner'], "sub": user['sub'], "role": user['role']
        }})
    return jsonify({"status": "error", "message": "Пользователь не найден"}), 404

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    data = request.json
    u = data.get('username')
    if u in users:
        users[u].update({"bio": data.get('bio'), "avatar": data.get('avatar'), "banner": data.get('banner')})
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@app.route('/api/admin/add_track', methods=['POST'])
def add_track():
    data = request.json
    tracks.append({"id": len(tracks)+1, "title": data.get('title'), "artist": data.get('artist'), "url": data.get('url')})
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
