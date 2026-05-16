from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # Лимит 100МБ
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

users = {
    "maloshko": {
        "password": "maksjmka2607", "role": "admin", "sub": True,
        "bio": "Основатель Nova Sounds", "avatar": "", "banner": "",
        "pinned_tracks": [] # Список ID закрепленных треков
    }
}
tracks = []

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    return jsonify({"status": "success", "data": tracks})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    u = data.get('username')
    if u in users: return jsonify({"status": "error", "message": "Ник занят"}), 400
    users[u] = {"password": data.get('password'), "role": "user", "sub": False, "bio": "", "avatar": "", "banner": "", "pinned_tracks": []}
    return jsonify({"status": "success"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    u, p = data.get('username'), data.get('password')
    user = users.get(u)
    if user and user['password'] == p:
        return jsonify({"status": "success", "user": {**user, "username": u}})
    return jsonify({"status": "error", "message": "Ошибка входа"}), 401

@app.route('/api/profile/pin', methods=['POST'])
def pin_track():
    data = request.json
    u, t_id = data.get('username'), data.get('track_id')
    if u in users:
        if t_id not in users[u]['pinned_tracks']:
            users[u]['pinned_tracks'].append(t_id)
            return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route('/api/users/search', methods=['POST'])
def search_users():
    query = request.json.get('query', '').lower()
    found = [{"username": k, "avatar": v['avatar'], "bio": v['bio']} for k, v in users.items() if query in k.lower()]
    return jsonify({"status": "success", "users": found})

@app.route('/api/admin/add_track', methods=['POST'])
def add_track():
    data = request.json
    tracks.append({"id": len(tracks)+1, "title": data.get('title'), "artist": data.get('artist'), "url": data.get('url')})
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
