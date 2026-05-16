from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# База данных
users = {
    "maloshko": {
        "password": "maksjmka2607", "role": "admin", "sub": True, "balance": 0,
        "bio": "Основатель Nova Sounds", "avatar": "", "banner": "",
        "pinned_tracks": [] # Список ID прикрепленных треков
    }
}

tracks = []

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    return jsonify({"status": "success", "data": tracks})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = users.get(data.get('username'))
    if user and user['password'] == data.get('password'):
        return jsonify({"status": "success", "user": {**user, "username": data.get('username')}})
    return jsonify({"status": "error", "message": "Ошибка входа"}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    u = data.get('username')
    if u in users: return jsonify({"status": "error", "message": "Ник занят"}), 400
    users[u] = {"password": data.get('password'), "role": "user", "sub": False, "balance": 0, "bio": "", "avatar": "", "banner": "", "pinned_tracks": []}
    return jsonify({"status": "success"})

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    data = request.json
    u = data.get('username')
    if u in users:
        users[u].update({"bio": data.get('bio'), "avatar": data.get('avatar'), "banner": data.get('banner')})
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

# ПРИКРЕПИТЬ ТРЕК К ПРОФИЛЮ
@app.route('/api/profile/pin', methods=['POST'])
def pin_track():
    data = request.json
    u = data.get('username')
    track_id = data.get('track_id')
    if u in users and track_id not in users[u]['pinned_tracks']:
        users[u]['pinned_tracks'].append(track_id)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"})

# ВЫДАЧА ПРАВ ПО НИКУ (АДМИНКА)
@app.route('/api/admin/grant', methods=['POST'])
def grant_rights():
    data = request.json
    admin = data.get('admin_username')
    target = data.get('target_user')
    right = data.get('right') # 'admin' или 'premium'

    if users.get(admin, {}).get('role') == 'admin':
        if target in users:
            if right == 'admin': users[target]['role'] = 'admin'
            if right == 'premium': users[target]['sub'] = True
            return jsonify({"status": "success", "message": f"Права {right} выданы {target}"})
        return jsonify({"status": "error", "message": "Пользователь не найден"}), 404
    return jsonify({"status": "error", "message": "Нет доступа"}), 403

@app.route('/api/admin/add_track', methods=['POST'])
def add_track():
    data = request.json
    tracks.append({
        "id": len(tracks) + 1,
        "title": data.get('title'),
        "artist": data.get('artist'),
        "url": data.get('url')
    })
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
