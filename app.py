from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Снимаем ограничение на размер запроса (ставим 100 МБ)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

users = {
    "maloshko": {
        "password": "maksjmka2607", "role": "admin", "sub": True, "balance": 0,
        "bio": "Основатель Nova Sounds", "avatar": "", "banner": "", "pinned_tracks": []
    }
}
tracks = []

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    return jsonify({"status": "success", "data": tracks})

# ПОИСК ДРУЗЕЙ
@app.route('/api/users/search', methods=['POST'])
def search_users():
    data = request.json
    query = data.get('query', '').lower()
    # Ищем всех пользователей, чей ник содержит запрос
    found = []
    for username, info in users.items():
        if query in username.lower():
            found.append({
                "username": username,
                "avatar": info.get('avatar', ''),
                "bio": info.get('bio', '')
            })
    return jsonify({"status": "success", "users": found})

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

@app.route('/api/admin/grant', methods=['POST'])
def grant_rights():
    data = request.json
    if users.get(data.get('admin_username'), {}).get('role') == 'admin':
        target = data.get('target_user')
        if target in users:
            if data.get('right') == 'admin': users[target]['role'] = 'admin'
            if data.get('right') == 'premium': users[target]['sub'] = True
            return jsonify({"status": "success", "message": "Готово"})
    return jsonify({"status": "error"}), 403

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
