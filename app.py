from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Разрешаем запросы с любого домена
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# Наша База данных. Твой аккаунт уже тут с правами админа!
users = {
    "maloshko": {
        "password": "maksjmka2607", 
        "friends": [], 
        "balance": 0, 
        "sub": True, 
        "role": "admin"
    }
}

tracks = [
    {"id": 1, "title": "Night City", "artist": "CyberM", "url": "audio/1.mp3"},
    {"id": 2, "title": "Chill Vibes", "artist": "LoFi Guy", "url": "audio/2.mp3"}
]

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    return jsonify({"status": "success", "data": tracks})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username in users:
        return jsonify({"status": "error", "message": "Пользователь уже существует"}), 400
        
    users[username] = {"password": password, "friends": [], "balance": 0, "sub": False, "role": "user"}
    return jsonify({"status": "success", "message": "Регистрация успешна!"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = users.get(username)
    if user and user['password'] == password:
        user_data = {"username": username, "sub": user['sub'], "role": user['role'], "balance": user['balance']}
        return jsonify({"status": "success", "user": user_data})
    return jsonify({"status": "error", "message": "Неверный логин или пароль"}), 401

# --- АДМИН ПАНЕЛЬ ---
@app.route('/api/admin/users', methods=['POST'])
def get_all_users():
    data = request.json
    req_user = data.get('admin_username')
    
    if users.get(req_user, {}).get('role') == 'admin':
        safe_users = {k: {"role": v["role"], "sub": v["sub"]} for k, v in users.items()}
        return jsonify({"status": "success", "users": safe_users})
    return jsonify({"status": "error", "message": "Нет прав"}), 403

@app.route('/api/admin/action', methods=['POST'])
def admin_action():
    data = request.json
    req_user = data.get('admin_username')
    target_user = data.get('target_user')
    action = data.get('action') 

    if users.get(req_user, {}).get('role') != 'admin':
        return jsonify({"status": "error", "message": "Нет прав"}), 403

    if action == 'give_sub':
        users[target_user]['sub'] = True
    elif action == 'give_admin':
        users[target_user]['role'] = 'admin'

    return jsonify({"status": "success", "message": f"Действие {action} для {target_user} выполнено!"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
