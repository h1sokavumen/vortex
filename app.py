from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# ВАЖНО: Разрешаем твоему GitHub-сайту делать запросы к этому серверу
# Замени URL на свой сайт после публикации на GitHub Pages
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# Пример базы данных (пока в памяти, потом подключим PostgreSQL или SQLite)
users = {}
tracks = [
    {"id": 1, "title": "Night City", "artist": "CyberM", "url": "/audio/1.mp3"},
    {"id": 2, "title": "Chill Vibes", "artist": "LoFi Guy", "url": "/audio/2.mp3"}
]

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    # Отдаем треки для вкладки "Рекомендации"
    return jsonify({"status": "success", "data": tracks})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username in users:
        return jsonify({"status": "error", "message": "Пользователь уже существует"}), 400
        
    users[username] = {"password": password, "friends": [], "balance": 0, "sub": False}
    return jsonify({"status": "success", "message": "Регистрация успешна!"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)