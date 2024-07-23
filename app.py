# app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/yourdbname"
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
mongo = PyMongo(app)
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(username):
    user = mongo.db.users.find_one({"username": username})
    if not user:
        return None
    return User(username=user['username'])

@app.route('/')
@login_required
def index():
    return redirect(url_for('main_app'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_app'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = mongo.db.users.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            user_obj = User(username=user['username'])
            login_user(user_obj)
            return redirect(url_for('main_app'))
        return 'Invalid username or password'
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main_app'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
            return 'Username already exists'
        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({'username': username, 'password': hashed_password})
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/main_app')
@login_required
def main_app():
    return render_template('main_app.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/items', methods=['GET'])
@login_required
def get_items():
    items = list(mongo.db.items.find({"username": current_user.username}))
    return jsonify([{**item, '_id': str(item['_id'])} for item in items])

@app.route('/api/items', methods=['POST'])
@login_required
def add_item():
    new_item = request.json
    new_item['username'] = current_user.username
    result = mongo.db.items.insert_one(new_item)
    return jsonify({'_id': str(result.inserted_id)}), 201

@app.route('/api/items/<id>', methods=['PUT'])
@login_required
def update_item(id):
    mongo.db.items.update_one({'_id': ObjectId(id), 'username': current_user.username}, {'$set': request.json})
    return jsonify({'message': 'Item updated successfully'}), 200

@app.route('/api/items/<id>', methods=['DELETE'])
@login_required
def delete_item(id):
    mongo.db.items.delete_one({'_id': ObjectId(id), 'username': current_user.username})
    return jsonify({'message': 'Item deleted successfully'}), 200

@app.route('/api/check_auth')
def check_auth():
    return jsonify({'authenticated': current_user.is_authenticated}), 200

if __name__ == '__main__':
    app.run(debug=True)