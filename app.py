from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from jwt import encode, decode, ExpiredSignatureError, InvalidTokenError
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Check for required environment variables and log errors if any are missing
required_env_vars = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'SECRET_KEY']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]

if missing_vars:
    raise ValueError(f"Missing environment variables: {', '.join(missing_vars)}")

app = Flask(__name__)

# Use environment variables for the database connection
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')

# Print out the values for debugging
print(f"DB_USER: {db_user}")
print(f"DB_PASSWORD: {db_password}")
print(f"DB_HOST: {db_host}")
print(f"DB_PORT: {db_port}")
print(f"DB_NAME: {db_name}")

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
CORS(app)  # Enable CORS for frontend-backend communication

# Secret key for JWT
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Todo model
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Route for the home page
@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the To-Do List API!'})

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        # Create JWT token
        token = encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token, 'message': 'logged in successfully'})

    return jsonify({'message': 'Invalid credentials'}), 401

# Helper function to verify token
def verify_token():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        data = decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])

        if not user:
            return jsonify({'message': 'User not found'}), 404

        return user
    except (ExpiredSignatureError, InvalidTokenError):
        return jsonify({'message': 'Invalid or expired token'}), 401

# Protected route to get todos
@app.route('/todos', methods=['GET'])
def get_todos():
    user = verify_token()
    if isinstance(user, tuple):  # In case of error
        return user

    todos = Todo.query.filter_by(user_id=user.id).all()
    return jsonify({'todos': [{'id': todo.id, 'text': todo.text} for todo in todos]})

# Protected route to add a todo
@app.route('/todos', methods=['POST'])
def add_todo():
    user = verify_token()
    if isinstance(user, tuple):  # In case of error
        return user

    todo_data = request.get_json()
    if not todo_data or not todo_data.get('text'):
        return jsonify({'message': 'Todo text is required'}), 400

    new_todo = Todo(text=todo_data['text'], user_id=user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'Todo added successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True)