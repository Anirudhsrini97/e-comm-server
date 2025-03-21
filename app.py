from flask import Flask, request, jsonify, make_response
import boto3
import json
import psycopg2
import re
import base64
import jwt
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# Initialize AWS Clients
kms_client = boto3.client("kms", region_name="us-east-1")
secret_client = boto3.client('secretsmanager', region_name="us-east-1")

def get_secrets():
    secret_value = secret_client.get_secret_value(SecretId="my-app-secrets")
    return json.loads(secret_value['SecretString'])

secrets = get_secrets()

SECRET_KEY = secrets["jwt_secret_key"]
KMS_KEY_ID = secrets["kms_key_id"]

DATABASE_CONFIG = {
    'dbname': secrets["db_name"],
    'user': secrets["db_user"],
    'password': secrets["db_password"],
    'host': secrets["db_host"],
    'port': secrets["db_port"]
}

app = Flask(__name__)

def generate_jwt_token(user_id, email, role, username = None):
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token valid for 1 hour
    payload = {
        "id": user_id,
        "email": email,
        "role": role,
        "exp": expiry_time
    }
    if username is not None:
        payload["username"] = username
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token, expiry_time

def get_db_connection():
    return psycopg2.connect(**DATABASE_CONFIG)

def is_valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def is_valid_password(password):
    return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password)

# 🔑 **Decrypt Password Using AWS KMS**
def decrypt_password(encrypted_password):
    decoded_data = base64.b64decode(encrypted_password)

    response = kms_client.decrypt(
        CiphertextBlob=decoded_data,
        EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )

    return response['Plaintext'].decode('utf-8')


# Middleware to validate JWT token
def validate_user_token(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        token = None

        # Check for Authorization header (Bearer Token)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        # If no token in Authorization header, check the cookie
        if not token:
            token = request.cookies.get("jwt_token")

        if not token:
            return jsonify({'error': 'Unauthorized access, token required'}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = payload  # Attach user details to the request for use in the endpoint
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired, please log in again'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return func(*args, **kwargs)

    return decorated_function


@app.route('/api/v1/users', methods=['POST'])
def create_user():
    data = request.get_json()
    email = data.get('email')
    encrypted_password = data.get('password')
    username = data.get('username')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    if not (email and encrypted_password and username and first_name and last_name):
        return jsonify({'error': 'All fields are required'}), 400

    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    decrypted_password = decrypt_password(encrypted_password)

    if not is_valid_password(decrypted_password):
        return jsonify({'error': 'Password must be at least 8 characters, include one uppercase, one lowercase, one number, and one special character'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email = %s OR username = %s", (email, username))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'error': 'Username or email already exists'}), 400

    hashed_password = generate_password_hash(decrypted_password)
    cur.execute("INSERT INTO users (email, password, username, first_name, last_name) VALUES (%s, %s, %s, %s, %s)",
                (email, hashed_password, username, first_name, last_name))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/v1/seller/login', methods=['POST'])
def seller_login():
    data = request.get_json()
    email = data.get('email')
    encrypted_password = data.get('password')

    if not email or not encrypted_password:
        return jsonify({'error': 'Email/Username and Password are required'}), 400

    decrypted_password = decrypt_password(encrypted_password)

    conn = get_db_connection()
    cur = conn.cursor()

    # Search for user by email or username
    cur.execute("SELECT id, email, password FROM seller WHERE email = %s",
                email)
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    user_id, email, stored_hashed_password = user

    if not check_password_hash(stored_hashed_password, decrypted_password):
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate JWT token
    token, expiry_time = generate_jwt_token(user_id, email, "seller")

    cur.close()
    conn.close()

    # Set JWT token as a cookie
    response = make_response(jsonify({'message': 'Login successful'}))
    response.set_cookie('seller_jwt_token', token, httponly=True, expires=expiry_time)

    return response

@app.route('/api/v1/user/login', methods=['POST'])
def user_login():
    data = request.get_json()
    email_or_username = data.get('email') or data.get('username')
    encrypted_password = data.get('password')

    if not email_or_username or not encrypted_password:
        return jsonify({'error': 'Email/Username and Password are required'}), 400

    decrypted_password = decrypt_password(encrypted_password)

    conn = get_db_connection()
    cur = conn.cursor()

    # Search for user by email or username
    cur.execute("SELECT id, username, email, password FROM users WHERE email = %s OR username = %s",
                (email_or_username, email_or_username))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    user_id, username, email, stored_hashed_password = user

    if not check_password_hash(stored_hashed_password, decrypted_password):
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate JWT token
    token, expiry_time = generate_jwt_token(user_id, email, "user", username)

    cur.close()
    conn.close()

    # Set JWT token as a cookie
    response = make_response(jsonify({'message': 'Login successful'}))
    response.set_cookie('jwt_token', token, httponly=True, expires=expiry_time)

    return response

@app.route('/api/v1/user/details', methods=['GET'])
@validate_user_token
def get_user_details():
    user_id = request.user.get("id")  # Extract user ID from token

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch user details from the database
    cur.execute("SELECT id, username, email, first_name, last_name FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    user_details = {
        "id": user[0],
        "username": user[1],
        "email": user[2],
        "first_name": user[3],
        "last_name": user[4]
    }

    return jsonify(user_details), 200


@app.route('/api/v1/seller', methods=['POST'])
def create_seller():
    data = request.get_json()
    email = data.get('email')
    encrypted_password = data.get('password')

    if not (email and encrypted_password):
        return jsonify({'error': 'All fields are required'}), 400

    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    decrypted_password = decrypt_password(encrypted_password)

    if not is_valid_password(decrypted_password):
        return jsonify({'error': 'Password must be at least 8 characters, include one uppercase, one lowercase, one number, and one special character'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM seller WHERE email = %s", (email,))  #%s acts as a placeholder
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'error': 'email already exists'}), 400

    hashed_password = generate_password_hash(decrypted_password)
    cur.execute("INSERT INTO seller (email, password) VALUES (%s, %s)",
                (email, hashed_password))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'message': 'Seller created successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True, port = 8080)
