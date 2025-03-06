from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import json
import pandas as pd
from datetime import date

app = Flask(__name__)
CORS(app)  # Enable CORS

# Load environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL  # PostgreSQL on Render
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your_fallback_secret_key")
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), "uploads")

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(db.Model):
    __tablename__ = "user_table"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "manager" or "agent"
    phone_number = db.Column(db.String(20), unique=True, nullable=False)  # Added phone number field

class PDF(db.Model):
    __tablename__ = "pdfs"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user_table.id'), nullable=False)
    viewed = db.Column(db.Boolean, default=False)

# New Commission Model
class Commission(db.Model):
    __tablename__ = "commissions"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('user_table.id'), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, default=date.today)

db.create_all()

@app.route('/upload_commissions', methods=['POST'])
@jwt_required()
def upload_commissions():
    """ Uploads a CSV/XLSX file and assigns commissions to agents based on phone number. """
    user_identity = json.loads(get_jwt_identity())
    if user_identity['role'] != 'manager':
        return jsonify({'error': 'Unauthorized'}), 403

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)

    if not filename.endswith('.csv') and not filename.endswith('.xlsx'):
        return jsonify({"error": "Invalid file format. Only CSV and Excel allowed"}), 400

    # Save file temporarily
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        if filename.endswith('.csv'):
            df = pd.read_csv(file_path)
        else:
            df = pd.read_excel(file_path)

        # Check required columns
        required_columns = {"First Name", "Last Name", "Phone number", "Commission"}
        if not required_columns.issubset(df.columns):
            return jsonify({"error": "Invalid file format. Missing required columns."}), 400

        # Process each row
        for _, row in df.iterrows():
            phone_number = str(row["Phone number"]).strip()
            amount = float(row["Commission"])

            agent = User.query.filter_by(phone_number=phone_number).first()
            if agent:
                new_commission = Commission(
                    agent_id=agent.id,
                    phone_number=phone_number,
                    amount=amount
                )
                db.session.add(new_commission)

        db.session.commit()
        return jsonify({"message": "Commissions uploaded successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_commissions', methods=['GET'])
@jwt_required()
def get_commissions():
    """ Fetches commissions assigned to the logged-in agent. """
    user_identity = json.loads(get_jwt_identity())
    agent = User.query.filter_by(id=user_identity['id']).first()

    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    commissions = Commission.query.filter_by(phone_number=agent.phone_number).all()
    return jsonify([
        {
            "date": c.date.strftime('%Y-%m-%d'),
            "amount": c.amount
        } for c in commissions
    ])

# Existing endpoints remain unchanged
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        token = create_access_token(identity=json.dumps({'id': user.id, 'role': user.role}))
        return jsonify({'token': token, 'role': user.role})

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    """ Register new users (for testing purposes) """
    data = request.json
    if not data or 'username' not in data or 'password' not in data or 'role' not in data or 'phone_number' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'],
        password_hash=hashed_password,
        role=data['role'],
        phone_number=data['phone_number']
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/get_agents', methods=['GET'])
@jwt_required()
def get_agents():
    user_identity = json.loads(get_jwt_identity())

    if user_identity["role"] != "manager":
        return jsonify({"error": "Unauthorized"}), 403

    agents = User.query.filter_by(role='agent').all()
    return jsonify([{"id": agent.id, "username": agent.username, "phone_number": agent.phone_number} for agent in agents])

@app.route('/serve_pdf/<filename>', methods=['GET'])
@jwt_required()
def serve_pdf(filename):
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(pdf_path):
        return jsonify({'error': 'File not found'}), 404

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/mark_as_viewed/<int:pdf_id>', methods=['POST'])
@jwt_required()
def mark_as_viewed(pdf_id):
    user_identity = json.loads(get_jwt_identity())
    pdf = PDF.query.filter_by(id=pdf_id, assigned_to=user_identity['id']).first()

    if pdf:
        pdf.viewed = True
        db.session.commit()
        return jsonify({'message': 'Marked as viewed'})

    return jsonify({'error': 'PDF not found'}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 10000)), debug=True)
