from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

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

class PDF(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user_table.id'), nullable=False)
    viewed = db.Column(db.Boolean, default=False)

# Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    user = db.session.execute(db.select(User).filter_by(username=data['username'])).scalar_one_or_none()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token, 'role': user.role})

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    """ Register new users (for testing purposes) """
    data = request.json
    if not data or 'username' not in data or 'password' not in data or 'role' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    existing_user = db.session.execute(db.select(User).filter_by(username=data['username'])).scalar_one_or_none()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password_hash=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/upload_pdf', methods=['POST'])
@jwt_required()
def upload_pdf():
    user = get_jwt_identity()
    if user['role'] != 'manager':
        return jsonify({'error': 'Unauthorized'}), 403

    print("DEBUG: Received upload request")  # Debugging log

    if 'file' not in request.files:
        print("ERROR: No file uploaded")
        return jsonify({'error': 'No file uploaded'}), 422

    if 'assigned_to' not in request.form:
        print("ERROR: Missing assigned_to field")
        return jsonify({'error': 'Missing assigned_to field'}), 422

    file = request.files['file']
    assigned_to = request.form['assigned_to']

    # Convert assigned_to to integer (Fix for 422 error)
    try:
        assigned_to = int(assigned_to)
    except ValueError:
        print("ERROR: assigned_to must be an integer")
        return jsonify({'error': 'Invalid assigned_to value'}), 422

    print(f"DEBUG: File received - {file.filename}")
    print(f"DEBUG: Assigned to - {assigned_to}")

    assigned_user = db.session.get(User, assigned_to)
    if not assigned_user:
        print("ERROR: Assigned user does not exist")
        return jsonify({'error': 'Assigned user does not exist'}), 404

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Ensure filename is unique
    counter = 1
    base, ext = os.path.splitext(filename)
    while os.path.exists(filepath):
        filename = f"{base}_{counter}{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        counter += 1

    file.save(filepath)

    new_pdf = PDF(filename=filename, filepath=filepath, assigned_to=assigned_to)
    db.session.add(new_pdf)
    db.session.commit()

    print(f"DEBUG: PDF saved at {filepath}")

    return jsonify({'message': 'File uploaded successfully'})



@app.route('/get_pdfs', methods=['GET'])
@jwt_required()
def get_pdfs():
    user = get_jwt_identity()
    if user['role'] != 'agent':
        return jsonify({'error': 'Unauthorized'}), 403

    pdfs = PDF.query.filter_by(assigned_to=user['id']).all()
    return jsonify([{'id': p.id, 'filename': p.filename, 'url': f"/serve_pdf/{p.filename}", 'viewed': p.viewed} for p in pdfs])

@app.route('/serve_pdf/<filename>', methods=['GET'])
@jwt_required()
def serve_pdf(filename):
    """ Serve uploaded PDFs securely """
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(pdf_path):
        print(f"ERROR: PDF {filename} not found")
        return jsonify({'error': 'File not found'}), 404
    print(f"DEBUG: Serving PDF {filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/mark_as_viewed/<int:pdf_id>', methods=['POST'])
@jwt_required()
def mark_as_viewed(pdf_id):
    user = get_jwt_identity()
    pdf = PDF.query.filter_by(id=pdf_id, assigned_to=user['id']).first()

    if pdf:
        pdf.viewed = True
        db.session.commit()
        print(f"DEBUG: PDF {pdf_id} marked as viewed")
        return jsonify({'message': 'Marked as viewed'})

    print(f"ERROR: PDF {pdf_id} not found")
    return jsonify({'error': 'PDF not found'}), 404

@app.route('/get_agents', methods=['GET'])
@jwt_required()
def get_agents():
    agents = User.query.filter_by(role='agent').all()
    return jsonify([{"id": agent.id, "username": agent.username} for agent in agents])


# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures tables are created in Render
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 10000)), debug=True)
