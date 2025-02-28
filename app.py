from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
CORS(app)  # Enable CORS

# Load environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")  # PostgreSQL on Render
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your_fallback_secret_key")  # Secret key for JWT
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Hashed password storage
    role = db.Column(db.String(10), nullable=False)  # "manager" or "agent"

class PDF(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed = db.Column(db.Boolean, default=False)

# Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password_hash, data['password']):  
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token, 'role': user.role})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    """ Register new users (for testing purposes) """
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    
    new_user = User(username=data['username'], password_hash=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'})

@app.route('/upload_pdf', methods=['POST'])
@jwt_required()
def upload_pdf():
    user = get_jwt_identity()
    if user['role'] != 'manager':
        return jsonify({'error': 'Unauthorized'}), 403

    file = request.files['file']
    assigned_to = request.form['assigned_to']
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        new_pdf = PDF(filename=filename, filepath=filepath, assigned_to=assigned_to)
        db.session.add(new_pdf)
        db.session.commit()
        
        return jsonify({'message': 'File uploaded successfully'})

@app.route('/get_pdfs', methods=['GET'])
@jwt_required()
def get_pdfs():
    user = get_jwt_identity()
    if user['role'] != 'agent':
        return jsonify({'error': 'Unauthorized'}), 403

    pdfs = PDF.query.filter_by(assigned_to=user['id']).all()
    return jsonify([{'id': p.id, 'filename': p.filename, 'url': p.filepath, 'viewed': p.viewed} for p in pdfs])

@app.route('/mark_as_viewed/<int:pdf_id>', methods=['POST'])
@jwt_required()
def mark_as_viewed(pdf_id):
    user = get_jwt_identity()
    pdf = PDF.query.filter_by(id=pdf_id, assigned_to=user['id']).first()
    
    if pdf:
        pdf.viewed = True
        db.session.commit()
        return jsonify({'message': 'Marked as viewed'})
    
    return jsonify({'error': 'PDF not found'}), 404

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures tables are created in Render
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 10000)), debug=True)
