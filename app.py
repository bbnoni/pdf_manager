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
from flask_migrate import Migrate  # ✅ Import Flask-Migrate

app = Flask(__name__)
CORS(app)  # Enable CORS

# Load environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your_fallback_secret_key")
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), "uploads")

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # ✅ Initialize Flask-Migrate here


jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(db.Model):
    __tablename__ = "user_table"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)  # Added
    last_name = db.Column(db.String(80), nullable=False)   # Added
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    #role = db.Column(db.String(10), nullable=False)  # "manager" or "agent"
    role = db.Column(db.String(10), nullable=False, default="agent")  # Default role is agent
    phone_number = db.Column(db.String(20), unique=True, nullable=False, index=True)  # Indexed for faster lookup
    first_login = db.Column(db.Boolean, default=True)

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
    phone_number = db.Column(db.String(20), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, default=date.today)
    commission_period = db.Column(db.String(50), nullable=False)  # 🔹 Added field

with app.app_context():
    db.create_all()

@app.route('/upload_commissions', methods=['POST'])
@jwt_required()
def upload_commissions():
    """ Uploads an Excel/CSV file and assigns commissions. If an agent does not exist, they are added. """
    user_identity = json.loads(get_jwt_identity())
    if user_identity['role'] != 'manager':
        return jsonify({'error': 'Unauthorized'}), 403

    if 'file' not in request.files or 'commission_period' not in request.form:
        return jsonify({"error": "No file uploaded or commission period missing"}), 400

    file = request.files['file']
    commission_period = request.form['commission_period'].strip()  # 🔹 Get manually entered period
    filename = secure_filename(file.filename)

    if not filename.endswith(('.csv', '.xlsx')):
        return jsonify({"error": "Invalid file format. Only CSV and Excel allowed"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        # 🔹 Check if the file is readable
        print(f"✅ Reading file: {filename}")
        df = pd.read_csv(file_path) if filename.endswith('.csv') else pd.read_excel(file_path)

        required_columns = {"First Name", "Last Name", "Phone number", "Commission"}
        if not required_columns.issubset(df.columns):
            print(f"❌ ERROR: Missing required columns. Found columns: {df.columns}")
            return jsonify({"error": "Invalid file format. Missing required columns."}), 400

        new_commissions = []
        for _, row in df.iterrows():
            first_name = row["First Name"].strip() if pd.notna(row["First Name"]) else "Unknown"
            last_name = row["Last Name"].strip() if pd.notna(row["Last Name"]) else "User"
            phone_number = str(row["Phone number"]).strip()
            amount = float(row["Commission"])

            # 🔹 Debug: Check each row
            print(f"Processing Agent: {first_name} {last_name}, Phone: {phone_number}, Commission: {amount}, Period: {commission_period}")

            agent = User.query.filter_by(phone_number=phone_number).first()

            if not agent:
                # 🔹 Log missing agent
                print(f"❌ Agent with phone {phone_number} NOT FOUND! Creating a new agent.")

                default_password = bcrypt.generate_password_hash("default123").decode('utf-8')
                username = f"{first_name.lower()}.{last_name.lower()}".replace(" ", "_")  # Prevent empty username

                new_agent = User(
                    first_name=first_name,  # ✅ Ensure first_name is never None
                    last_name=last_name,  # ✅ Ensure last_name is never None
                    username=username,  # ✅ Ensure username is unique
                    password_hash=default_password,
                    role="agent",
                    phone_number=phone_number,
                    first_login=True  # 🔹 Mark as first login (forces reset)
                )
                db.session.add(new_agent)
                db.session.commit()  # Save agent first
                agent = new_agent  # Assign new agent

            # 🔹 Log commission assignment
            print(f"✅ Assigning Commission: Agent ID: {agent.id}, Amount: {amount}, Period: {commission_period}")

            new_commissions.append(
                Commission(agent_id=agent.id, phone_number=phone_number, amount=amount, commission_period=commission_period)  # 🔹 Store period
            )

        if new_commissions:
            db.session.bulk_save_objects(new_commissions)
            db.session.commit()
            print("✅ Commissions Successfully Inserted!")

        return jsonify({"message": "Commissions uploaded successfully! Agents auto-created if not found."})

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500




from datetime import datetime

@app.route('/get_commissions', methods=['GET'])
@jwt_required()
def get_commissions():
    """ Fetches commissions assigned to the logged-in agent with the manually entered commission period. """
    user_identity = json.loads(get_jwt_identity())
    agent = User.query.filter_by(id=user_identity['id']).first()

    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    print(f"Fetching commissions for Agent ID: {agent.id}, Phone: {agent.phone_number}")

    commissions = Commission.query.filter_by(phone_number=agent.phone_number).all()

    if not commissions:
        print("No commissions found!")

    return jsonify([
        {
            "date": c.date.strftime('%Y-%m-%d'),
            "amount": c.amount,
            "commission_period": c.commission_period  # 🔹 Now included in the response
        }
        for c in commissions
    ])





# Authentication
@app.route('/login', methods=['POST'])
def login():
    """ Login using phone number and password. """
    data = request.json
    if not data or 'phone_number' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    user = User.query.filter_by(phone_number=data['phone_number']).first()

    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        # 🔹 Generate token first
        token = create_access_token(identity=json.dumps({'id': user.id, 'role': user.role}))

        # 🔹 Check if user must reset password
        if user.first_login:
            return jsonify({
                'message': 'Password reset required',
                'reset_required': True,
                'token': token  # 🔹 Ensure token is included for reset
            }), 403  # Forbidden until password is reset

        # 🔹 Return normal login response
        return jsonify({'token': token, 'role': user.role, 'first_name': user.first_name})

    return jsonify({'error': 'Invalid credentials'}), 401





@app.route('/register', methods=['POST'])
def register():
    """ Register a new agent using first name, last name, phone number, and password. """
    data = request.json
    required_fields = ['first_name', 'last_name', 'phone_number', 'password']

    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter_by(phone_number=data['phone_number']).first():
        return jsonify({'error': 'Phone number already registered'}), 409

    # 🔹 Generate a unique username
    username = f"{data['first_name'].lower()}.{data['last_name'].lower()}"

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_agent = User(
        first_name=data['first_name'].strip(),
        last_name=data['last_name'].strip(),
        phone_number=data['phone_number'].strip(),
        password_hash=hashed_password,
        username=username,  # 🔹 Fix: Assign username automatically
        role="agent"
    )

    db.session.add(new_agent)
    db.session.commit()

    return jsonify({'message': 'Agent registered successfully'}), 201


@app.route('/get_agents', methods=['GET'])
@jwt_required()
def get_agents():
    user_identity = json.loads(get_jwt_identity())

    if user_identity.get("role") != "manager":
        return jsonify({"error": "Unauthorized"}), 403

    agents = User.query.filter_by(role='agent').all()

    if not agents:
        return jsonify({"message": "No agents found."}), 404  # Better response if empty

    return jsonify([
        {
            "id": agent.id,
            "username": agent.username,
            "first_name": agent.first_name,  # 🔹 Add First Name
            "last_name": agent.last_name,  # 🔹 Add Last Name
            "phone_number": agent.phone_number
        }
        for agent in agents
    ])


@app.route('/get_payments/<int:user_id>', methods=['GET'])
@jwt_required()
def get_payments(user_id):
    """ Fetches all commission payments for a specific agent """
    user_identity = json.loads(get_jwt_identity())

    # Only managers should be able to view payments
    if user_identity["role"] != "manager":
        return jsonify({"error": "Unauthorized"}), 403

    # Fetch payments for the given user_id
    payments = Commission.query.filter_by(agent_id=user_id).all()

    if not payments:
        return jsonify([])  # Return empty list if no payments found

    return jsonify([
        {
            "amount": c.amount,
            "date": c.date.strftime('%Y-%m-%d'),
            "commission_period": c.commission_period
        }
        for c in payments
    ])



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

@app.route('/reset_password', methods=['POST'])
@jwt_required()
def reset_password():
    """ Allows first-time agents to reset their password """
    try:
        user_identity = json.loads(get_jwt_identity())
        user = User.query.get(user_identity['id'])

        if not user:
            return jsonify({"error": "User not found"}), 404

        data = request.json
        new_password = data.get('new_password', '').strip()

        if not new_password or len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters"}), 400

        # 🔹 Update password and remove first_login flag
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.first_login = False  # ✅ Mark first login as complete
        db.session.commit()

        return jsonify({"message": "Password updated successfully. You can now log in."}), 200
    
    except Exception as e:
        print(f"❌ Reset Password Error: {e}")  # Log error for debugging
        return jsonify({"error": "Something went wrong. Please try again."}), 500




@app.route('/')
def home():
    return "PDF Manager API is running!"


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 10000)), debug=True)
