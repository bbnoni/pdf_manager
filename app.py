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
from random import randint  # ✅ Import randint for generating OTPs
from dotenv import load_dotenv

# ✅ Load environment variables from .env
if os.path.exists(".env"):
    load_dotenv()
else:
    print("⚠️ Warning: .env file not found!")



app = Flask(__name__)
CORS(app)  # Enable CORS

# ✅ Load database URL from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("❌ DATABASE_URL is not set! Check your .env file or Render settings.")


# Load environment variables
#DATABASE_URL = os.getenv("DATABASE_URL")
# ✅ Use the correct database URL
#DATABASE_URL = "postgresql://pdf_manager_db_user:NjU5pim8oEuFD1D0Pb4rwcZwmxN27m1j@dpg-cv136gjqf0us73c3f6p0-a/render.com/pdf_manager_db"
#DATABASE_URL = "postgresql://pdf_manager_db_user:NjU5pim8oEuFD1D0Pb4rwCzWmxN27m1j@dpg-cv136gjqf0us73c3f6p0-a.oregon-postgres.render.com/pdf_manager_db"

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

# ✅ Debugging: Print database connection
print(f"🔍 DATABASE_URL: {DATABASE_URL}")

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
    reset_token = db.Column(db.String(6), nullable=True)  # ✅ Store reset token

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

    # **Additional Fields from the Excel Sheet**
     # ✅ Add missing fields from Excel
    cashin_total_transactions = db.Column(db.String(20))  
    cashin_total_value = db.Column(db.String(20))  
    cashin_total_number_valid = db.Column(db.String(20))  # Added
    cashin_total_value_valid = db.Column(db.String(20))  # Added
    cashin_total_tax_on_valid = db.Column(db.String(20))  
    cashin_payout_commission = db.Column(db.String(20))  
    cashout_total_transactions = db.Column(db.String(20))  
    cashout_total_value = db.Column(db.String(20))  
    cashout_total_number_valid = db.Column(db.String(20))  # Added
    cashout_total_value_valid = db.Column(db.String(20))  # Added
    cashout_total_tax_on_valid = db.Column(db.String(20))  
    cashout_payout_commission = db.Column(db.String(20))  
    total_commissions_due = db.Column(db.String(20))  

with app.app_context():
    db.create_all()



@app.route('/upload_commissions', methods=['POST'])
@jwt_required()
def upload_commissions():
    """ Uploads an Excel/CSV file and assigns commissions, including all additional fields. """
    user_identity = json.loads(get_jwt_identity())
    if user_identity['role'] != 'manager':
        return jsonify({'error': 'Unauthorized'}), 403

    if 'file' not in request.files or 'commission_period' not in request.form:
        return jsonify({"error": "No file uploaded or commission period missing"}), 400

    file = request.files['file']
    commission_period = request.form['commission_period'].strip()
    filename = secure_filename(file.filename)

    if not filename.endswith(('.csv', '.xlsx')):
        return jsonify({"error": "Invalid file format. Only CSV and Excel allowed"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        print(f"✅ Reading file: {filename}")

        # ✅ Read Excel or CSV File - Ensure Phone Number Stays as String
        df = pd.read_csv(file_path, dtype={"Phone number": str}) if filename.endswith('.csv') else pd.read_excel(file_path, dtype={"Phone number": str})

        # ✅ Debug: Print detected column names
        print(f"🔍 Detected Columns in File: {df.columns.tolist()}")

        # ✅ Updated Required Columns - Ensure exact match
        required_columns = {
            "First Name", "Last Name", "Phone number", "Commission",
            "cashin-total number transactions", "cashin-total numberVALID",  # ✅ FIXED
            "cashin-total value", "cashin-total valueVALID",  # ✅ FIXED
            "cashin-total tax on VALID", "cashin-payout commission",
            "cashout-total number transactions", "cashout-total numberVALID",  # ✅ FIXED
            "cashout-total value", "cashout-total valueVALID",  # ✅ FIXED
            "cashout-total tax on VALID", "cashout-payout commission",
            "total commissions due"
        }

        # ✅ Check for missing columns
        missing_columns = required_columns - set(df.columns)
        if missing_columns:
            print(f"❌ ERROR: Missing required columns: {missing_columns}")
            return jsonify({"error": f"Invalid file format. Missing columns: {missing_columns}"}), 400

        total_records = len(df)  # ✅ Get total records in file
        success_count = 0  # ✅ Track successful uploads

        new_commissions = []

        def generate_unique_username(first_name, last_name):
            """ Generate a unique username by appending a number if needed. """
            base_username = f"{first_name.lower()}.{last_name.lower()}".replace(" ", "_")
            username = base_username
            counter = 1

            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1

            return username

        def get_value(column_name):
            """ Safely fetch column value from row, return None if missing. """
            return row[column_name] if column_name in row and pd.notna(row[column_name]) else None

        for _, row in df.iterrows():
            first_name = str(row.get("First Name", "Unknown")).strip()
            last_name = str(row.get("Last Name", "User")).strip()
            
            # ✅ Ensure Phone Number Stays as String Without ".0"
            phone_number = str(row.get("Phone number", "")).strip()
            phone_number = phone_number.split(".")[0] if ".0" in phone_number else phone_number

            if not phone_number:
                print(f"⚠️ Skipping record due to missing phone number: {row}")
                continue

            try:
                amount = float(row.get("Commission", 0))
            except ValueError:
                print(f"⚠️ Skipping record due to invalid commission amount: {row}")
                continue

            agent = User.query.filter_by(phone_number=phone_number).first()

            if not agent:
                print(f"❌ Agent with phone {phone_number} NOT FOUND! Creating a new agent.")

                default_password = bcrypt.generate_password_hash("default123").decode('utf-8')
                username = generate_unique_username(first_name, last_name)

                new_agent = User(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    password_hash=default_password,
                    role="agent",
                    phone_number=phone_number,
                    first_login=True
                )
                db.session.add(new_agent)
                db.session.commit()
                agent = new_agent  # Assign new agent

            print(f"✅ Assigning Commission: Agent ID: {agent.id}, Amount: {amount}, Period: {commission_period}")

            # ✅ Inserting All Required Fields, Including Missing Ones
            # ✅ Inserting All Required Fields, Including Missing Ones
            new_commissions.append(
                Commission(
                    agent_id=agent.id,
                    phone_number=phone_number,
                    amount=amount,
                    commission_period=commission_period,
                    cashin_total_transactions=get_value("cashin-total number transactions"),  # ✅ FIXED
                    cashin_total_number_valid=get_value("cashin-total numberVALID"),  # ✅ FIXED
                    cashin_total_value=get_value("cashin-total value"),
                    cashin_total_value_valid=get_value("cashin-total valueVALID"),  # ✅ FIXED
                    cashin_total_tax_on_valid=get_value("cashin-total tax on VALID"),
                    cashin_payout_commission=get_value("cashin-payout commission"),
                    cashout_total_transactions=get_value("cashout-total number transactions"),
                    cashout_total_number_valid=get_value("cashout-total numberVALID"),  # ✅ FIXED
                    cashout_total_value=get_value("cashout-total value"),
                    cashout_total_value_valid=get_value("cashout-total valueVALID"),  # ✅ FIXED
                    cashout_total_tax_on_valid=get_value("cashout-total tax on VALID"),
                    cashout_payout_commission=get_value("cashout-payout commission"),
                    total_commissions_due=get_value("total commissions due")
                )
            )

            success_count += 1  # ✅ Increment success count

        if new_commissions:
            db.session.bulk_save_objects(new_commissions)
            db.session.commit()
            print(f"✅ {success_count}/{total_records} Commissions Successfully Inserted!")

        return jsonify({
            "message": "Commissions uploaded successfully!",
            "total_records": total_records,  # ✅ Total records in the file
            "records_uploaded": success_count  # ✅ Successfully uploaded records
        })

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500










from datetime import datetime

@app.route('/get_commissions', methods=['GET'])
@jwt_required()
def get_commissions():
    """ Fetches commissions assigned to the logged-in agent, including all details. """
    user_identity = json.loads(get_jwt_identity())
    agent = User.query.filter_by(id=user_identity['id']).first()

    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    print(f"🔍 Fetching commissions for Agent ID: {agent.id}, Phone: {agent.phone_number}")

    commissions = Commission.query.filter_by(phone_number=agent.phone_number).all()

    if not commissions:
        print("⚠️ No commissions found!")
        return jsonify([])  # Return an empty list instead of nothing

    # ✅ Improved Response Format
    response_data = [
        {
            "id": c.id,  # 🔹 Include commission ID
            "phone_number": c.phone_number,  # 🔹 Ensures phone number consistency
            "date": c.date.strftime('%Y-%m-%d') if c.date else "N/A",
            "amount": float(c.amount) if c.amount is not None else 0.0,  # ✅ Ensure numerical format
            "commission_period": c.commission_period if c.commission_period else "Not Provided",
            "cashin_total_transactions": c.cashin_total_transactions or "N/A",
            "cashin_total_number_valid": c.cashin_total_number_valid or "N/A",  # ✅ Added missing field
            "cashin_total_value": c.cashin_total_value or "N/A",
            "cashin_total_value_valid": c.cashin_total_value_valid or "N/A",  # ✅ Added missing field
            "cashin_total_tax_on_valid": c.cashin_total_tax_on_valid or "N/A",
            "cashin_payout_commission": c.cashin_payout_commission or "N/A",
            "cashout_total_transactions": c.cashout_total_transactions or "N/A",
            "cashout_total_number_valid": c.cashout_total_number_valid or "N/A",  # ✅ Added missing field
            "cashout_total_value": c.cashout_total_value or "N/A",
            "cashout_total_value_valid": c.cashout_total_value_valid or "N/A",  # ✅ Added missing field
            "cashout_total_tax_on_valid": c.cashout_total_tax_on_valid or "N/A",
            "cashout_payout_commission": c.cashout_payout_commission or "N/A",
            "total_commissions_due": float(c.total_commissions_due) if c.total_commissions_due is not None else 0.0,
        }
        for c in commissions
    ]

    print(f"✅ Found {len(response_data)} commissions for Agent ID: {agent.id}")

    return jsonify(response_data)







# Authentication
@app.route('/login', methods=['POST'])
def login():
    """ Login using phone number OR username and password. """
    data = request.json
    if not data or 'phone_number' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    # 🔹 Allow login using either Phone Number OR Username
    user = User.query.filter(
        (User.phone_number == data['phone_number']) | (User.username == data['phone_number'])
    ).first()

    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        # 🔹 Generate JWT token
        token = create_access_token(identity=json.dumps({'id': user.id, 'role': user.role}))

        # 🔹 Check if the user must reset password (Only for first-time users)
        if user.first_login:
            return jsonify({
                'message': 'Password reset required',
                'reset_required': True,
                'token': token,  # 🔹 Ensure token is included for reset
                'first_login': True  # ✅ Explicitly return first_login status
            }), 403  # Forbidden until password is reset

        # 🔹 Normal login response for manually registered users
        return jsonify({
            'token': token,
            'role': user.role,
            'first_name': user.first_name,
            'first_login': False  # ✅ Explicitly return false for normal users
        })

    return jsonify({'error': 'Invalid credentials'}, 401)








@app.route('/register', methods=['POST'])
@jwt_required(optional=True)  # ✅ Allow managers to register other managers while allowing public agent sign-ups
def register():
    """ Register a new agent or manager. 
        - Agents who register manually get `first_login = False`
        - Managers created by an existing manager get `first_login = True` 
    """
    data = request.json
    required_fields = ['first_name', 'last_name', 'phone_number', 'role']

    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter_by(phone_number=data['phone_number']).first():
        return jsonify({'error': 'Phone number already registered'}), 409

    # 🔹 Ensure username is unique
    base_username = f"{data['first_name'].lower()}.{data['last_name'].lower()}".replace(" ", "_")
    username = base_username
    counter = 1

    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"  # Append number if username exists
        counter += 1

    # ✅ Generate a random 6-digit password
    generated_password = str(random.randint(100000, 999999))

    hashed_password = bcrypt.generate_password_hash(generated_password).decode('utf-8')

    # 🔹 Determine if user is self-registering (agent) or being created (manager)
    jwt_identity = get_jwt_identity()
    is_manager_creation = jwt_identity and json.loads(jwt_identity).get("role") == "manager"

    new_user = User(
        first_name=data['first_name'].strip(),
        last_name=data['last_name'].strip(),
        phone_number=data['phone_number'].strip(),
        password_hash=hashed_password,
        username=username,  # ✅ Ensure unique username
        role=data['role'].strip().lower(),  # Can be "agent" or "manager"
        first_login=is_manager_creation  # ✅ True for new managers, False for manually registered agents
    )

    db.session.add(new_user)
    db.session.commit()

    # ✅ Log the generated password for debugging
    print(f"✅ {data['role'].capitalize()} Created: {data['phone_number']}, Password: {generated_password}")

    # ✅ Send notification via SMS, Email, or WhatsApp
    notify_channel = data.get("notify_channel", "sms")  # Default to SMS
    if notify_channel == "sms":
        print(f"📩 SMS sent to {data['phone_number']}: Your temporary password is {generated_password}")
    elif notify_channel == "email":
        print(f"📩 Email sent to {data['phone_number']}@example.com: Your temporary password is {generated_password}")
    elif notify_channel == "whatsapp":
        print(f"📩 WhatsApp message sent to {data['phone_number']}: Your temporary password is {generated_password}")

    return jsonify({'message': f"{data['role'].capitalize()} registered successfully!"}), 201




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
            "commission_period": c.commission_period  # 🔹 Make sure this is included
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
@jwt_required(optional=True)  # ✅ Optional JWT for first-time login users
def reset_password():
    """Allows users to reset their password (both first-time users and forgot password users)"""
    try:
        data = request.json
        phone_number = data.get('phone_number', '').strip()
        token = data.get("token", "").strip()  # ✅ Ensure reset token is received
        new_password = data.get('new_password', '').strip()

        if not phone_number or not token or not new_password:
            return jsonify({"error": "Phone number, token, and new password are required"}), 400

        if len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters"}), 400

        # ✅ Normalize phone number for correct matching
        formatted_phone = f"0{phone_number[3:]}" if phone_number.startswith("233") else phone_number
        print(f"🔍 Searching for user with phone number: {formatted_phone}")

        # ✅ Find user by phone number
        user = User.query.filter_by(phone_number=formatted_phone).first()

        if not user:
            print(f"❌ User not found for phone: {formatted_phone}")
            return jsonify({"error": "User not found"}), 404

        # ✅ Validate token from the database
        if not user.reset_token or user.reset_token != token:
            print(f"❌ Invalid or expired reset token for {formatted_phone}")
            return jsonify({"error": "Invalid or expired reset token"}), 400

        # ✅ Reset password and clear the reset token
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password_hash = hashed_password
        user.first_login = False  # ✅ Mark reset as complete
        user.reset_token = None  # ✅ Clear the reset token after successful reset
        db.session.commit()

        print(f"✅ Password successfully reset for {formatted_phone}")

        return jsonify({"message": "Password updated successfully. You can now log in."}), 200

    except Exception as e:
        print(f"❌ Reset Password Error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500




from datetime import datetime, timedelta
import random



@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    """Handles Forgot Password Requests Securely"""
    try:
        data = request.json
        phone_number = data.get("phone_number", "").strip()
        channel = data.get("channel", "").strip().lower()  # "sms", "email", "whatsapp"

        if not phone_number or not channel:
            return jsonify({"error": "Phone number and channel are required"}), 400

        print(f"🔍 Received phone number: {phone_number}")

        # ✅ Normalize phone number
        formatted_phone = f"0{phone_number[3:]}" if phone_number.startswith("233") else phone_number
        print(f"🔄 Normalized phone number: {formatted_phone}")

        # ✅ Check if user exists
        user = User.query.filter_by(phone_number=formatted_phone).first()
        if not user:
            print(f"❌ Phone number {formatted_phone} not registered.")
            return jsonify({"error": "Phone number not registered"}), 404

        # ✅ Generate a 6-digit reset token
        reset_token = str(random.randint(100000, 999999))
        print(f"✅ Reset token generated: {reset_token} for {user.phone_number}")

        # ✅ Store reset token in the database
        user.reset_token = reset_token
        db.session.commit()
        print(f"🔐 Reset token stored in the database for {formatted_phone}")

        # ✅ Send the token via the selected channel
        if channel == "email":
            registered_email = f"{user.username}@example.com"
            print(f"📩 Email sent to {registered_email}: Your reset code is {reset_token}")

        elif channel == "sms":
            print(f"📩 SMS sent to {user.phone_number}: Your reset code is {reset_token}")

        elif channel == "whatsapp":
            print(f"📩 WhatsApp message sent to {user.phone_number}: Your reset code is {reset_token}")

        # ✅ Return the token in the API response
        return jsonify({
            "message": f"Reset code sent via {channel}",
            "reset_token": reset_token  # ✅ Now explicitly included in the response
        }), 200

    except Exception as e:
        print(f"❌ Forgot Password Error: {e}")
        return jsonify({"error": "Something went wrong"}), 500















@app.route('/')
def home():
    return "PDF Manager API is running!"


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 10000)), debug=True)
