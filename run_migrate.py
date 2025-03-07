from app import db, app
from flask_migrate import Migrate

migrate = Migrate(app, db)

if __name__ == "__main__":
    print("✅ Migrations setup completed!")
