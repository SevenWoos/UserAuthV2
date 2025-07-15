from app import app, db, bcrypt
from app import User  # Adjust if your User model is elsewhere

def create_admin():
    # Check if admin already exists
    existing_admin = User.query.filter_by(username="admin").first()
    if existing_admin:
        print("⚠️ Admin user already exists.")
        return

    # Hash the password securely
    hashed_password = bcrypt.generate_password_hash("adminpass").decode('utf-8')

    # Create admin user
    admin = User(username="admin", password=hashed_password, is_admin=True)
    db.session.add(admin)
    db.session.commit()
    print("✅ Admin user created.")

# Run inside app context
with app.app_context():
    create_admin()
