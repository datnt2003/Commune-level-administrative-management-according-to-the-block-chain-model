from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from sqlalchemy.engine.reflection import Inspector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='frontend')
app.config['SECRET_KEY'] = 'a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blockchain.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def your_date_filter_function(value, format='%Y-%m-%d %H:%M:%S'):
    date = datetime.fromtimestamp(value)
    return date.strftime(format)

app.jinja_env.filters['date'] = your_date_filter_function
from .models import *
with app.app_context():
    db.drop_all()
    db.create_all()
    engine = db.engine
    inspector = Inspector.from_engine(engine)
    if inspector.has_table('block'):
        db.create_all()

    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
        admin_user = User(
            username='admin', 
            password_hash=hashed_password, 
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
    
    blockchain = Blockchain()

from .routers import *
