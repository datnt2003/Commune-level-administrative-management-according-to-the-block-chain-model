from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from time import time
from functools import wraps
import hashlib
import json
from sqlalchemy.engine.reflection import Inspector
from jinja2 import Environment
from datetime import datetime

app = Flask(__name__, template_folder='frontend')
app.config['SECRET_KEY'] = 'a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blockchain.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


def your_date_filter_function(value, format='%Y-%m-%d %H:%M:%S'):
    """Convert a timestamp (float) to a formatted date string."""
    date = datetime.fromtimestamp(value)
    return date.strftime(format)

# Đăng ký bộ lọc này trong Jinja environment của Flask
app.jinja_env.filters['date'] = your_date_filter_function


db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, password_hash, is_admin=False):
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin


class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    transaction_data = db.Column(db.Text, nullable=False)
    proof = db.Column(db.Integer, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=False)
    cccd_details = db.Column(db.Text, nullable=False)
    block_id = db.Column(db.Integer, db.ForeignKey('block.id'), nullable=False)
    block = db.relationship('Block', backref=db.backref('transactions_list', lazy=True))


class PendingTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=False)
    cccd_details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.Float, default=time, nullable=False)


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.Float, nullable=False)


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.load_chain()

    def load_chain(self):
        """Load the chain from the database."""
        blocks = Block.query.order_by(Block.index).all()
        for block in blocks:
            self.chain.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'transactions': json.loads(block.transaction_data),
                'proof': block.proof,
                'previous_hash': block.previous_hash
            })
        if not self.chain:
            self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        """Create a new block and add it to the chain."""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        new_block = Block(index=block['index'], timestamp=block['timestamp'],
                          transaction_data=json.dumps(block['transactions']),
                          proof=block['proof'], previous_hash=block['previous_hash'])
        db.session.add(new_block)
        db.session.commit()

        for tx in self.current_transactions:
            new_transaction = Transaction(sender=tx['sender'], recipient=tx['recipient'],
                                          cccd_details=json.dumps(tx['cccd_details']),
                                          block_id=new_block.id)
            db.session.add(new_transaction)

        db.session.commit()

        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, cccd_details):
        """Add a new transaction to the list of current transactions."""
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'cccd_details': cccd_details,
        })
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """Create a SHA-256 hash of a block."""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        """Return the last block in the chain."""
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        """Simple Proof of Work Algorithm."""
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """Validates the Proof: Does hash(last_proof, proof) contain leading 4 zeroes?"""
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully!')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/mine', methods=['GET'])
@login_required
def mine():
    try:
        last_block = blockchain.last_block
        last_proof = last_block['proof']
        proof = blockchain.proof_of_work(last_proof)

        # Reward the miner by adding a reward transaction
        blockchain.new_transaction(
            sender="0",
            recipient=current_user.username,
            cccd_details={"note": "Reward for mining"}
        )

        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)

        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        return jsonify(response), 200
    except Exception as e:
        # Log the error and provide a generic error message
        app.logger.error(f"Error during mining: {str(e)}")
        return jsonify({"message": "An error occurred during mining"}), 500


@app.route('/transactions/new', methods=['GET', 'POST'])
@login_required
def new_transaction():
    if request.method == 'POST':
        cccd_details = {
            'full_name': request.form['full_name'],
            'date_of_birth': request.form['date_of_birth'],
            'address': request.form['address'],
            'cccd_number': request.form['cccd_number']
        }
        sender = request.form['sender']
        recipient = request.form['recipient']

        # Add the transaction to the pending list
        new_pending_tx = PendingTransaction(sender=sender, recipient=recipient, cccd_details=json.dumps(cccd_details))
        db.session.add(new_pending_tx)
        db.session.commit()

        flash('Transaction sent for approval.')
        return redirect(url_for('home'))
    return render_template('create_transaction.html')


@app.route('/chain', methods=['GET'])
@login_required
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response)


@app.route('/news/post', methods=['GET', 'POST'])
@login_required
def post_news():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_post = News(title=title, content=content, author=current_user.username, timestamp=time())
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('view_news'))
    return render_template('post_news.html')


@app.route('/news', methods=['GET'])
def view_news():
    news_feed = News.query.order_by(News.timestamp.desc()).all()
    return render_template('view_news.html', news_feed=news_feed)


@app.route('/')
def home():
    latest_news = News.query.order_by(News.timestamp.desc()).limit(5).all()
    return render_template('home.html', latest_news=latest_news)


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_admin:
            return func(*args, **kwargs)
        else:
            abort(403)  # Forbidden
    return decorated_function


@app.route('/transactions/all', methods=['GET'])
@login_required
@admin_required
def view_all_transactions():
    all_transactions = []
    blocks = Block.query.all()
    for block in blocks:
        transactions = Transaction.query.filter_by(block_id=block.id).all()
        for tx in transactions:
            all_transactions.append({
                'sender': tx.sender,
                'recipient': tx.recipient,
                'cccd_details': json.loads(tx.cccd_details),
                'block_index': block.index,
                'timestamp': block.timestamp
            })
    return render_template('all_transactions.html', transactions=all_transactions)


@app.route('/transactions/pending', methods=['GET', 'POST'])
@login_required
@admin_required
def view_pending_transactions():
    pending_transactions = PendingTransaction.query.all()
    if request.method == 'POST':
        action = request.form.get('action')
        tx_id = request.form.get('tx_id')
        pending_tx = PendingTransaction.query.get(tx_id)

        if action == 'approve' and pending_tx:
            # Add the approved transaction to the blockchain current transactions
            blockchain.new_transaction(
                sender=pending_tx.sender,
                recipient=pending_tx.recipient,
                cccd_details=json.loads(pending_tx.cccd_details)
            )

            # Mine a block if there are enough transactions or based on a condition
            if len(blockchain.current_transactions) >= 1:  # You can adjust this threshold
                last_proof = blockchain.last_block['proof']
                proof = blockchain.proof_of_work(last_proof)
                previous_hash = blockchain.hash(blockchain.last_block)
                new_block = blockchain.new_block(proof, previous_hash)
                flash(f'Block {new_block["index"]} is mined to include approved transactions.')

            # Delete the pending transaction after it is added to the blockchain
            db.session.delete(pending_tx)
            db.session.commit()
            flash(f'Transaction {tx_id} approved.')

        elif action == 'reject' and pending_tx:
            db.session.delete(pending_tx)
            db.session.commit()
            flash(f'Transaction {tx_id} rejected.')

        return redirect(url_for('view_pending_transactions'))

    return render_template('pending_transactions.html', transactions=pending_transactions)

@app.route('/transactions/user', methods=['GET'])
@login_required
def user_transactions():
    # Fetch approved transactions associated with the user
    approved_transactions = []
    user_blocks = Block.query.join(Transaction).filter(
        (Transaction.sender == current_user.username) | (Transaction.recipient == current_user.username)
    ).all()

    for block in user_blocks:
        transactions = Transaction.query.filter_by(block_id=block.id).filter(
            (Transaction.sender == current_user.username) | (Transaction.recipient == current_user.username)
        ).all()
        for tx in transactions:
            approved_transactions.append({
                'id': tx.id,
                'sender': tx.sender,
                'recipient': tx.recipient,
                'cccd_details': json.loads(tx.cccd_details),
                'block': {
                    'index': block.index,
                    'timestamp': block.timestamp
                }
            })

    # Fetch pending transactions associated with the user
    pending_transactions = []
    user_pending = PendingTransaction.query.filter(
        (PendingTransaction.sender == current_user.username) | (PendingTransaction.recipient == current_user.username)
    ).all()

    for tx in user_pending:
        pending_transactions.append({
            'id': tx.id,
            'sender': tx.sender,
            'recipient': tx.recipient,
            'cccd_details': json.loads(tx.cccd_details),
            'timestamp': tx.timestamp
        })

    return render_template('user_transactions.html',
                           approved_transactions=approved_transactions,
                           pending_transactions=pending_transactions)

if __name__ == '__main__':
    with app.app_context():
        # Ensure all migrations are up to date before starting the app
        db.create_all()
        engine = db.engine
        inspector = Inspector.from_engine(engine)
        if inspector.has_table('block'):
            db.create_all()

        # Create an admin user if not already created
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
            admin_user = User(username='admin', password_hash=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()

        # Initialize the blockchain
        blockchain = Blockchain()

    app.run(host='0.0.0.0', port=5001, debug=True)