from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from time import time
from functools import wraps
import json
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from .models import User, Block, Transaction, PendingTransaction, News
from . import app, db, login_manager, blockchain
def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return decorated_function

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
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
        app.logger.error(f"Error during mining: {str(e)}")
        return jsonify({"message": "An error occurred during mining"}), 500

@app.route('/transactions/new/cccd', methods=['GET', 'POST'])
@login_required
def new_cccd_transaction():
    if request.method == 'POST':
        cccd_details = {
            'full_name': request.form['full_name'],
            'date_of_birth': request.form['date_of_birth'],
            'address': request.form['address'],
            'cccd_number': request.form['cccd_number']
        }
        sender = request.form['sender']
        recipient = request.form['recipient']

        new_pending_tx = PendingTransaction(
            sender=sender, 
            recipient=recipient, 
            cccd_details=json.dumps(cccd_details)
        )
        db.session.add(new_pending_tx)
        db.session.commit()

        flash('CCCD transaction sent for approval.')
        return redirect(url_for('user_transactions'))
    return render_template('create_cccd_transaction.html')

@app.route('/transactions/new/passport', methods=['GET', 'POST'])
@login_required
def new_passport_transaction():
    if request.method == 'POST':
        passport_details = {
            'full_name': request.form['passport_full_name'],
            'date_of_birth': request.form['passport_date_of_birth'],
            'address': request.form['passport_address'],
            'passport_number': request.form['passport_number']
        }
        sender = request.form['sender']
        recipient = request.form['recipient']

        new_pending_tx = PendingTransaction(
            sender=sender, 
            recipient=recipient, 
            passport_details=json.dumps(passport_details)
        )
        db.session.add(new_pending_tx)
        db.session.commit()

        flash('Passport transaction sent for approval.')
        return redirect(url_for('user_transactions'))
    return render_template('create_passport_transaction.html')

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
            blockchain.new_transaction(
                sender=pending_tx.sender,
                recipient=pending_tx.recipient,
                cccd_details=json.loads(pending_tx.cccd_details) if pending_tx.cccd_details else None,
                passport_details=json.loads(pending_tx.passport_details) if pending_tx.passport_details else None
            )

            if len(blockchain.current_transactions) >= 1:  # Adjust this threshold as needed
                last_proof = blockchain.last_block['proof']
                proof = blockchain.proof_of_work(last_proof)
                previous_hash = blockchain.hash(blockchain.last_block)
                new_block = blockchain.new_block(proof, previous_hash)
                flash(f'Block {new_block["index"]} is mined to include approved transactions.')

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
    if not current_user.is_admin:
        
        approved_transactions = []
        user_blocks = Block.query.join(Transaction).filter(
            (Transaction.sender == current_user.username) | (Transaction.recipient == current_user.username)
        ).all()

        for block in user_blocks:
            block_transactions = []
            transactions = Transaction.query.filter_by(block_id=block.id).filter(
                (Transaction.sender == current_user.username) | (Transaction.recipient == current_user.username)
            ).all()
            for tx in transactions:
                block_transactions.append({
                    'id': tx.id,
                    'sender': tx.sender,
                    'recipient': tx.recipient,
                    'cccd_details': json.loads(tx.cccd_details) if tx.cccd_details else None,
                    'passport_details': json.loads(tx.passport_details) if tx.passport_details else None
                })
            approved_transactions.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'transactions': block_transactions
            })

        pending_transactions = []
        user_pending = PendingTransaction.query.filter(
            (PendingTransaction.sender == current_user.username) | (PendingTransaction.recipient == current_user.username)
        ).all()

        for tx in user_pending:
            pending_transactions.append({
                'id': tx.id,
                'sender': tx.sender,
                'recipient': tx.recipient,
                'cccd_details': json.loads(tx.cccd_details) if tx.cccd_details else None,
                'passport_details': json.loads(tx.passport_details) if tx.passport_details else None,
                'timestamp': tx.timestamp
            })

        return render_template('user_transactions.html',
                            approved_transactions=approved_transactions,
                            pending_transactions=pending_transactions)
    else:
        all_transactions = []
        blocks = Block.query.all()
        for block in blocks:
            transactions = Transaction.query.filter_by(block_id=block.id).all()
            for tx in transactions:
                all_transactions.append({
                    'sender': tx.sender,
                    'recipient': tx.recipient,
                    'cccd_details': json.loads(tx.cccd_details) if tx.cccd_details else None,
                    'passport_details': json.loads(tx.passport_details) if tx.passport_details else None,
                    'block_index': block.index,
                    'timestamp': block.timestamp
                })
        return render_template('all_transactions.html', transactions=all_transactions)

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
                'cccd_details': json.loads(tx.cccd_details) if tx.cccd_details else None,
                'passport_details': json.loads(tx.passport_details) if tx.passport_details else None,
                'block_index': block.index,
                'timestamp': block.timestamp
            })
    return render_template('all_transactions.html', transactions=all_transactions)

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
    latest_news = News.query.order_by(News.timestamp.desc()).limit(6).all()
    return render_template('home.html', latest_news=latest_news)

@app.route('/search', methods=['GET'])
@login_required
def search_transactions():
    query = request.args.get('query')
    if not query:
        flash('Please enter a search term', 'warning')
        return redirect(url_for('user_transactions'))

    # Tìm tất cả các giao dịch để tính toán mức độ tương đồng
    all_transactions = Transaction.query.all()

    # Chuẩn bị dữ liệu văn bản
    documents = []
    for tx in all_transactions:
        document = f"{tx.sender} {tx.recipient} {tx.cccd_details or ''} {tx.passport_details or ''}".strip()
        if document:  # Chỉ thêm tài liệu nếu không trống
            documents.append(document)

    if not documents:  # Kiểm tra xem có tài liệu nào không
        flash('No transactions found to search through.', 'warning')
        return redirect(url_for('user_transactions'))

    # Chuyển đổi truy vấn và dữ liệu giao dịch thành vector TF-IDF
    vectorizer = TfidfVectorizer(stop_words='english').fit_transform([query] + documents)
    vectors = vectorizer.toarray()

    # Tính toán mức độ tương đồng cosine giữa truy vấn và các giao dịch
    cosine_similarities = cosine_similarity(vectors[0:1], vectors[1:]).flatten()

    # Lấy các giao dịch có mức độ tương đồng cao nhất
    most_similar_indices = cosine_similarities.argsort()[-10:][::-1]
    similar_transactions = [all_transactions[i] for i in most_similar_indices]

    # Phân loại các giao dịch theo block
    approved_transactions = []
    for tx in similar_transactions:
        block = Block.query.get(tx.block_id)
        block_transactions = {
            'id': tx.id,
            'sender': tx.sender,
            'recipient': tx.recipient,
            'cccd_details': json.loads(tx.cccd_details) if tx.cccd_details else None,
            'passport_details': json.loads(tx.passport_details) if tx.passport_details else None,
            'block': {
                'index': block.index,
                'timestamp': block.timestamp
            }
        }
        approved_transactions.append(block_transactions)

    return render_template('search_results.html', approved_transactions=approved_transactions, query=query)

