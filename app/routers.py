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
        
        fullname = request.form['fullname']
        date_of_birth = request.form['date_of_birth']
        phone = request.form['phone']
        gender = request.form['gender']
        # Chuyển đổi date_of_birth từ chuỗi sang đối tượng datetime.date
        try:
            date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
        except ValueError:
            flash('Ngày sinh không hợp lệ. Vui lòng nhập lại.')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username, 
            password_hash=hashed_password, 
            fullname = fullname, 
            date_of_birth = date_of_birth, 
            phone = phone, 
            gender = gender
        )
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

import random
import string

def generate_unique_number(prefix, length=10):
    while True:
        number = prefix + ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not (PendingTransaction.query.filter_by(cccd_details=number).first() or
                PendingTransaction.query.filter_by(passport_details=number).first() or
                Transaction.query.filter_by(cccd_details=number).first() or
                Transaction.query.filter_by(passport_details=number).first()):
            return number

@app.route('/transactions/new/cccd', methods=['GET', 'POST'])
@login_required
# def new_cccd_transaction():
#     if request.method == 'POST':
#         cccd_details = {
#             'full_name': request.form['full_name'],
#             'date_of_birth': request.form['date_of_birth'],
#             'address': request.form['address'],
            
#         }
#         sender = current_user.get_username()
#         recipient = request.form['co_quan_tiep_nhan']

#         new_pending_tx = PendingTransaction(
#             sender=sender, 
#             recipient=recipient, 
#             cccd_details=json.dumps(cccd_details)
#         )
#         db.session.add(new_pending_tx)
#         db.session.commit()

#         flash('CCCD transaction sent for approval.')
#         return redirect(url_for('user_transactions'))
#     return render_template('create_cccd_transaction.html')

def new_cccd_transaction():
    if request.method == 'POST':
        full_name = request.form['full_name']
        date_of_birth = request.form['date_of_birth']
        address = request.form['address']
        gender = request.form['gender']
        phone = request.form['phone']
        request_text = request.form['request']
        nationality = request.form['nationality']
        religion = request.form.get('religion')
        ethnicity = request.form['ethnicity']
        cccd_number_old = request.form['cccd_number']
        receiving_agency = request.form['receiving_agency']

        # # Chuyển đổi date_of_birth từ chuỗi sang đối tượng datetime.date
        # try:
        #     date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
        # except ValueError:
        #     flash('Ngày sinh không hợp lệ. Vui lòng nhập lại.')
        #     return redirect(url_for('new_cccd_transaction'))

        # Tạo giao dịch mới
        new_tx = PendingTransaction(
            sender=current_user.get_username(),
            recipient=receiving_agency,
            cccd_details=json.dumps({
                "date_of_birth": date_of_birth,
                "address": address,
                "gender": gender,
                "phone": phone,
                "request": request_text,
                "nationality": nationality,
                "religion": religion,
                "ethnicity": ethnicity,
                "cccd_number": cccd_number_old
            })
        )

        # Thêm vào cơ sở dữ liệu
        db.session.add(new_tx)
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
            'gender': request.form['passport_gender'],
            'nationality': request.form['passport_nationality'],
            'ethnicity': request.form['passport_ethnicity'],
            'religion': request.form['passport_religion'],
            'address': request.form['passport_address'],
            'temp_address': request.form['passport_temp_address'],
            'occupation': request.form['passport_occupation'],
            'employer': request.form['passport_employer'],
            'father_name': request.form['passport_father_name'],
            'mother_name': request.form['passport_mother_name'],
            'spouse_name': request.form['passport_spouse_name'],
            'old_passport': request.form['passport_old_passport'],
            'content': request.form['passport_content'],
            'passport_number': generate_unique_number('HC'),
            'phone': request.form['passport_phone'],
            'email': request.form['passport_email']
        }
        # sender = 
        receiving_agency = request.form['receiving_agency']
        new_pending_tx = PendingTransaction(
            sender=current_user.get_username(),
            recipient=receiving_agency,
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
    filter_type = request.args.get('filter', 'all')
    # Lấy danh sách giao dịch đang chờ xử lý từ cơ sở dữ liệu
    if filter_type == 'cccd':
        pending_transactions = PendingTransaction.query.filter(PendingTransaction.cccd_details.isnot(None)).all()
    elif filter_type == 'passport':
        pending_transactions = PendingTransaction.query.filter(PendingTransaction.passport_details.isnot(None)).all()
    else:
        pending_transactions = PendingTransaction.query.all()  # Thay thế bằng truy vấn thực tế của bạn

    if request.method == 'POST':
        action = request.form.get('action')
        tx_id = request.form.get('tx_id')
        pending_tx = PendingTransaction.query.get(tx_id)

        if action == 'approve' and pending_tx:
            blockchain.new_transaction(
                sender=pending_tx.sender,
                recipient=pending_tx.recipient,
                cccd_details=json.loads(pending_tx.cccd_details) if pending_tx.cccd_details else None,
                passport_details=json.loads(pending_tx.passport_details) if pending_tx.passport_details else None, 
                timestamp = pending_tx.timestamp
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
    for i in range(len(pending_transactions)):
        pending_transactions[i].timestamp = datetime.fromtimestamp(pending_transactions[i].timestamp).strftime('%d/%m/%Y %H:%M:%S')
    # print(pending_transactions)
    # pending_transactions.timestamp = datetime.fromtimestamp(pending_transactions.timestamp)
    return render_template('pending_transactions.html', transactions=pending_transactions)
@app.route('/transaction/<string:type_data>/<int:tx_id>', methods=['GET'])
@login_required
def transaction_detail(type_data, tx_id):
    if type_data == "pending":
        # Lấy giao dịch từ cơ sở dữ liệu dựa trên ID
        transaction = PendingTransaction.query.get_or_404(tx_id)
    else:
        # Lấy giao dịch từ cơ sở dữ liệu dựa trên ID
        transaction = Transaction.query.get_or_404(tx_id)
    
    # # Định dạng lại timestamp
    transaction.timestamp = datetime.fromtimestamp(transaction.timestamp).strftime('%d/%m/%Y %H:%M:%S')
    
    # Giải mã JSON chi tiết CCCD hoặc Passport
    if transaction.cccd_details :
        transaction.cccd_details = json.loads(transaction.cccd_details)
    if transaction.passport_details:
        transaction.passport_details = json.loads(transaction.passport_details)
    
    return render_template('transaction_detail.html', transaction=transaction)

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
                    'timestamp': block.timestamp, 
                    'id': tx.id
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
                'timestamp': block.timestamp, 
                'id': tx.id
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

