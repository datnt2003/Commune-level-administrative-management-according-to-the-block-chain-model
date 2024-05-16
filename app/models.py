
from flask_login import UserMixin
from time import time
from . import db
import hashlib
import json
from werkzeug.security import generate_password_hash, check_password_hash

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, password_hash, is_admin=False):
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

    def get_username(self):
        return self.username

    def set_username(self, username):
        self.username = username

    def get_is_admin(self):
        return self.is_admin

    def set_is_admin(self, is_admin):
        self.is_admin = is_admin

    def __repr__(self):
        return f'<User {self.username}>'


class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    transaction_data = db.Column(db.Text, nullable=False)
    proof = db.Column(db.Integer, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)

    def get_id(self):
        return self.id

    def get_index(self):
        return self.index

    def get_timestamp(self):
        return self.timestamp

    def get_transaction_data(self):
        return self.transaction_data

    def set_transaction_data(self, transaction_data):
        self.transaction_data = transaction_data

    def get_proof(self):
        return self.proof

    def set_proof(self, proof):
        self.proof = proof

    def get_previous_hash(self):
        return self.previous_hash

    def set_previous_hash(self, previous_hash):
        self.previous_hash = previous_hash

    def __repr__(self):
        return f'<Block {self.index}>'


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=False)
    cccd_details = db.Column(db.Text, nullable=True)
    passport_details = db.Column(db.Text, nullable=True)
    block_id = db.Column(db.Integer, db.ForeignKey('block.id'), nullable=False)
    block = db.relationship('Block', backref=db.backref('transactions_list', lazy=True))

    def get_id(self):
        return self.id

    def get_sender(self):
        return self.sender

    def set_sender(self, sender):
        self.sender = sender

    def get_recipient(self):
        return self.recipient

    def set_recipient(self, recipient):
        self.recipient = recipient

    def get_cccd_details(self):
        return self.cccd_details

    def set_cccd_details(self, cccd_details):
        self.cccd_details = cccd_details

    def get_passport_details(self):
        return self.passport_details

    def set_passport_details(self, passport_details):
        self.passport_details = passport_details

    def get_block_id(self):
        return self.block_id

    def set_block_id(self, block_id):
        self.block_id = block_id

    def __repr__(self):
        return f'<Transaction {self.id} from {self.sender} to {self.recipient}>'


class PendingTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=False)
    cccd_details = db.Column(db.Text, nullable=True)
    passport_details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.Float, default=time, nullable=False)

    def get_id(self):
        return self.id

    def get_sender(self):
        return self.sender

    def set_sender(self, sender):
        self.sender = sender

    def get_recipient(self):
        return self.recipient

    def set_recipient(self, recipient):
        self.recipient = recipient

    def get_cccd_details(self):
        return self.cccd_details

    def set_cccd_details(self, cccd_details):
        self.cccd_details = cccd_details

    def get_passport_details(self):
        return self.passport_details

    def set_passport_details(self, passport_details):
        self.passport_details = passport_details

    def get_timestamp(self):
        return self.timestamp

    def set_timestamp(self, timestamp):
        self.timestamp = timestamp

    def __repr__(self):
        return f'<PendingTransaction {self.id} from {self.sender} to {self.recipient}>'


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = block_id = db.Column(db.String(80), db.ForeignKey('User.username'), nullable=False)
    timestamp = db.Column(db.Float, nullable=False)

    def get_id(self):
        return self.id

    def get_title(self):
        return self.title

    def set_title(self, title):
        self.title = title

    def get_content(self):
        return self.content

    def set_content(self, content):
        self.content = content

    def get_author(self):
        return self.author

    def get_timestamp(self):
        return self.timestamp

    def set_timestamp(self, timestamp):
        self.timestamp = timestamp

    def __repr__(self):
        return f'<News {self.title} by {self.author}>'

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.load_chain()

    def load_chain(self):
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
                                          cccd_details=json.dumps(tx['cccd_details']) if tx['cccd_details'] else None,
                                          passport_details=json.dumps(tx['passport_details']) if tx['passport_details'] else None,
                                          block_id=new_block.id)
            db.session.add(new_transaction)

        db.session.commit()
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, cccd_details=None, passport_details=None):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'cccd_details': cccd_details,
            'passport_details': passport_details
        })
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
