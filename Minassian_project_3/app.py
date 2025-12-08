from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from datetime import timedelta
from flask_socketio import SocketIO, emit, disconnect
from flask_wtf.csrf import CSRFProtect
import os


app = Flask(__name__)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)

# Set a secret key for session management
app.secret_key = os.urandom(24)  # Generate a random secret key

app.permanent_session_lifetime = timedelta(minutes=3)  # Set session lifetime to 10 minutes

app.config.update(
    SESSION_COOKIE_SECURE=True     # Ensure cookies are only sent over HTTPS
)


client = MongoClient("mongodb://localhost:27017/")
db = client['user_database']
users_collection = db['users']
wallets_collection = db['wallets']

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/secret_page')
def secret():
    if 'username' not in session:
        return redirect(url_for('login_page'))  # Redirect to login if not authenticated
    
    return render_template('secret.html', username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form  # Changed to use form data
        username = data.get('username')
        password = data.get('password')

        if users_collection.find_one({"username": username}):
            return jsonify({'message': 'User already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {"username": username, "password_hash": hashed_password}
        users_collection.insert_one(user)

        # Redirect to the login page after successful registration
        return redirect(url_for('login_page'))

    # Render the registration form for GET requests
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')

        user = users_collection.find_one({"username": username})

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session.permanent = True  # Enable permanent sessions
            session['username'] = username
            return redirect(url_for('index'))

        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Render the login form for GET requests
    return render_template('login.html')

# Route to show Create Wallet form (only accessible if logged in)
@app.route('/create_wallet_page', methods=['GET'])
def create_wallet_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))  # Redirect to login if not logged in

    # Render the wallet creation page
    return render_template('create_wallet.html', username=session['username'])

# Function to create a wallet (requires user to be logged in)
@app.route('/create_wallet', methods=['POST'])
def create_wallet():
    if 'username' not in session:
        return redirect(url_for('login_page'))  # Redirect to login if not logged in
    
    initial_balance = request.form.get('initial_balance', '0')

    if 'e' in initial_balance.lower():
        return "Scientific Notation is not allowed.", 400
    # TODO: Add input validation for the amount. Make sure the user is giving 
    # a number and the value is >= 0.
    try:
        initial_balance = float(initial_balance)
        if initial_balance < 0:
            raise ValueError("Initial balance cannot be negative.")
    except ValueError as e:
        return str(e), 400

    # Check if the wallet already exists for the logged-in user
    existing_wallet = wallets_collection.find_one({"username": session['username']})
    if existing_wallet:
        return f"Wallet already exists for {session['username']}."

    # Create wallet for the user
    wallet = {"username": session['username'], "balance": float(initial_balance)}
    wallets_collection.insert_one(wallet)

    return redirect(url_for('index'))  # Redirect to home page after wallet creation


@app.route('/show_wallet', methods=['GET'])
def show_wallet():
    if 'username' not in session:
        return redirect(url_for('login_page'))  # Redirect to login if not logged in

    # Fetch user's wallet information
    # TODO: Fetch the wallet from wallets_collection for this username and 
    # assign the value to wallet variable. Check create_wallet function to get some hints.
    # We use wallet variable in this function in different places. 
    wallet = wallets_collection.find_one({"username": session['username']})
    
    if not wallet:
        return "Wallet does not exist. Please create one first.", 404

    balance = wallet['balance']
    return render_template('show_wallet.html', username=session['username'], balance=balance)

@app.route('/add_money', methods=['GET', 'POST'])
def add_money():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    # For GET request: Display the current wallet balance
    if request.method == 'GET':
        wallet = wallets_collection.find_one({"username": session['username']})
        if not wallet:
            return "Wallet does not exist. Please create one first.", 404

        return render_template(
            'add_money.html',
            balance=wallet['balance'], 
            username=session['username'],
            success=None,
            error=None
        )

    # For POST request: Process adding money
    if request.method == 'POST':
        
        amount = request.form.get('amount')
        if 'e' in amount.lower():
            return "Scientific Notation is not allowed.", 400
        if not amount or float(amount) <= 0:
            wallet = wallets_collection.find_one({"username": session['username']})
            return render_template(
                'add_money.html',
                balance=wallet['balance'], 
                username=session['username'],
                error="Invalid amount. Please enter a positive number.",
                success=None
            )

        wallets_collection.update_one(
            {"username": session['username']},
            {"$inc": {"balance": float(amount)}}
        )

        return redirect(url_for('index'))

@app.route('/transfer_money', methods=['GET', 'POST'])
def transfer_money():
    # TODO: add a session check. If the user is not logged in send them to the login page.
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    # For GET request: Display the transfer money form
    if request.method == 'GET':
        wallet = wallets_collection.find_one({"username": session['username']})
        if not wallet:
            return "Wallet does not exist. Please create one first.", 404

        return render_template(
            'transfer_money.html',
            balance=wallet['balance'], 
            username=session['username'],
            success=None,
            error=None
        )

    # For POST request: Process the transfer
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        amount = request.form.get('amount')
        if 'e' in amount.lower():
            return "Scientific Notation is not allowed.", 400

        if not amount or float(amount) <= 0:
            wallet = wallets_collection.find_one({"username": session['username']})
            return render_template(
                'transfer_money.html',
                balance=wallet['balance'],
                username=session['username'],
                error="Invalid amount. Please enter a positive number.",
                success=None
            )
        try:
            amount = float(amount)  # Naively converting input to float
            if 'e' in str(amount).lower():
                return "Scientific Notation is not allowed.", 400
        except ValueError:
            return "Invalid amount format.", 400
        
        if amount <= 0:
            return "Amount must be greater than zero.", 400
        # Check if the sender has enough balance
        sender_wallet = wallets_collection.find_one({"username": session['username']})
        # TODO: Add lines to redirect to transfer_money page and display a message
        # that the balance is insufficient. You can follow the previous render_template
        # call to show invalid amount.
        if sender_wallet['balance'] < amount:
             return render_template(
                'transfer_money.html',
                balance=wallet['balance'],
                username=session['username'],
                error="Insufficient balance for this transfer.",
                success=None
             )
        # Check if the recipient exists
        recipient_wallet = wallets_collection.find_one({"username": recipient_username})
        if not recipient_wallet:
            return render_template(
                'transfer_money.html',
                balance=sender_wallet['balance'],
                username=session['username'],
                error=f"No wallet found for recipient '{recipient_username}'.",
                success=None
            )

        wallets_collection.update_one(
            {"username": session['username']},  # Deduct from sender
            {"$inc": {"balance": -amount}}
        )
        wallets_collection.update_one(
            {"username": recipient_username},  # Add to recipient
            {"$inc": {"balance": amount}}
        )

        return render_template(
            'transfer_money.html',
            balance=sender_wallet['balance'] - amount,
            username=session['username'],
            success=f"Successfully transferred ${amount} to {recipient_username}.",
            error=None
        )

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    # Redirect to the login page after logging out
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    # Run HTTP and HTTPS servers in parallel using threading
    socketio.run(app, host='127.0.0.1', port=3009)
