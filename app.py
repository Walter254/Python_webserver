from flask import Flask, request, jsonify, render_template
from bcrypt import hashpw, gensalt, checkpw
import logging
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from db import get_db
from flask_socketio import SocketIO, emit
from flask import Flask, session, redirect, url_for, request, render_template

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'cH1j6Q3fVTVyXs3n9AHxW805X7cgJo5L0z6V0cyWR9D30XktO23EY2ia9Hj8SudHpYZWeiTlwWvv6mO2Cv22Eg' 
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Encode to bytes
        db = get_db()

        if db is None:
            return render_template('error.html', error="Database connection error.")

        users_collection = db['users']  # Access the users collection
        user = users_collection.find_one({"username": username})

        if user and checkpw(password, user['password'].encode('utf-8')):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error="Passwords must match.")

        db = get_db()
        if db is None:
            return render_template('error.html', error="Database connection error.")

        users_collection = db['users']  # Access the users collection
        if users_collection.find_one({"username": username}):
            return render_template('register.html', error='Username already exists')

        hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
        users_collection.insert_one({"username": username, "password": hashed_password})
        return redirect(url_for('login'))

    return render_template('register.html')

       


def is_logged_in():
    return 'logged_in' in session and session['logged_in']

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    return '', 204


@app.route('/')
def home():
    if not is_logged_in():
        return redirect(url_for('login'))
    Show the home page only if logged in
    page = request.args.get('color')
    if page == 'red':
        return render_template('color.html', color='red-color', message='Your color is red!')
    elif page == 'green':
        return render_template('color.html', color='green-color', message='Your color is green!')
    elif page == 'ee129':
        return render_template('ee129.html')
    elif page == 'chat':
        return render_template('chat.html')
    return render_template('index.html')

@app.route('/red')
def red():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('color.html', color='red', message='Your color is red!')

@app.route('/green')
def green():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('color.html', color='green', message='Your color is green!')

@app.route('/ee129')
def ee129():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('ee129.html')

@app.errorhandler(404)
def page_not_found(e):
    logging.error(f"404 Not Found: {e}")
    return render_template('404.html'), 404

# SocketIO event handlers
@socketio.on('message')
def handle_message(data):
    logging.info('received message: ' + str(data))
    emit('message', data, broadcast=True)

@app.route('/chat')
def chat():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('chat.html')

if __name__ == '__main__':
    from OpenSSL import SSL
    context = ('./cert.pem', './key.pem') 
    try:
        socketio.run(app, debug=True, port=8000, ssl_context=context, use_reloader=False)  
        logging.info("Server started successfully on port 8000 with SSL.")
    except Exception as e:
        logging.error(f"Failed to start the server due to: {e}")
        logging.error(e, exc_info=True)