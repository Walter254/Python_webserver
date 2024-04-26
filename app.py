from flask import Flask, request, jsonify, render_template
import logging
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from db import get_db
from flask_socketio import SocketIO, emit

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'cH1j6Q3fVTVyXs3n9AHxW805X7cgJo5L0z6V0cyWR9D30XktO23EY2ia9Hj8SudHpYZWeiTlwWvv6mO2Cv22Eg' 
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def home():
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
    return render_template('color.html', color='red', message='Your color is red!')

@app.route('/green')
def green():
    return render_template('color.html', color='green', message='Your color is green!')

@app.route('/register', methods=['POST'])
def register():
    db = get_db()
    users = db.users 
    username = request.json.get('username')
    password = request.json.get('password')
    if users.find_one({"username": username}):
        logging.warning("Attempt to register with an existing username: {}".format(username))
        return jsonify({"msg": "Username already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users.insert_one({"username": username, "password": hashed_password})
    logging.info("User registered successfully: {}".format(username))
    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    db = get_db()
    users = db.users
    username = request.json.get('username')
    password = request.json.get('password')
    user = users.find_one({"username": username})
    
    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=username)
        logging.info("User logged in successfully: {}".format(username))
        return jsonify(access_token=access_token), 200
    else:
        logging.warning("Invalid login attempt for username: {}".format(username))
        return jsonify({"msg": "Invalid username or password"}), 401

@app.route('/ee129')
def ee129():
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