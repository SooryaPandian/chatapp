from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'
socketio = SocketIO(app)

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")
db = client['chat_db']
users_collection = db['users']
groups_collection = db['groups']
messages_collection = db['messages']

# Home Route
@app.route('/')
def index():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        if users_collection.find_one({"username": username}):
            return 'Username already taken!'

        # Store hashed password
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"username": username, "password": hashed_password, "groups": []})
        return redirect(url_for('login'))

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            return 'Invalid credentials'

    return render_template('login.html')

# Chat Route - Displays available groups and all users except the current user
@app.route('/chat', methods=['GET'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    all_users = users_collection.find({"username": {"$ne": username}}, {"username": 1, "_id": 0})
    user_groups = users_collection.find_one({"username": username})['groups']
    
    # Retrieve all users except the current user

    return render_template('chat.html', username=username, user_groups=user_groups, all_users=all_users)

# Create Group Route
@app.route('/create_group', methods=['POST'])
def create_group():
    if 'username' not in session:
        return redirect(url_for('login'))

    creator_username = session['username']
    group_name = request.form['group']
    selected_users = request.form.getlist('selected_users')
    selected_users.append(creator_username)

    # Check if the group name already exists
    if groups_collection.find_one({"group_name": group_name}):
        return 'Group name already exists!'

    # Insert group into the DB with all selected users including the creator
    groups_collection.insert_one({"group_name": group_name, "members": selected_users})

    # Update each user's group list to include the new group
    for user in selected_users:
        users_collection.update_one({"username": user}, {"$push": {"groups": group_name}})

    return redirect(url_for('chat'))

# Search User Route
@app.route('/search_user', methods=['GET'])
def search_user():
    query = request.args.get('q')
    users = users_collection.find({"username": {"$regex": query, "$options": "i"}})
    return jsonify([user['username'] for user in users])

# Group Chat Route
# Group Chat Route
@app.route('/group_chat/<group_name>', methods=['GET'])
def group_chat(group_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users_collection.find_one({"username": username})
    username = session['username']
    all_users = users_collection.find({"username": {"$ne": username}}, {"username": 1, "_id": 0})
    if group_name not in user['groups']:
        return "You do not have access to this group!"

    # Retrieve the group and its messages
    group = groups_collection.find_one({"group_name": group_name})
    messages = group.get("messages", []) if group else []

    return render_template('group_chat.html', group_name=group_name, username=username, messages=messages,all_users=all_users)


# WebSocket Events
@socketio.on('join')
def on_join(data):
    username = data.get('username')
    group_name = data.get('group_name')  # Use group_name as the room identifier
    print("User "+username+" joined "+"")
    if username and group_name:
        join_room(group_name)  # Join the specified group's room
        send(f"{username} has joined the group {group_name}.", to=group_name)

@socketio.on('leave')
def on_leave(data):
    username = data.get('username')
    group_name = data.get('group_name')

    if username and group_name:
        leave_room(group_name)
        send(f"{username} has left the group {group_name}.", to=group_name)

@socketio.on('message')
def handle_message(data):
    group_name = data.get('group_name')
    message = data.get('message')
    username = data.get('username')

    if group_name and message and username:
        # Create a message object with formatted timestamp
        timestamp = datetime.utcnow()
        message_object = {
            "username": username,
            "timestamp":timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "content": message
        }

        # Append the message to the 'messages' array in the group's document
        groups_collection.update_one(
            {"group_name": group_name},
            {"$push": {"messages": message_object}}
        )

        # Emit the message to the specified group room with formatted timestamp
        send({
            "message": message,
            "username": username,
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }, to=group_name)


if __name__ == '__main__': 
    socketio.run(app, debug=True)
