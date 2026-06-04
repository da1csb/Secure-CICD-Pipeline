from flask import Flask, request 
import subprocess
import sqlite3 

app = Flask(__name__)

# Hardcore secret - Gitleaks will catch this
SECRET_KEY = "aws_secret_key_1234567890abcdef"

@app.route('/')
def home():
    return "Hello from the secure CI/CD demo app"

@app.route('/search')
def search():
    # SQL injection vulnerability - intentional for demo
    query = request.args.get('q', '')
    conn = sqlite3.connect('demo.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return str(cursor.fetchall())

@app.route('/ping')
def ping():
    # Command injection vulnerability - intentional for demo
    host = reques.args.get('host', 'localhost')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()

if __name__ == '__main__':
    app.run(debug=True)
