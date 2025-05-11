from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        if user:
            if user['needsPasswordChange']:
                session['user_id'] = user['id']
                return redirect(url_for('change_password'))
            else:
                session['user_id'] = user['id']
                return redirect(url_for('home'))
        else:
            flash('帳號或密碼錯誤')
    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('兩次密碼不一致')
        else:
            conn = get_db_connection()
            conn.execute('UPDATE users SET password = ?, needsPasswordChange = 0 WHERE id = ?', (new_password, session['user_id']))
            conn.commit()
            conn.close()
            flash('密碼更新成功')
            return redirect(url_for('home'))
    return render_template('change_password.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)
