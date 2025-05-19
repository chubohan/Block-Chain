from flask import Blueprint, render_template, request, redirect, flash, url_for, session, jsonify
from flask_login import login_user, login_required, logout_user, current_user, LoginManager, UserMixin
from werkzeug.security import generate_password_hash
import bcrypt
import re
from itsdangerous import TimedSerializer, SignatureExpired
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer
import random

from utils import db




# 產生藍圖
user_bp = Blueprint('user', __name__)

# config.py
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = '11056028@ntub.edu.tw'        # 你自己的發信信箱
MAIL_PASSWORD = 'illu pozd sgco nfxl'                   # 注意：不是 Gmail 密碼，而是「App 密碼」
MAIL_DEFAULT_SENDER = '11056028@ntub.edu.tw'

# 設定郵件
mail = Mail()

#產生登入管理物件
login_manager = LoginManager()

#定義使用者類別
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

def send_verification_email(email, verify_url):
    msg = Message('帳號驗證', sender='your_email@gmail.com', recipients=[email])
    msg.body = f'請點擊以下連結驗證您的帳戶：\n{verify_url}'
    mail.send(msg)

def send_reset_email(email, reset_link):
    html_content = render_template('email/reset_password.html', reset_link=reset_link)
    msg = Message('重設密碼請求', sender='your_email@gmail.com', recipients=[email])
    msg.html = html_content
    mail.send(msg)

def generate_verification_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_verification_code_email(email, code):
    msg = Message('您的登入驗證碼', recipients=[email])
    msg.body = f'您好，您的驗證碼為：{code}\n請於 10 分鐘內完成輸入。'
    mail.send(msg)

#載入使用者
@login_manager.user_loader
def load_user(user_id):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT userno, username, password FROM user WHERE userno = %s", (user_id,))
    result = cursor.fetchone()  # 字典形式
    conn.close()

    if result:
        return User(
            id=result['userno'],      # 使用字段名
            username=result['username'],
            password=result['password']
        )
    return None

#宣告註冊畫面
@user_bp.route('/signup/form')
def user_signup_form():
    return render_template('user/signup_form.html')


# 使用者註冊
@user_bp.route('/signup', methods=['GET','POST'])
def signup():
    try:
        # 取得使用者的輸入值
        username = request.form.get('username')
        age=request.form.get('age')
        gender=request.form.get('gender')
        gmail = request.form.get('gmail')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        print(username,age,gender,gmail,password1,password2)

        # 檢查必填字段
        if not all([username, gmail, password1, password2]):
            return render_template('user/signup.html', success=False, message="所有欄位皆為必填")

        # 驗證密碼一致性
        if password1 != password2:
            return render_template('user/signup.html', success=False, message="密碼不一致")
        
        # 生成密碼哈希
        password_bytes = password1.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')

        # Gmail 限制：只允許 @gmail.com 結尾
        if not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', gmail):
            return render_template('user/signup.html', success=False, message="請輸入有效的 Gmail 格式（必須是 @gmail.com）")

        # 密碼強度檢查
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', password1):
            return render_template('user/signup.html', success=False, message="密碼需包含大小寫英文、數字與特殊符號，且長度至少8位")

        # 寫入資料庫
        conn = db.get_connection()
        if conn is None:
            return render_template('user/signup.html', success=False, message="資料庫連接失敗")

        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (username, age, gender, password, gmail) VALUES (%s, %s, %s,%s,%s)",
            (username,age,gender ,hashed_password, gmail)
        )
        conn.commit()
        conn.close()

        # 寄送驗證信
        s = TimedSerializer('secret_key')
        token = s.dumps(gmail, salt='email-confirm')
        verify_url = url_for('user.verify_email', token=token, _external=True)
        send_verification_email(gmail, verify_url)

        flash('註冊成功，請到 Gmail 完成驗證後再登入。', 'info')
        return render_template('user/signup.html', success=True)


    except Exception as e:
        print(f"Database connection error: {str(e)}")
        return render_template('user/signup.html', success=False, message="資料庫連接失敗")

    
@user_bp.route('/login/form')
def login_form_index():
    return render_template('user/login_form.html')

@user_bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    gmail=request.form.get('gmail')
    password = request.form.get('password')

    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT userno, username, password,gmail, is_verified FROM user WHERE username = %s and gmail=%s", (username,gmail,))
    result = cursor.fetchone()

    if not result:
        return render_template('user/login.html', success=False, message="帳號不存在")

    stored_hash_str = result['password']
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash_str.encode('utf-8')):
        if not result['is_verified']:
            # 產生並寄送驗證碼
            code = generate_verification_code()
            session['pending_verification'] = {
                'username': username,
                'gmail': result['gmail'],
                'code': code
            }
            send_verification_code_email(result['gmail'], code)
            return redirect(url_for('user.verify_code_form'))
        
        # 登入成功
        user = User(id=result['userno'], username=result['username'], password=result['password'])
        login_user(user)
        return redirect('/')
    else:
        return render_template('user/login.html', success=False, message="密碼錯誤")
    
#使用者登出
@user_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/user/login/form')

# 忘記密碼路由

# 重設密碼路由
@user_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        s = TimedSerializer('secret_key')
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1小時過期
    except SignatureExpired:
        flash('這個鏈接已過期！', 'danger')
        return redirect(url_for('user.forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        # 更新密碼
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE user SET password = %s WHERE gmail = %s", 
                       (generate_password_hash(new_password), email))
        conn.commit()
        conn.close()

        flash('密碼已成功重設！', 'success')
        return redirect(url_for('user.login_form_index'))
    
    return render_template('/user/reset_password.html')

@user_bp.route('/verify/<token>')
def verify_email(token):
    try:
        s = TimedSerializer('secret_key')
        email = s.loads(token, salt='email-confirm', max_age=3600)  # 1 小時內有效
    except SignatureExpired:
        flash('驗證連結已過期，請重新註冊或聯繫管理員。', 'danger')
        return redirect(url_for('user.user_signup_form'))

    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE user SET is_verified = TRUE WHERE gmail = %s", (email,))
    conn.commit()
    conn.close()

    flash('帳戶驗證成功，請登入。', 'success')
    return redirect(url_for('user.login_form_index'))

@user_bp.route('/resend_verification', methods=['GET'])
@login_required  # 確保用戶已經登入
def resend_verification():
    email = current_user.username  # 假設 Gmail 存在於 username 欄位

    # 檢查該 Gmail 是否已經驗證
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_verified FROM user WHERE gmail = %s", (email,))
    result = cursor.fetchone()
    conn.close()

    if result:
        if result['is_verified']:
            flash('此帳戶已經驗證，請直接登入。', 'info')
        else:
            # 寄送新的驗證信
            s = TimedSerializer('secret_key')
            token = s.dumps(email, salt='email-confirm')
            verify_url = url_for('user.verify_email', token=token, _external=True)
            send_verification_email(email, verify_url)
            flash('驗證信已重新寄出，請查收 Gmail。', 'success')
    else:
        flash('找不到此 Gmail，請確認是否註冊過。', 'danger')

    return redirect(url_for('user.profile'))  # 重定向至使用者資料頁面（或其他適當頁面

@user_bp.route('/verify_code/form')
def verify_code_form():
    return render_template('user/verify_code_form.html')

@user_bp.route('/verify_code', methods=['POST'])
def verify_code():
    input_code = request.form.get('code')
    data = session.get('pending_verification')

    if data and input_code == data['code']:
        # 驗證成功，標記帳號為已驗證
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE user SET is_verified = TRUE WHERE gmail = %s", (data['gmail'],))
        conn.commit()
        conn.close()

        user = User(username=data['gmail'], password=None)
        login_user(user)

        session.pop('pending_verification', None)
        flash('驗證成功，已登入！', 'success')
        return redirect('/')
    else:
        flash('驗證碼錯誤，請重新輸入。', 'danger')
        return redirect(url_for('user.verify_code_form'))
    
@user_bp.route('/complete-profile', methods=['POST'])
@login_required
def complete_profile():
    try:
        age = request.form.get('age')
        gender = request.form.get('gender')
        
        if not age or not gender:
            return jsonify({'success': False, 'error': '必填欄位未填寫'}), 400

        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user 
            SET age = %s, gender = %s 
            WHERE userno = %s
        """, (age, gender, current_user.id))
        conn.commit()
        
        session.pop('needs_profile', None)
        return jsonify({'success': True, 'redirect': url_for('user.profile')})

    except Exception as e:
        print(f"資料補全錯誤: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()