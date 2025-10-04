from flask import Blueprint, render_template, request, redirect, flash, url_for, session, jsonify
from flask_login import login_user, login_required, logout_user, current_user, LoginManager, UserMixin
from werkzeug.security import generate_password_hash
import bcrypt
import re
from itsdangerous import TimedSerializer, SignatureExpired
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer
import random
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from utils import db




# 產生藍圖
user_bp = Blueprint('user', __name__)

# config.py
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USE_SSL = False
MAIL_USERNAME = '11056028@ntub.edu.tw'        # 你自己的發信信箱
MAIL_PASSWORD = 'rfdaigqbrtnhobye'    #zzjp cahb gwrt dgrm              # 注意：不是 Gmail 密碼，而是「App 密碼」
MAIL_DEFAULT_SENDER = '11056028@ntub.edu.tw'

# 設定郵件
mail = Mail()

#產生登入管理物件
login_manager = LoginManager()

#定義使用者類別
class User(UserMixin):
    def __init__(self, id, username, password, insurance_officer=None):
        self.id = id
        self.username = username
        self.password = password
        self.insurance_officer = insurance_officer 

def send_verification_email(email, verify_url):
    # 不要手動寫 sender，讓它自動使用 MAIL_DEFAULT_SENDER
    msg = Message('帳號驗證', recipients=[email])
    
    # 建議改用 HTML 模板（看起來更專業），如果暫時要用純文字也可以
    msg.body = f'請點擊以下連結驗證您的帳戶：\n{verify_url}'
    
    mail.send(msg)

def send_reset_email(email, reset_link):
    # ✅ 注意這裡改成 reset_url
    html_content = render_template('email/reset_password.html', reset_url=reset_link)

    # ✅ sender 改成用預設，不要寫死 Gmail
    msg = Message('重設密碼請求', recipients=[email])

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
    cursor.execute("""
        SELECT gmail, username, password, insurance_officer 
        FROM user 
        WHERE gmail = %s
    """, (user_id,))
    result = cursor.fetchone()  # 字典形式
    conn.close()

    if result:
        return User(
            id=result['gmail'],      # 使用字段名
            username=result['username'],
            password=result['password'],
            insurance_officer=result['insurance_officer']  # 新增這行
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
        age = request.form.get('age')
        gender = request.form.get('gender')
        gmail = request.form.get('gmail')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        insurance_officer = request.form.get('insurance_officer', 0)  # 預設 0
        wallet = request.form.get('wallet')

        print(username, age, gender, gmail, password1, password2, insurance_officer, wallet)

        # 檢查必填字段
        if not all([username, gmail, password1, password2, insurance_officer, wallet]):
            return render_template('user/signup.html', success=False, message="所有欄位皆為必填")

        # 驗證密碼一致性
        if password1 != password2:
            return render_template('user/signup.html', success=False, message="密碼不一致")

        # 生成密碼哈希
        password_bytes = password1.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')

        # 寫入資料庫
        conn = db.get_connection()
        if conn is None:
            return render_template('user/signup.html', success=False, message="資料庫連接失敗")

        cursor = conn.cursor()
        # 檢查 gmail 是否已存在
        cursor.execute("SELECT gmail FROM user WHERE gmail = %s", (gmail,))
        if cursor.fetchone():
            return render_template('user/signup.html', success=False, message="此 Gmail 已被注冊")

        cursor.execute("""
            INSERT INTO user (username, age, gender, password, gmail, insurance_officer, wallet)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (username, age, gender, hashed_password, gmail, int(insurance_officer), wallet))

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
    gmail = request.form.get('gmail')
    password = request.form.get('password')

    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT gmail, username, password, is_verified, insurance_officer FROM user WHERE gmail=%s", (gmail,))
    result = cursor.fetchone()

    if not result:
        return render_template('user/login.html', success=False, message="此 Gmail 未注冊")

    stored_hash_str = result['password']
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash_str.encode('utf-8')):
        if not result['is_verified']:
            # 產生並寄送驗證碼
            code = generate_verification_code()
            session['pending_verification'] = {
                'username': result['username'],
                'gmail': result['gmail'],
                'code': code
            }
            send_verification_code_email(result['gmail'], code)
            return redirect(url_for('user.verify_code_form'))
        
        # 登入成功
        user = User(id=result['gmail'], 
                   username=result['username'], 
                   password=result['password'],
                   insurance_officer=result['insurance_officer'])  # 新增這行
        
        login_user(user)
        return redirect('/')
    else:
        return render_template('user/login.html', success=False, message="密碼錯誤")


# 忘記密碼路由
@user_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')  # 對應表單欄位
        if not email:
            flash('請輸入電子郵件', 'danger')
            return redirect(url_for('user.forgot_password'))

        # 查詢使用者
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT gmail FROM user WHERE gmail = %s", (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash('此電子郵件尚未註冊', 'danger')
            return redirect(url_for('user.forgot_password'))

        # 產生重設密碼 token
        s = TimedSerializer('secret_key')  # 建議使用 app.secret_key
        token = s.dumps(email, salt='password-reset')
        ngrok_url = "https://nonscaling-ocellar-brian.ngrok-free.dev"
        reset_link = f"{ngrok_url}{url_for('user.reset_password', token=token)}"

        # 寄送重設信件
        send_reset_email(email, reset_link)
        flash('重設密碼信件已寄送，請檢查您的電子郵件', 'success')
        return redirect(url_for('user.login_form_index'))

    return render_template('user/forgot_password.html')

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
    
    return render_template('user/reset_password.html')

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

        user = User(id=data['gmail'],username=data['username'], password=None)
        login_user(user)

        session.pop('pending_verification', None)
        flash('驗證成功，已登入！', 'success')
        return redirect('/')
    else:
        flash('驗證碼錯誤，請重新輸入。', 'danger')
        return redirect(url_for('user.verify_code_form'))
#------------------------------------
#google登入    
# 配置 Google 客户端 ID（从环境变量获取）
# 從 Google Cloud Console 獲取的客戶端 ID
GOOGLE_CLIENT_ID = '551019375208-ee9n8eg06kg6v7chg9k8h7p98luc4p63.apps.googleusercontent.com'

# Google 登录路由（移动到 user_bp 蓝图中）
@user_bp.route('/auth/google', methods=['POST'])
def auth_google():
    token = request.json.get('credential')
    
    try:
        # 验证 Google ID token
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        if not idinfo:
            raise ValueError("Google token verification failed")
        # 验证客户端 ID
        if idinfo['aud'] != GOOGLE_CLIENT_ID:
            return jsonify({'success': False, 'error': 'Invalid client ID'}), 401

        # 提取关键信息
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', '')
        picture = idinfo.get('picture', '')

        required_fields = ['sub', 'email']
        if not all(field in idinfo for field in required_fields):
            raise ValueError(f"Missing fields in Google response: {required_fields}")

        # 数据库操作
        conn = db.get_connection()
        cursor = conn.cursor()

        # 检查用户是否存在
        cursor.execute("""
            SELECT age, gender, google_id 
                FROM user 
                WHERE gmail = %s
        """, (email,))
        user = cursor.fetchone()
        
        is_new_user = False
        needs_profile = False

        if user:
            # 已存在用戶：檢查資料完整性
            needs_profile = user.get('age') is None or user.get('gender') is None
            # 已存在用户：更新 google_id（如果尚未关联）
            if not user['google_id'] or user['google_id'] != google_id:
                cursor.execute("""
                    UPDATE user 
                    SET google_id = %s 
                    WHERE gmail = %s
                """, (google_id, email))
                conn.commit()
        else:
            # 新用户：创建基础记录
            cursor.execute("""
                INSERT INTO user 
                (gmail, google_id, username, age, gender) 
                VALUES (%s, %s, %s, NULL, NULL)
            """, (email, google_id, name))
            conn.commit()
            is_new_user = True
            needs_profile = True

        conn.close()

        flask_user = User(id=email, username=name, password=None)
        login_user(flask_user)
        
        # 統一返回 JSON 格式
        if needs_profile:
            session['needs_profile'] = True
            return jsonify({
                'success': True,
                'redirect': url_for('user.complete_profile_form')
            })
        
        return jsonify({
            'success': True,
            'redirect': '/'  # 关键修改点
        })

    except Exception as e:
        print(f"Google 登录错误: {str(e)}")
        return jsonify({
            'success': False,
            'error': '認證失败'
        }), 401

# 补全资料表单页面
@user_bp.route('/complete-profile/form')
@login_required
def complete_profile_form():
    if not session.get('needs_profile'):
        return redirect(url_for('main.index'))
    return render_template('user/complete_profile.html')

# 修改后的补全资料提交处理
@user_bp.route('/complete-profile', methods=['POST'])
@login_required
def complete_profile():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求格式'}), 400

        age = data.get('age')
        gender = data.get('gender')
        
        # 字段存在性检查
        if age is None or gender is None:
            return jsonify({'success': False, 'error': '所有資料必填'}), 400

        # 年龄转换与验证
        try:
            age = int(age)
            if not (18 <= age <= 120):
                return jsonify({'success': False, 'error': '年齡需為 18-120 之間的整數'}), 400
        except ValueError:
            return jsonify({'success': False, 'error': '年齡需為有效數字'}), 400

        # 性别验证
        gender = gender.strip().lower()
        if gender not in ['male', 'female', 'other']:
            return jsonify({'success': False, 'error': '無效的性别選項'}), 400

        # 获取数据库连接
        conn = db.get_connection()
        if conn is None:
            return jsonify({'success': False, 'error': '資料庫連接失敗'}), 500
            
        cursor = conn.cursor()
        
        try:
            # 先检查用户是否存在
            cursor.execute("SELECT 1 FROM `user` WHERE gmail = %s", (current_user.id,))
            if not cursor.fetchone():
                conn.close()
                return jsonify({'success': False, 'error': '用戶不存在'}), 404

            # 执行更新
            cursor.execute("""
                UPDATE `user` 
                SET age = %s, gender = %s 
                WHERE gmail = %s
            """, (age, gender, current_user.id))
            
            # 提交事务
            conn.commit()
            
            if cursor.rowcount == 0:
                print(f"WARN - 數據未變化: {current_user.id}")
            
        except Exception as e:
            conn.rollback()
            print(f"資料庫操作失败: {str(e)}")
            return jsonify({'success': False, 'error': '資料庫更新失敗'}), 500
        finally:
            conn.close()

        session.pop('needs_profile', None)
        return jsonify({'success': True, 'redirect': url_for('user.profile')})

    except Exception as e:
        print(f"[ERROR] 資料補全失敗: {str(e)}")
        return jsonify({'success': False, 'error': f"伺服器錯誤: {str(e)}"}), 500
# user.py
@user_bp.route('/profile')
@login_required
def profile():
    # 获取用户资料数据
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, age, gender, gmail ,wallet
        FROM user 
        WHERE gmail = %s
    """, (current_user.id,))
    user_data = cursor.fetchone()
    conn.close()

    return render_template('user/profile.html', user=user_data)

# 登出路由
@user_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('您已成功登出', 'success')
    return render_template('index.html')