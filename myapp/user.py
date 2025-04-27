from flask import Blueprint, render_template, request, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt

from utils import db

#產生藍圖
user_bp = Blueprint('user', __name__)



#定義使用者類別
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

#產生登入管理物件
login_manager = LoginManager()

#定義使用者類別
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

#產生登入管理物件
login_manager = LoginManager()

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

#使用者註冊
#宣告註冊畫面
@user_bp.route('/signup/form')
def user_signup_form():
    return render_template('user/signup_form.html')


#使用者註冊
@user_bp.route('/signup', methods=['POST'])
def signup():
    try:
        # 取得使用者的輸入值
        userno = request.form.get('userno')
        username = request.form.get('username')
        gmail=request.form.get('gmail')
        password = request.form.get('password1')
        
        
        # 加密密碼
        hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_str = hashed_bytes.decode('utf-8')  # 轉為字串

        # 寫入資料庫
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (userno, username, password,gmail) VALUES (%s, %s, %s ,%s)",
                       (userno, username, hashed_str,gmail))
        conn.commit()
        conn.close()
        
        return render_template('user/signup.html', success=True)
    except Exception as e:
        # 打印詳細錯誤訊息到控制台
        print(f"Database connection error: {str(e)}")
        return render_template('user/signup.html', success=False, message="資料庫連接失敗")
    
@user_bp.route('/login/form')
def login_form_index():
    return render_template('user/login_form.html')
# 使用者登入
@user_bp.route('/login', methods=['POST'])
def login():
    try:
        userno = request.form.get('userno')
        password = request.form.get('password')

        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT userno, username, password FROM user WHERE userno = %s", (userno,))
        result = cursor.fetchone()  # 返回字典，例如 {'userno': '123', 'username': 'test', 'password': 'hashed_str'}
        conn.close()

        if not result:
            return render_template('user/login.html', success=False, message="帳號不存在")

        # 使用字段名訪問（注意大小寫需與資料庫完全一致）
        stored_hash_str = result['password']  # 正確訪問方式
        userno_from_db = result['userno']
        username_from_db = result['username']

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash_str.encode('utf-8')):
            user = User(id=userno_from_db, username=username_from_db, password=stored_hash_str)
            login_user(user)
            return redirect('/')
        else:
            return render_template('user/login.html', success=False, message="密碼錯誤")

    except Exception as e:
        user_bp.logger.error(f"登入錯誤詳細訊息: {repr(e)}")
        return render_template('user/login.html', success=False, message=f"發生錯誤: {str(e)}")

#使用者登出
@user_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/user/login/form')