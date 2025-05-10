from flask import Blueprint, render_template, request, redirect,url_for,session,jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from utils import db
from pymysql.cursors import DictCursor
import datetime
#產生藍圖
user_bp = Blueprint('user', __name__)


# 定義使用者類別
class User(UserMixin):
    def __init__(self, userno, username, password, age=None, gender=None):
        self.id = userno       # Flask-Login 強制使用 self.id
        self.userno = userno   # 可選，用於其他邏輯
        self.username = username
        self.password = password
        self.age = age
        self.gender = gender



#產生登入管理物件
login_manager = LoginManager()



# 載入使用者
@login_manager.user_loader
def load_user(user_id):
    conn = db.get_connection()
    cursor = conn.cursor()  # 確保返回字典
    cursor.execute(
        "SELECT userno, username, COALESCE(password, '') AS password, age, gender FROM user WHERE userno = %s",
        (user_id,)
    )
    result = cursor.fetchone()
    conn.close()

    if result:
        return User(
            userno=result['userno'],
            username=result['username'],
            password=result['password'],
            age=result.get('age'),    # 使用 get() 避免 KeyError 並允許 NULL
            gender=result.get('gender')
        )
    return None
#使用者註冊
#宣告註冊畫面
@user_bp.route('/signup/form')
def user_signup_form():
    return render_template('user/signup_form.html')


@user_bp.route('/signup', methods=['POST'])
def signup():
    try:
        # 獲取表單數據
        username = request.form.get('username')
        age=request.form.get('age')
        gender=request.form.get('gender')
        gmail = request.form.get('gmail')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

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

        # 寫入資料庫
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO user (username, age, gender, password, gmail) VALUES (%s, %s, %s,%s,%s)",
            (username,age,gender ,hashed_password, gmail)
        )
        conn.commit()
        return render_template('user/signup.html', success=True)

    except Exception as e:
        print(f"註冊錯誤: {str(e)}")
        return render_template('user/signup.html', success=False, message=f"註冊失敗: {str(e)}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()
    
@user_bp.route('/login/form')
def login_form_index():
    return render_template('user/login_form.html')
# 使用者登入
@user_bp.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username')
        gmail=request.form.get('gmail')
        password = request.form.get('password')

        conn = db.get_connection()
        cursor = conn.cursor(DictCursor)
        cursor.execute("SELECT userno, username, password,gmail FROM user WHERE username = %s and gmail=%s", (username,gmail,))
        result = cursor.fetchone()  # 返回字典，例如 {'userno': '123', 'username': 'test', 'password': 'hashed_str'}
        conn.close()

        if not result:
            return render_template('user/login.html', success=False, message="帳號不存在")

        # 使用字段名訪問（注意大小寫需與資料庫完全一致）
        stored_hash_str = result['password']  # 正確訪問方式
        userno_from_db = result['userno']
        username_from_db = result['username']

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash_str.encode('utf-8')):
            user = User(userno=userno_from_db,  username=username_from_db, password=stored_hash_str)
            login_user(user)
            return redirect('/')
        else:
            return render_template('user/login.html', success=False, message="密碼錯誤")

    except Exception as e:
        #user_bp.logger.error(f"登入錯誤詳細訊息: {repr(e)}")
        return render_template('user/login.html', success=False, message=f"發生錯誤: {str(e)}")
#------------------------------------------------------
# 從 Google Cloud Console 獲取的客戶端 ID
GOOGLE_CLIENT_ID = '551019375208-ee9n8eg06kg6v7chg9k8h7p98luc4p63.apps.googleusercontent.com'
# 在 user_bp 藍圖下新增以下路由
@user_bp.route('/auth/google', methods=['POST'])
def auth_google():
    try:
        token = request.json.get('credential')
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        # 驗證必要欄位
        if idinfo['aud'] != GOOGLE_CLIENT_ID:
            raise ValueError('Invalid client ID')
        if not idinfo.get('email_verified', False):
            return jsonify({'success': False, 'error': 'Email not verified'}), 401

        # 提取 Google 資料
        google_id = idinfo['sub']
        gmail = idinfo['email']
        username = idinfo.get('name', gmail.split('@')[0])  # 預設使用信箱前綴

        conn = db.get_connection()
        cursor = conn.cursor(DictCursor)

        # 檢查現有用戶 (優先使用 google_id 查詢)
        cursor.execute("""
            SELECT * FROM user 
            WHERE google_id = %s OR gmail = %s
            ORDER BY google_id DESC 
            LIMIT 1
        """, (google_id, gmail))
        user = cursor.fetchone()

        # 用戶存在邏輯
        if user:
            # 更新現有記錄 (確保 google_id 不重複)
            cursor.execute("""
                UPDATE user SET
                    username = COALESCE(username, %s),
                    google_id = %s,
                    is_verified = 1,
                    gmail = %s
                WHERE userno = %s
            """, (username, google_id, gmail, user['userno']))
        else:
            # 新增用戶 (處理預設值)
            cursor.execute("""
                INSERT INTO user (
                    username, 
                    gmail, 
                    google_id, 
                    is_verified,
                    password,  -- 允許 NULL
                    created_at
                ) VALUES (%s, %s, %s, %s, NULL, %s)
            """, (username, gmail, google_id, 1, datetime.now()))

        conn.commit()

        # 重新查詢完整用戶資料
        cursor.execute("SELECT * FROM user WHERE google_id = %s", (google_id,))
        user = cursor.fetchone()

        # 登入處理
        if user:
            # 檢查是否需要補全資料
            if not user.get('age') or not user.get('gender'):
                session['needs_profile'] = True
                session['userno'] = user['userno']
                return jsonify({
                    'success': True,
                    'needs_profile': True,
                    'userno': user['userno']
                })

            # 執行 Flask-Login 登入
            flask_user = User(
                userno=user['userno'],
                username=user['username'],
                password=user['password'] or ''  # 處理 NULL 值
            )
            login_user(flask_user)
            return jsonify({
                'success': True,
                'redirect': url_for('user.profile')
            })

        return jsonify({'success': False, 'error': 'Database error'}), 500

    except ValueError as e:
        print(f"Google 登入驗證失敗: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 401
    except Exception as e:
        print(f"資料庫錯誤: {str(e)}")
        conn.rollback()
        return jsonify({'success': False, 'error': 'Server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

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
#使用者登出
@user_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/user/login/form')