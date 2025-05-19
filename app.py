#-----------------------
# 匯入必要模組
#-----------------------
from flask import Flask, request, jsonify, render_template,session,flash,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pdf2image import convert_from_path
from PIL import Image
import pytesseract
import utils.db as db
from web3 import Web3
import json
import time
import base64
import os
import bcrypt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from flask_cors import CORS
import hashlib
from werkzeug.utils import secure_filename
from threading import Lock
import logging
import pymysql
# 正确导入路径（Web3.py ≥7.0）
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider  # 注意新的导入路径
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from paddleocr import PaddleOCR, draw_ocr
from PIL import Image
from opencc import OpenCC
import os
import re
import cv2
import numpy as np
#-----------------------
# **匯入藍圖
#-----------------------
from myapp.user import user_bp
from myapp.user import load_user as user_load_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 或其他郵件伺服器
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '11056028@ntub.edu.tw'  # 你的郵箱
app.config['MAIL_PASSWORD'] = 'illu pozd sgco nfxl'  # 你的郵箱密碼
app.config['MAIL_DEFAULT_SENDER'] = '11056028@ntub.edu.tw'

mail = Mail(app)
login_manager = LoginManager(app)

# 用戶資料模擬（你應該將它連接到你的數據庫）
users = {}  # 假設這是你的用戶資料

# 用於生成重設密碼的令牌
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.secret_key = os.urandom(24)# 設置 session 加密金鑰
CORS(app)# 允許所有跨域請求

#-------------------------
# **註冊藍圖的服務
#-------------------------

app.register_blueprint(user_bp, url_prefix='/user')

# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)  # 綁定到應用
login_manager.login_view = 'login'  # 指定登入路由
#-----------------------
# 載入使用者
#-----------------------
@login_manager.user_loader
def load_user(user_id):
    return user_load_user(user_id)

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '123456789',
    'database': 'project',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# 线程安全的数据库连接
_db_lock = Lock()
def get_connection():
    with _db_lock:
        try:
            conn = pymysql.connect(**DB_CONFIG)
            logger.debug("数据库连接成功")
            return conn
        except Exception as e:
            logger.error(f"数据库连接失败: {e}")
            raise
print(get_connection())
# Web3配置 (异步模式)
try:
    from web3 import AsyncWeb3
    from web3.providers import AsyncHTTPProvider
    w3 = AsyncWeb3(AsyncHTTPProvider("http://127.0.0.1:8545"))
    logger.info("Web3异步连接成功")
except ImportError:
    logger.warning("未安装异步Web3，回退到同步模式")
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

# 從 Google Cloud Console 獲取的客戶端 ID
GOOGLE_CLIENT_ID = '551019375208-ee9n8eg06kg6v7chg9k8h7p98luc4p63.apps.googleusercontent.com'

# 设置数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keys.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 連接本地 Ganache 區塊鏈
hardhat_url = "http://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(hardhat_url))

# 檢查是否成功連線
if not w3.is_connected():
    raise Exception("無法連接本地區塊鏈，請檢查 Hardhat 是否運行")

# 生成 RSA 密鑰 (公鑰和私鑰)
private_key_cry = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 確保 private_key_cry 與 public_key 是同一對
public_key = private_key_cry.public_key()

# 選擇性將密鑰導出到文件或安全儲存
private_pem = private_key_cry.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 定义密钥存储表
class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    private_key = db.Column(db.String(500), nullable=False)
    public_key = db.Column(db.String(500), nullable=False)

# 创建数据库和表
with app.app_context():
    db.create_all()

def encrypt_data(public_key, data):
    """加密數據"""
    encrypted = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            algorithm=hashes.SHA256(),
            mgf=padding.MGF1(hashes.SHA256()),
            label=None
        )
    )
    return encrypted
 
def decrypt_data(private_key_cry, encrypted_data):
    """解密加密的數據"""
    if not isinstance(encrypted_data, bytes):
        raise ValueError("傳入的數據必須是 bytes 類型")
    
    try:
        # 嘗試解密數據
        decrypted = private_key_cry.decrypt(
            encrypted_data,
            padding.OAEP(
                algorithm=hashes.SHA256(),
                mgf=padding.MGF1(hashes.SHA256()),
                label=None
            )
        )
        decrypted_str = decrypted.decode('utf-8')
        return decrypted_str  # 解密後返回字符串
    except ValueError as e:
        # 捕獲解密時可能出現的具體錯誤
        print(f"解密錯誤：{e}")
        raise  # 重新拋出異常，方便在主函數中捕捉並處理
    except Exception as e:
        # 捕獲所有其他異常並打印錯誤信息
        print(f"解密時發生未預料的錯誤：{e}")
        raise  # 重新拋出異常
    
encrypted = encrypt_data(public_key, "policyHolder")

decrypted = decrypt_data(private_key_cry, encrypted)

def store_keys(private_key_cry, public_key):
    # 确保在应用程序上下文中执行
    with app.app_context():
        # 将私钥转换为 PEM 格式
        private_pem = private_key_cry.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 将公钥转换为 PEM 格式
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 将密钥存储到数据库
        key_entry = Key(private_key=private_pem.decode('utf-8'), public_key=public_pem.decode('utf-8'))
        db.session.add(key_entry)
        db.session.commit()
        
# 在程序启动时调用 store_keys
with app.app_context():
    store_keys(private_key_cry, public_key)

# 存储当前生成的密钥
store_keys(private_key_cry, public_key)

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')  # 設定上傳資料夾路徑
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def hash_pdf_file(pdf_path):
    """計算PDF文件的雜湊值"""
    with open(pdf_path, 'rb') as file:
        pdf_hash = hashlib.sha256(file.read()).hexdigest()
    return pdf_hash

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# 初始化 PaddleOCR 與簡轉繁
ocr = PaddleOCR(
    use_angle_cls=True,
    lang='ch',
    use_gpu=False,
    det_model_dir='C:/paddleocr_models/ch_PP-OCRv4_det_infer',
    rec_model_dir='C:/paddleocr_models/ch_PP-OCRv4_rec_infer',
    cls_model_dir='C:/paddleocr_models/ch_ppocr_mobile_v2.0_cls_infer'
)
cc = OpenCC('s2t')

# 設定智能合約地址 & ABI (需替換為你自己的合約資訊)
contract_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
contract_address=w3.to_checksum_address(contract_address)
contract_abi = json.loads("""[
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_policyHolder",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_insuredPerson",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "_insuranceAmount",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_premiumPeriod",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_premiumAmount",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_startDate",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "_beneficiary",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "_growthRate",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_declaredInterestRate",
				"type": "uint256"
			}
		],
		"name": "addPolicy",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_policyNumber",
				"type": "uint256"
			}
		],
		"name": "deletePolicy",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_policyNumber",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_insuranceAmount",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_premiumAmount",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_growthRate",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_declaredInterestRate",
				"type": "uint256"
			}
		],
		"name": "updatePolicy",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_policyNumber",
				"type": "uint256"
			}
		],
		"name": "getPolicy",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getPolicyCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "policies",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "policyNumber",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "policyHolder",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "insuredPerson",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "insuranceAmount",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "premiumPeriod",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "premiumAmount",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "startDate",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "beneficiary",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "growthRate",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "declaredInterestRate",
				"type": "uint256"
			},
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "policyCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]""")

# 載入智能合約
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# 測試用帳戶 (Hardhat 提供)
wallet_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
wallet_address=w3.to_checksum_address(wallet_address)
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/policy/create/form')
def policy_addpolicy_form():
    return render_template('policy/create_form.html')
'''
@app.route("/add_policy", methods=["POST"])
def add_policy():
    try:
        # 取得前端傳來的 JSON 數據
        data = request.json
        print(f"收到請求數據: {data}")

        # 提取資料
        policyHolder = data["policyHolder"]
        insuredPerson = data["insuredPerson"]
        insuranceAmount = int(data["insuranceAmount"])  # 轉換為整數
        premiumPeriod = int(data["premiumPeriod"])  # 轉換為整數
        premiumAmount = int(data["premiumAmount"])  # 轉換為整數
        startDate = int(time.time())  # 使用當前時間
        beneficiary = data["beneficiary"]
        growthRate = int(data["growthRate"])  # 轉換為整數
        declaredInterestRate = int(data["declaredInterestRate"])  # 轉換為整數

        # 確保資料是字符串，並進行加密
        encrypted_policyHolder = encrypt_data(public_key, policyHolder)
        encrypted_insuredPerson = encrypt_data(public_key, insuredPerson)
        encrypted_beneficiary = encrypt_data(public_key, beneficiary)

        # 將加密的 bytes 資料轉換為 Base64 字符串
        encoded_policyHolder = base64.b64encode(encrypted_policyHolder).decode('utf-8')
        encoded_insuredPerson = base64.b64encode(encrypted_insuredPerson).decode('utf-8')
        encoded_beneficiary = base64.b64encode(encrypted_beneficiary).decode('utf-8')

        # 設定交易資訊
        nonce = w3.eth.get_transaction_count(wallet_address)
        transaction = contract.functions.addPolicy(
            encoded_policyHolder, encoded_insuredPerson, insuranceAmount, premiumPeriod,
            premiumAmount, startDate, encoded_beneficiary, growthRate, declaredInterestRate
        ).build_transaction({
            "gas": 8000000,
            "gasPrice": w3.to_wei("20", "gwei"),
            "nonce": nonce,
            "from": wallet_address
        })

        # 簽署並發送交易
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

        if not tx_hash:
            raise Exception("交易哈希返回為空，可能發生錯誤。")

        print(f"交易已發送，交易哈希: {tx_hash.hex()}")
        return jsonify({"status": "success", "tx_hash": tx_hash.hex()})

    except Exception as e:
        error_message = f"發生錯誤: {str(e)}"
        print(error_message)
        return jsonify({"status": "error", "message": error_message}), 400

#---------------------------------------

#修改保單
@app.route('/policy/update/fetch')
def policy_updatepolicy_form():
    return render_template('policy/update_fetch.html')


#修改保單(區塊鏈)
def update_policy(policy_number, insurance_amount, premium_amount, growth_rate, declared_interest_rate):
    nonce = w3.eth.get_transaction_count(wallet_address)

    txn = contract.functions.updatePolicy(
        policy_number, insurance_amount, premium_amount, growth_rate, declared_interest_rate
    ).build_transaction({
        "from": wallet_address,
        "nonce": nonce,
        "gas": 500000,
        "gasPrice": w3.to_wei("10", "gwei"),
    })

    signed_txn = w3.eth.account.sign_transaction(txn, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

    return w3.to_hex(tx_hash)
'''
#----------------

#客戶刪除表單
@app.route('/policy/delete/form')
def policy_delete_form():
    return render_template('policy/delete_form.html') 
'''
#刪除保單(區塊鏈)
@app.route("/delete_policy/<int:policy_number>", methods=["DELETE"])
def delete_policy(policy_number):
    try:
        nonce = w3.eth.get_transaction_count(wallet_address)

        txn = contract.functions.deletePolicy(policy_number).build_transaction({
            "from": wallet_address,
            "nonce": nonce,
            "gas": 500000,
            "gasPrice": w3.to_wei("10", "gwei"),
        })

        signed_txn = w3.eth.account.sign_transaction(txn, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

        return jsonify({
            "message": f"保單 #{policy_number} 已成功刪除",
            "tx_hash": w3.to_hex(tx_hash)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
'''
#-------------------------

#客戶查詢表單
@app.route('/policy/read/form')
def policy_read_form():
    return render_template('policy/read_form.html') 
'''
#查詢保單(區塊鏈)
@app.route("/get_policy/<int:policy_number>", methods=["GET"])
def get_policy(policy_number):
    try:
        # 查詢保單
        policy = contract.functions.getPolicy(policy_number).call()

        if not policy or policy[0] == "":
            return jsonify({"error": "保單不存在"}), 404

        if not policy[0] or not policy[1] or not policy[5]:
            return jsonify({"error": "保單資料不完整"}), 404

        # 解碼 Base64
        encoded_policyHolder_crp = base64.b64decode(policy[0])  
        encoded_insuredPerson_crp = base64.b64decode(policy[1])  
        encoded_beneficiary_crp = base64.b64decode(policy[6])  
            

        # 解密資料
        try:
            decrypted_policyHolder = decrypt_data(private_key_cry, encoded_policyHolder_crp)
            decrypted_insuredPerson = decrypt_data(private_key_cry, encoded_insuredPerson_crp)
            decrypted_beneficiary = decrypt_data(private_key_cry, encoded_beneficiary_crp)
            
        except Exception as decrypt_error:
            print(f"解密過程出現錯誤: {decrypt_error}")
            return jsonify({"error": "解密資料時出現錯誤"}), 500

        return jsonify({
            "policyHolder": decrypted_policyHolder,
            "insuredPerson": decrypted_insuredPerson,
            "insuranceAmount": policy[2],
            "premiumPeriod": policy[3],
            "premiumAmount": policy[4],
            "startDate": policy[5],
            "beneficiary": decrypted_beneficiary,
            "growthRate": policy[7],
            "declaredInterestRate": policy[8]
        })

    except Exception as e:
        print(f"發生錯誤: {str(e)}")
        return jsonify({"error": str(e)}), 500
'''
#-------------------------------------------------
#使用者介面
@app.route('/user/customer')
def user_index():
    return render_template('user/customer.html') 
@app.route('/user/admin')
def admin_index():
    return render_template('user/admin.html')

#------------------------------------------------------
#Google sign in
@app.route('/auth/google', methods=['POST'])
def auth_google():
    print(request.json)
    token = request.json.get('credential')
    
    try:
        # 驗證 Google ID token
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        # 檢查 token 是否發給正確的客戶端
        if idinfo['aud'] != GOOGLE_CLIENT_ID:
            raise ValueError('Invalid client ID')

        # 提取用戶資訊
        user_data = {
            'id': idinfo['sub'],
            'name': idinfo.get('name'),
            'email': idinfo.get('email'),
            'picture': idinfo.get('picture')
        }

        # 在這裡可以將用戶資料存入資料庫或 session
        session['user'] = user_data

        return jsonify({
            'success': True,
            'user': user_data
        })

    except ValueError as e:
        # 無效的 token
        return jsonify({
            'success': False,
            'error': str(e)
        }), 401

@app.route('/profile')
def profile():
    if 'user' not in session:
        return '請先登入', 401
    
    user = session['user']
    return render_template("user/profile.html",user=user)
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'success': True})

@app.route('/policy/creat_PDF', methods=['POST'])
def create_PDF():
    if 'file' not in request.files:
        return jsonify(success=False, error='未选择文件')
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, error='文件名无效')

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            pdf_hash = hash_pdf_file(filepath)
            return jsonify(success=True, pdf_hash=pdf_hash, filename=filename)
        except Exception as e:
            return jsonify(success=False, error=f'处理失败: {str(e)}')
    
    return jsonify(success=False, error='文件类型不支持')

@app.route('/policy/create_ID_image', methods=['GET', 'POST'])
def create_ID_image():
    id_fields = {}
    filename = None

    if request.method == 'POST':
        file = request.files['file']
        if not file:
            return render_template("policy/create_ID_image.html", id_fields=None, filename=None)

        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # OCR 辨識與簡繁轉換
        try:
            result = ocr.ocr(filepath, cls=True)
        except RuntimeError as r:
            return render_template('policy/create_ID_image.html', id_fields=None, filename=None)
        text_list = [line[1][0] for block in result for line in block]
        text_list = [cc.convert(t) for t in text_list]  # <<<< 加上這行
        text = ' '.join(text_list)
        text = cc.convert(text)
        text = text.replace('编装', '統一編號')  # 修正常見錯字

        # ===== 擷取姓名 =====
        # 姓名擷取（從「出生」前的完整中文字抓取）
        name = None  # 預設為 None，避免未賦值錯誤
        name_match = re.search(r'姓名[:：]?\s*([\u4e00-\u9fa5]{2,5})', text)
        if not name_match:
            for i, t in enumerate(text_list):
                if '出生' in t and i > 0:
                    # 向前合併兩個詞作為姓名候選
                    name_candidate = text_list[i - 2] + text_list[i - 1] if i > 1 else text_list[i - 1]
                    match = re.search(r'([\u4e00-\u9fa5]{2,5})', name_candidate)
                    if match:
                        name = match.group(1)
                        break
        else:
            name = name_match.group(1)
        name = name.replace('出生', '').strip() if name else None

        # ===== 擷取身分證字號 =====
        id_number = re.search(r'[A-Z][0-9]{8,9}', text)

        # ===== 擷取性別 =====
        gender_match = re.search(r'性別[:：]?\s*(男|女)', text)

        # ===== 擷取出生年月日 =====
        birth_date = None
        for i, t in enumerate(text_list):
            if '出生' in t or '生' in t:
                combined = ''.join(text_list[i:i+4])
                birth_date = re.search(r'民國\d+年\d+月\d+日?', combined)
                if birth_date:
                    break

        # --- 新的「發證日期」判讀區塊 ---
        # ➤ 清洗發證日期函式：排除身分證字號
        def clean_issue_date(raw_text: str) -> str:
            # 擷取「民國xx年xx月xx日（可含括號地名）後接換發/初發/補發」
            match = re.search(r'(民國\d+年\d+月\d+日(?:（.*?）)?(?:\s*(初發|換發|補發))?)', raw_text)
            if match:
                return match.group(1).strip()
            return '❌ 無法辨識'

        # ➤ 擷取發證日期主函式
        def extract_issue_date(text_list):
            issue_date = ''
            keywords = ['發證', '換發', '發證日期']
            for i, t in enumerate(text_list):
                if any(k in t for k in keywords):
                    combined = ''.join(text_list[i:i + 6])
                    cleaned = clean_issue_date(combined)
                    if cleaned != '❌ 無法辨識':
                        issue_date = cleaned
                        break
            return issue_date

        # ➤ 第一次 OCR 擷取
        issue_date = extract_issue_date(text_list)

        # ➤ 第二次從圖片裁切區塊 OCR 擷取
        if not issue_date:
            image = Image.open(filepath)
            width, height = image.size
            crop_box = (int(width * 0.5), int(height * 0.7), width, height)
            cropped = image.crop(crop_box)
            enlarged = cropped.resize((cropped.width * 2, cropped.height * 2))

            crop_result = ocr.ocr(np.array(enlarged), cls=True)
            crop_text_list = [line[1][0] for block in crop_result for line in block]
            issue_date = extract_issue_date(crop_text_list)

        # ➤ fallback：整段合併處理
        if not issue_date:
            combined_crop_text = ''.join(crop_text_list)
            issue_date = clean_issue_date(combined_crop_text)

        # ➤ 無法辨識結果
        if not issue_date:
            issue_date = '❌ 無法辨識'

        # ===== 組合欄位結果 =====
        id_fields = {
            '姓名': name if name else '❌ 無法辨識',
            '出生年月日': birth_date.group() if birth_date else '❌ 無法辨識',
            '發證日期': issue_date if issue_date else '❌ 無法辨識',
            '性別': gender_match.group(1) if gender_match else '❌ 無法辨識',
            '身份證字號': id_number.group() if id_number else '❌ 無法辨識',
        }

    return render_template('policy/create_ID_image.html', id_fields=id_fields, filename=filename)

#-----------------------
# 啟動網站
#-----------------------
if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        store_keys(private_key_cry, public_key)
    app.run()
