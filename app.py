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
#from pdf2image import convert_from_path
from PIL import Image
#import pytesseract
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
#from paddleocr import PaddleOCR, draw_ocr
from PIL import Image
#from opencc import OpenCC
import os
import re
#import cv2
import numpy as np
#-----------------------
# **匯入藍圖
#-----------------------
from myapp.user import user_bp
from myapp.user import load_user as user_load_user
from myapp.officer import officer_bp
from myapp.policy import policy_bp
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 或其他郵件伺服器
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '11056028@ntub.edu.tw'  # 你的郵箱
app.config['MAIL_PASSWORD'] = 'rfda igqb rtnh obye'  # 你的郵箱密碼
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
app.register_blueprint(officer_bp, url_prefix='/officer')
app.register_blueprint(policy_bp, url_prefix='/policy')
# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)  # 綁定到應用
login_manager.login_view = 'user.login'  # 指定登入路由
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

# 連接本地 Hardhat 區塊鏈
hardhat_url = "http://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(hardhat_url))

# 檢查是否成功連線
if not w3.is_connected():
    raise Exception("無法連接本地區塊鏈，請檢查 Hardhat 是否運行")

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/policy/create/form')
def policy_addpolicy_form():
    return render_template('policy/create_form.html')

#修改保單
@app.route('/policy/update/form')
def policy_updatepolicy_form():
    return render_template('policy/update_form.html')


#----------------

#客戶刪除表單
@app.route('/policy/delete/form')
def policy_delete_form():
    return render_template('policy/delete_form.html') 

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

@app.route('/policy/create_PDF', methods=['POST'])
def create_PDF():
    if 'file' not in request.files:
        return jsonify(success=False, error='未選擇文件')
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, error='文件名無效')

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            pdf_hash = hash_pdf_file(filepath)
            return jsonify(success=True, pdf_hash=pdf_hash, filename=filename)
        except Exception as e:
            return jsonify(success=False, error=f'處理失敗: {str(e)}')
    
    return jsonify(success=False, error='文件類型不支持')

@app.route('/policy/update_pdf', methods=['POST'])
def update_pdf():
    try:
        # 檢查文件
        if 'file' not in request.files:
            return jsonify(success=False, error='未選擇文件'), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify(success=False, error='文件名無效'), 400

        if not allowed_file(file.filename):
            return jsonify(success=False, error='文件類型不支持'), 400

        policy_number = request.form.get('policyNumber', '').strip()
        if not policy_number:
            return jsonify(success=False, error='缺少保單號碼'), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # 計算哈希值
            pdf_hash = hash_pdf_file(filepath)
            return jsonify(success=True, pdf_hash=pdf_hash)

        except Exception as e:
            return jsonify(success=False, error=f'處理失敗: {str(e)}'), 500

        finally:
            # 清理臨時文件
            if os.path.exists(filepath):
                os.remove(filepath)

    except Exception as e:
        return jsonify(success=False, error=f'服務器錯誤: {str(e)}'), 500
    
#連接錢包
@app.route('/policy/wallet')
def wallet():
    return render_template("policy/wallet.html")

FACTORY_ABI_JSON = '''[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "address",
				"name": "daoAddress",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "monthlyPremium",
				"type": "uint256"
			}
		],
		"name": "DAOCreated",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_monthlyPremium",
				"type": "uint256"
			}
		],
		"name": "createDAO",
		"outputs": [],
		"stateMutability": "nonpayable",
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
		"name": "daoAddresses",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getDAOAddresses",
		"outputs": [
			{
				"internalType": "address[]",
				"name": "",
				"type": "address[]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]'''

DAO_ABI_JSON = '''[
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_monthlyPremium",
				"type": "uint256"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "claimant",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "reason",
				"type": "string"
			}
		],
		"name": "ClaimCreated",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "bool",
				"name": "passed",
				"type": "bool"
			}
		],
		"name": "ClaimExecuted",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "address",
				"name": "user",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "month",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "PaidPremium",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "voter",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "bool",
				"name": "support",
				"type": "bool"
			}
		],
		"name": "Voted",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "claimId",
				"type": "uint256"
			}
		],
		"name": "canExecute",
		"outputs": [
			{
				"internalType": "bool",
				"name": "allowed",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "executeAfter",
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
		"name": "claims",
		"outputs": [
			{
				"internalType": "address",
				"name": "claimant",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "reason",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "yesVotes",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "noVotes",
				"type": "uint256"
			},
			{
				"internalType": "bool",
				"name": "executed",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "createdAt",
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
				"name": "amountInWei",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "_reason",
				"type": "string"
			}
		],
		"name": "createClaim",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "claimId",
				"type": "uint256"
			}
		],
		"name": "executeClaim",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "claimId",
				"type": "uint256"
			}
		],
		"name": "getClaim",
		"outputs": [
			{
				"components": [
					{
						"internalType": "address",
						"name": "claimant",
						"type": "address"
					},
					{
						"internalType": "uint256",
						"name": "amount",
						"type": "uint256"
					},
					{
						"internalType": "string",
						"name": "reason",
						"type": "string"
					},
					{
						"internalType": "uint256",
						"name": "yesVotes",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "noVotes",
						"type": "uint256"
					},
					{
						"internalType": "bool",
						"name": "executed",
						"type": "bool"
					},
					{
						"internalType": "uint256",
						"name": "createdAt",
						"type": "uint256"
					}
				],
				"internalType": "struct DAO.Claim",
				"name": "",
				"type": "tuple"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getClaimTime",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "pure",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getMemberCount",
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
		"inputs": [],
		"name": "getMonthlyPremium",
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
		"inputs": [],
		"name": "getTotalClaims",
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
		"inputs": [],
		"name": "getTreasuryBalance",
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
				"name": "claimId",
				"type": "uint256"
			},
			{
				"internalType": "address",
				"name": "voter",
				"type": "address"
			}
		],
		"name": "hasVoted",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
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
			},
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"name": "hasVotedMap",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "user",
				"type": "address"
			}
		],
		"name": "isMember",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "memberCount",
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
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"name": "memberPaidTotal",
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
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"name": "members",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "monthlyPremium",
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
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "month",
				"type": "uint256"
			}
		],
		"name": "payPremium",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "claimId",
				"type": "uint256"
			},
			{
				"internalType": "bool",
				"name": "support",
				"type": "bool"
			}
		],
		"name": "vote",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]'''

# 轉換為Python對象
FACTORY_ABI = json.loads(FACTORY_ABI_JSON)
DAO_ABI = json.loads(DAO_ABI_JSON)

factory_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

# ========== 頁面路由 ==========


@app.route('/dao/')
def dao_list():
    """DAO列表頁面"""
    return render_template("dao/index.html")

@app.route('/dao/<dao_address>')
def dao_details(dao_address):
    """DAO詳細頁面"""
    return render_template("dao/dao-details.html", dao_address=dao_address)

@app.route('/dao/<dao_address>/claims')
@app.route('/claims.html')  # 保持向後兼容
def dao_claims(dao_address=None):
    """DAO理賠歷史頁面"""
    if not dao_address:
        # 從查詢參數獲取地址（舊版本兼容）
        dao_address = request.args.get('address')
    
    if not dao_address:
        return "缺少 DAO 地址", 400
        
    return render_template("dao/claims.html", dao_address=dao_address)

# ========== API 路由 ==========
@app.route('/api/daos', methods=['GET'])
def get_daos():
    """獲取所有DAO地址"""
    try:
        factory = w3.eth.contract(address=factory_address, abi=FACTORY_ABI)
        daos = factory.functions.getDAOAddresses().call()
        return jsonify({
            'status': 'success',
            'data': {
                'daos': daos,
                'count': len(daos)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/dao/<dao_address>/info', methods=['GET'])
def get_dao_info(dao_address):
    """獲取DAO詳細信息"""
    try:
        # 驗證地址格式
        if not w3.is_address(dao_address):
            return jsonify({'error': 'Invalid DAO address'}), 400
        
        dao_address = w3.to_checksum_address(dao_address)
        
        # 檢查合約是否存在
        code = w3.eth.get_code(dao_address)
        if code == '0x':
            return jsonify({'error': 'Contract does not exist'}), 404
        
        # 獲取DAO信息
        dao = w3.eth.contract(address=dao_address, abi=DAO_ABI)
        info = {
            'monthly_premium': str(dao.functions.getMonthlyPremium().call()),
            'member_count': dao.functions.getMemberCount().call(),
            'total_claims': dao.functions.getTotalClaims().call(),
            'claim_time': dao.functions.getClaimTime().call(),
            'treasury_balance': str(dao.functions.getTreasuryBalance().call())
        }
        
        return jsonify({'status': 'success', 'data': info})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/dao/<dao_address>/is_member', methods=['GET'])
def is_member(dao_address):
    """檢查用戶是否為DAO成員"""
    try:
        user_address = request.args.get('user')
        if not user_address:
            return jsonify({'error': 'Missing user parameter'}), 400
        
        # 使用正確的方法名驗證地址
        if not w3.is_address(user_address):
            return jsonify({'error': f'Invalid user address: {user_address}'}), 400
        if not w3.is_address(dao_address):
            return jsonify({'error': f'Invalid DAO address: {dao_address}'}), 400
        
        # 格式化地址為校驗和格式
        user_address = w3.to_checksum_address(user_address)
        dao_address = w3.to_checksum_address(dao_address)
        
        # 檢查DAO合約是否存在
        code = w3.eth.get_code(dao_address)
        if code == '0x':
            return jsonify({'error': 'Contract does not exist at this address'}), 404
        
        # 創建合約實例並調用
        dao = w3.eth.contract(address=dao_address, abi=DAO_ABI)
        is_member = dao.functions.isMember(user_address).call()
        
        return jsonify({
            'is_member': is_member,
            'user': user_address,
            'dao': dao_address
        })
        
    except ValueError as ve:
        return jsonify({'error': f'Value error: {str(ve)}'}), 400
    except Exception as e:
        app.logger.error(f"Error in is_member: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'details': str(e)
        }), 500

@app.route('/api/dao/<dao_address>/join', methods=['POST'])
def join_dao(dao_address):
    """加入DAO"""
    try:
        data = request.get_json()
        user_address = data.get('user')
        
        if not user_address or not w3.is_address(user_address):
            return jsonify({'error': 'Invalid user address'}), 400
        
        dao = w3.eth.contract(address=dao_address, abi=DAO_ABI)
        monthly_premium = dao.functions.getMonthlyPremium().call()
        
        return jsonify({
            'monthly_premium': str(monthly_premium),
            'dao_address': dao_address,
            'user': user_address
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dao/<dao_address>/claims', methods=['GET'])
def get_claims(dao_address):
    """獲取DAO的所有理賠請求"""
    try:
        # 驗證地址
        if not w3.is_address(dao_address):
            return jsonify({'error': 'Invalid DAO address'}), 400
        
        dao_address = w3.to_checksum_address(dao_address)
        
        # 檢查合約是否存在
        code = w3.eth.get_code(dao_address)
        if code == '0x':
            return jsonify({'error': 'Contract does not exist'}), 404
        
        dao = w3.eth.contract(address=dao_address, abi=DAO_ABI)
        total_claims = dao.functions.getTotalClaims().call()
        
        claims = []
        for i in range(total_claims):
            claim = dao.functions.getClaim(i).call()
            # 檢查是否可以執行
            can_execute, execute_after = dao.functions.canExecute(i).call()
            
            claims.append({
                'id': i,
                'claimant': claim[0],
                'amount': str(claim[1]),
                'reason': claim[2],
                'yesVotes': claim[3],
                'noVotes': claim[4],
                'executed': claim[5],
                'createdAt': claim[6],
                'canExecute': can_execute,
                'executeAfter': execute_after
            })
        
        return jsonify({'status': 'success', 'data': claims})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/dao/<dao_address>/create-claim', methods=['POST'])
def create_claim(dao_address):
    """創建理賠請求"""
    try:
        data = request.get_json()
        user_address = data.get('user')
        amount = data.get('amount')
        reason = data.get('reason')
        
        if not all([user_address, amount, reason]):
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # 這裡需要實現實際的創建理賠邏輯
        # 通常會需要用戶簽名和交易發送
        
        return jsonify({
            'status': 'success',
            'message': 'Claim created successfully'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/dao/<dao_address>/vote', methods=['POST'])
def vote_claim(dao_address):
    """對理賠請求投票"""
    try:
        data = request.get_json()
        user_address = data.get('user')
        claim_id = data.get('claim_id')
        support = data.get('support')
        
        if not all([user_address, claim_id, support is not None]):
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # 這裡需要實現實際的投票邏輯
        # 通常會需要用戶簽名和交易發送
        
        return jsonify({
            'status': 'success',
            'message': 'Vote submitted successfully'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
#-----------------------
# 啟動網站
#-----------------------
if __name__ == '__main__':
    app.run(debug=True)
    '''
    with app.app_context():
        store_keys(private_key_cry, public_key)
        '''
    app.run()
