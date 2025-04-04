from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import db
from web3 import Web3
import json
import time
import base64
import os

app = Flask(__name__)

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
        print(f"成功解密，解密後的數據: {decrypted_str}")  # 打印解密後的數據
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
print(f"加密數據類型: {type(encrypted)}")
print(f"加密數據: {encrypted}")

decrypted = decrypt_data(private_key_cry, encrypted)
print(f"解密後的數據類型: {type(decrypted)}")
print(f"解密後的數據: {decrypted}")

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

        print(f"密钥已存储到数据库，公钥: {public_pem.decode('utf-8')}")
        
# 在程序启动时调用 store_keys
with app.app_context():
    store_keys(private_key_cry, public_key)

# 存储当前生成的密钥
store_keys(private_key_cry, public_key)




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

#----------------

#客戶刪除表單
@app.route('/policy/delete/form')
def policy_delete_form():
    return render_template('policy/delete_form.html') 

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
#-------------------------
#客戶查詢表單
@app.route('/policy/read/form')
def policy_read_form():
    return render_template('policy/read_form.html') 

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

#-------------------------------------------------

#-----------------------
# 啟動網站
#-----------------------
if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        store_keys(private_key_cry, public_key)
    app.run()
