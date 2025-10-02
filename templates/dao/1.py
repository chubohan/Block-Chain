from flask import Flask, jsonify, request,json,render_template
from web3 import Web3
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
# 連接到Hardhat本地節點
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))


# 直接在代碼中定義ABI
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

@app.route('/')
def index():
    return render_template("index.html")

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

@app.route('/api/dao/<dao_address>/is_member', methods=['GET'])
def is_member(dao_address):
    """檢查用戶是否為DAO成員"""
    try:
        user_address = request.args.get('user')
        if not user_address:
            return jsonify({'error': 'Missing user parameter'}), 400
        
        # 使用正確的方法名驗證地址
        if not w3.is_address(user_address):  # 或 Web3.is_address
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
        
        if not user_address or not w3.isAddress(user_address):
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
        dao = w3.eth.contract(address=dao_address, abi=DAO_ABI)
        total_claims = dao.functions.getTotalClaims().call()
        
        claims = []
        for i in range(total_claims):
            claim = dao.functions.getClaim(i).call()
            claims.append({
                'id': i,
                'claimant': claim[0],
                'amount': str(claim[1]),
                'reason': claim[2],
                'yesVotes': claim[3],
                'noVotes': claim[4],
                'executed': claim[5],
                'createdAt': claim[6]
            })
        
        return jsonify({'claims': claims})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dao-details')
def dao_details():
    """處理DAO詳細頁面請求"""
    return render_template("dao-details.html")

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
            'claim_time': dao.functions.getClaimTime().call()
        }
        
        return jsonify({'status': 'success', 'data': info})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
@app.route('/dao-details.html')
def dao_details_page():
    """處理DAO詳細頁面請求"""
    return render_template("dao-details.html")

@app.route('/claims.html')
def claims_page():
    """處理理賠歷史頁面請求"""
    return render_template("claims.html")
# 理赔历史页面
@app.route('/claims.html')
def claims_history():
    dao_address = request.args.get('address')
    return render_template('claims.html', address=dao_address)
if __name__ == '__main__':
    app.run(port=5000, debug=True)