// 對稱加密配置
const ENCRYPTION_KEY = CryptoJS.enc.Utf8.parse("your-32-byte-secret-key"); // 替換為實際密鑰
const IV = CryptoJS.enc.Utf8.parse("your-16-byte-iv"); // 初始化向量

// AES加密函數
function encryptField(plainText) {
  const encrypted = CryptoJS.AES.encrypt(
    CryptoJS.enc.Utf8.parse(plainText),
    ENCRYPTION_KEY,
    { 
      iv: IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    }
  );
  return encrypted.toString();
}

// 解密函數（範例）
function decryptField(cipherText) {
  const decrypted = CryptoJS.AES.decrypt(
    cipherText,
    ENCRYPTION_KEY,
    { 
      iv: IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    }
  );
  return decrypted.toString(CryptoJS.enc.Utf8);
}

/*---------------*/  
async function uploadPDF() {
    const fileInput = document.getElementById('pdfUpload');
    if (!fileInput || fileInput.files.length === 0) {
        return "";  // 沒選擇就回空值
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        const response = await fetch("/policy/creat_PDF", {
            method: "POST",
            body: formData,
        });
        const data = await response.json();

        if (data.success) {
            console.log("成功取得 IPFS hash:", data.pdf_hash);
            return data.pdf_hash;
        } else {
            console.error("上傳失敗:", data.error);
            return "";
        }
    } catch (error) {
        console.error("上傳錯誤:", error);
        return "";
    }
}

//------------------------
// 全域宣告
let web3 = null;
let contract = null;
let userWalletAddress = null;

// 合約地址和 ABI（需與後端一致）
const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const contractABI = [
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			},
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
			},
			{
				"internalType": "string",
				"name": "_pdfHash",
				"type": "string"
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
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "_wallet",
				"type": "address"
			}
		],
		"name": "authorizePolicyAccess",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
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
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
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
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
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
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			}
		],
		"name": "getPolicyOwner",
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
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "_wallet",
				"type": "address"
			}
		],
		"name": "isAuthorized",
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
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"name": "policies",
		"outputs": [
			{
				"internalType": "string",
				"name": "policyNumber",
				"type": "string"
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
			},
			{
				"internalType": "string",
				"name": "pdfHash",
				"type": "string"
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
		"name": "policyNumbers",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "_wallet",
				"type": "address"
			}
		],
		"name": "revokePolicyAccess",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			},
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
				"internalType": "string",
				"name": "_beneficiary",
				"type": "string"
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
				"internalType": "string",
				"name": "_policyNumber",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_pdfHash",
				"type": "string"
			}
		],
		"name": "updatePolicyPDF",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
];

// 格式化錢包地址顯示 (前6位...後4位)
function formatWalletAddress(address) {
    if (!address) return '';
    if (address.length <= 12) return address;
    return `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
}

// 頁面載入時自動獲取錢包地址
window.addEventListener('DOMContentLoaded', function() {
    // 自動填寫表單資料
    document.getElementById("policyNumber").value = "{{ policy.policy_number }}";
    document.getElementById("insuranceCompany").value = "{{ policy.insurance_company }}";
    document.getElementById("policyHolder").value = "{{ policy.policy_holder }}";
    document.getElementById("insuredPerson").value = "{{ policy.insured_person }}";
    document.getElementById("insuranceAmount").value = "{{ policy.insurance_amount }}";
    document.getElementById("premiumPeriod").value = "{{ policy.premium_period }}";
    document.getElementById("premiumAmount").value = "{{ policy.premium_amount }}";
    document.getElementById("startDate").value = "{{ policy.start_date }}";
    document.getElementById("beneficiary").value = "{{ policy.beneficiary }}";
    document.getElementById("growthRate").value = "{{ policy.growth_rate }}";
    document.getElementById("declaredInterestRate").value = "{{ policy.declared_interest_rate }}";
    
    // 延遲載入錢包地址，確保頁面完全載入
    setTimeout(() => {
        loadWalletAddress();
    }, 500);
});

// 載入錢包地址
async function loadWalletAddress() {
    try {
        console.log('開始載入錢包地址...');
        
        // 顯示載入狀態
        document.getElementById('userWalletAddress').textContent = '載入中...';
        document.getElementById('userWalletStatus').textContent = '載入中';

        // 獲取錢包地址
        const response = await fetch('/policy/get_wallet_addresses');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('錢包地址回應:', data);

        if (data.success && data.user_wallet) {
            userWalletAddress = data.user_wallet;
            document.getElementById('userWalletAddress').textContent = formatWalletAddress(data.user_wallet);
            document.getElementById('userWalletStatus').textContent = '已連接';
            document.getElementById('userWalletStatus').className = 'wallet-status status-connected';
            console.log('用戶錢包地址載入成功:', data.user_wallet);
            
            // 自動初始化 Web3 和合約
            await initWeb3AndContract();
        } else {
            throw new Error(data.error || '用戶錢包地址未設定');
        }
    } catch (error) {
        console.error('載入錢包地址失敗:', error);
        document.getElementById('userWalletAddress').textContent = '載入失敗';
        document.getElementById('userWalletStatus').textContent = '錯誤';
        document.getElementById('userWalletStatus').className = 'wallet-status status-error';
        
        let errorMsg = '載入錢包地址失敗: ';
        if (error.message.includes('HTTP error')) {
            errorMsg += '後端服務暫時無法訪問，請稍後再試';
        } else {
            errorMsg += error.message;
        }
        
        console.error(errorMsg);
    }
}

// 初始化 Web3 和合約
async function initWeb3AndContract() {
    if (!userWalletAddress) {
        throw new Error('用戶錢包地址未設定，請先載入錢包地址或聯繫管理員');
    }

    try {
        if (window.ethereum) {
            web3 = new Web3(window.ethereum);
            
            // 檢查當前連接的帳戶是否與資料庫中的一致
            const accounts = await window.ethereum.request({ 
                method: "eth_requestAccounts" 
            });
            
            const currentAccount = accounts[0];
            if (currentAccount.toLowerCase() !== userWalletAddress.toLowerCase()) {
                throw new Error(`當前連接的錢包地址 (${formatWalletAddress(currentAccount)}) 與資料庫中的地址 (${formatWalletAddress(userWalletAddress)}) 不一致，請切換到正確的錢包或更新資料庫中的錢包地址`);
            }
            
            contract = new web3.eth.Contract(contractABI, contractAddress);
            console.log('Web3 和合約初始化成功');
            return true;
        } else {
            throw new Error('請安裝 MetaMask 錢包擴展');
        }
    } catch (error) {
        console.error('初始化 Web3 失敗:', error);
        throw error;
    }
}

// 修改保單
function modifyPolicy() {
    window.location.href = '/policy/update/form?policy_number={{ policy.policy_number }}';
}

// 檢查錢包狀態
function checkWalletStatus() {
    if (!userWalletAddress) {
        return { valid: false, message: '請先載入錢包地址' };
    }
    if (!window.ethereum) {
        return { valid: false, message: '請安裝 MetaMask' };
    }
    return { valid: true, message: '錢包狀態正常' };
}

// 表單提交處理
document.getElementById("policyForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const statusDiv = document.getElementById("status");
    statusDiv.innerHTML = "<p style='color:black'>處理中...</p>";

    try {
        // 檢查錢包狀態
        const walletStatus = checkWalletStatus();
        if (!walletStatus.valid) {
            throw new Error(walletStatus.message);
        }

        // 初始化 Web3 和合約
        await initWeb3AndContract();

        // 加密配置
        const ENCRYPTION_KEY = CryptoJS.enc.Utf8.parse("32-ByteSecretKey-123456789012");
        const IV = CryptoJS.enc.Utf8.parse("16-ByteInitVector");

        const encryptField = (plainText) => {
            if (!plainText) return "";
            try {
                return CryptoJS.AES.encrypt(
                    CryptoJS.enc.Utf8.parse(plainText),
                    ENCRYPTION_KEY,
                    { 
                        iv: IV,
                        mode: CryptoJS.mode.CBC,
                        padding: CryptoJS.pad.Pkcs7
                    }
                ).toString();
            } catch (error) {
                console.error("加密失敗:", error);
                throw new Error("欄位加密處理失敗");
            }
        };

        // 收集並加密表單資料
        const pdfHash = document.getElementById('pdfHash').value;
        const params = {
            _policyNumber: document.getElementById("policyNumber").value,
            _policyHolder: encryptField(document.getElementById("policyHolder").value),
            _insuredPerson: encryptField(document.getElementById("insuredPerson").value),
            _insuranceAmount: document.getElementById("insuranceAmount").value, 
            _premiumPeriod: parseInt(document.getElementById("premiumPeriod").value),
            _premiumAmount: document.getElementById("premiumAmount").value,
            _startDate: Math.floor(new Date(document.getElementById("startDate").value).getTime() / 1000),
            _beneficiary: encryptField(document.getElementById("beneficiary").value),
            _growthRate: parseInt(document.getElementById("growthRate").value),
            _declaredInterestRate: parseInt(document.getElementById("declaredInterestRate").value),
            _pdfHash: pdfHash
        };

        console.log("交易參數:", params);

        // 建構交易
        const tx = contract.methods.addPolicy(
            params._policyNumber,
            params._policyHolder,
            params._insuredPerson,
            params._insuranceAmount,
            params._premiumPeriod,
            params._premiumAmount,
            params._startDate,
            params._beneficiary,
            params._growthRate,
            params._declaredInterestRate,
            params._pdfHash
        );

        // 估算 Gas
        const gas = await tx.estimateGas({ from: userWalletAddress })
            .catch(err => {
                console.error("Gas估算失敗:", err);
                throw new Error(`交易預檢失敗: ${err.message}`);
            });

        // 發送交易
        const receipt = await tx.send({
            from: userWalletAddress,
            gas: Math.floor(gas * 1.2),
            gasPrice: await web3.eth.getGasPrice()
        })
        .on('transactionHash', hash => {
            statusDiv.innerHTML = `<p style='color:black'>交易已廣播，等待確認...<br>交易哈希: ${hash}</p>`;
        });

        console.log("交易成功:", receipt);
        statusDiv.innerHTML = `
            <p style="color:green">✅ 交易成功！</p>
            <p style="color:black">區塊高度: ${receipt.blockNumber}</p>
            <p style="color:black">交易哈希: ${receipt.transactionHash}</p>
        `;

        // 提交到後端資料庫
        await submitAndConfirmPolicy();
        
    } catch (error) {
        console.error("交易失敗:", error);
        
        let userMessage = '交易失敗: ' + error.message;
        if (error.code === 4001 || error.message?.includes('denied transaction signature')) {
            userMessage = '您已取消交易簽名';
        } else if (error.message.includes('Policy number already exists')) {
            userMessage = '保單編號已存在，請檢查後重新提交';
        } else if (error.message.includes('錢包地址不一致')) {
            userMessage = error.message;
        } else if (error.message.includes('請先載入錢包地址')) {
            userMessage = '請先點擊「重新載入錢包地址」按鈕載入錢包資訊';
        }

        statusDiv.innerHTML = `<p style="color:red">❌ ${userMessage}</p>`;
        
        console.error("完整錯誤訊息:", error);
    }
});

// 提交到後端資料庫
async function submitAndConfirmPolicy() {
    const CURRENT_CLIENT_GMAIL = document.getElementById('clientGmail').value;
    const CURRENT_OFFICER_GMAIL = document.getElementById('officerGmail').value;
    const pdfHash = document.getElementById('pdfHash').value;
    
    const policyData = {
        policy_number: document.getElementById("policyNumber").value,
        insurance_company: document.getElementById("insuranceCompany").value,
        policy_holder: document.getElementById("policyHolder").value,
        insured_person: document.getElementById("insuredPerson").value,
        insurance_amount: document.getElementById("insuranceAmount").value,
        premium_period: document.getElementById("premiumPeriod").value,
        premium_amount: document.getElementById("premiumAmount").value,
        start_date: document.getElementById("startDate").value,
        beneficiary: document.getElementById("beneficiary").value,
        growth_rate: document.getElementById("growthRate").value,
        declared_interest_rate: document.getElementById("declaredInterestRate").value,
        pdf_hash: pdfHash,
        client_gmail: CURRENT_CLIENT_GMAIL,
        officer_gmail: CURRENT_OFFICER_GMAIL
    };

    try {
        const response = await fetch('/policy/create_and_confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(policyData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert("保單已成功上鏈並儲存至資料庫！");
            // 可以選擇跳轉到成功頁面
            // window.location.href = '/policy/success';
        } else {
            alert("區塊鏈交易成功，但資料庫儲存失敗：" + result.message);
        }
    } catch (error) {
        alert("請求失敗: " + error.message);
        console.error("❌ 錯誤:", error);
    }
}

// 添加頁面可見性變化時的重新載入
document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        // 頁面從後台切換到前台時，重新檢查錢包狀態
        console.log('頁面重新可見，檢查錢包狀態');
        loadWalletAddress();
    }
});
