// 建立小星星動畫
function createStars() {
    const numStars = 200;
    for (let i = 0; i < numStars; i++) {
        let star = document.createElement("div");
        star.classList.add("star");
        const x = Math.random() * 100;
        const y = Math.random() * 100;
        const duration = Math.random() * 2 + 1;
        const delay = Math.random() * 5;
        star.style.top = `${y}vh`;
        star.style.left = `${x}vw`;
        star.style.animationDuration = `${duration}s`;
        star.style.animationDelay = `${delay}s`;
        document.body.appendChild(star);
    }
}

createStars();

// Navbar隱藏顯示的邏輯
let lastScrollTop = 0;
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    let currentScroll = window.pageYOffset || document.documentElement.scrollTop;
    
    if (currentScroll > lastScrollTop) {
        navbar.classList.add('hidden'); // 向下滾動隱藏navbar
    } else {
        navbar.classList.remove('hidden'); // 向上滾動顯示navbar
    }
    lastScrollTop = currentScroll <= 0 ? 0 : currentScroll; // 防止滾動條小於0
});

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

// 連接後端PDF
async function uploadPDF() {
  const fileInput = document.getElementById('pdfUpload');
  if (fileInput.files.length === 0) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const response = await fetch('/policy/creat_PDF', {
      method: 'POST',
      body: formData
    });
    
    const result = await response.json();
    if (result.success) {
      document.getElementById('pdfHash').value = result.pdf_hash;
    } else {
      alert('上傳失敗: ' + result.error);
    }
  } catch (error) {
    console.error('上傳錯誤:', error);
  }
}

//------------------------
// 全域宣告 (必須!)
let web3 = null;
let contract = null;
let account = null; // 明確初始化為 null

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

// 錢包連接功能
async function connectWallet() {
  try {
    if (!window.ethereum) throw new Error("請安裝MetaMask");

    // 強制重新連接
    web3 = new Web3(window.ethereum);
    
    // 請求帳戶存取權限
    const accounts = await window.ethereum.request({ 
      method: "eth_requestAccounts" 
    });
    
    // 更新全域變數
    account = accounts[0]; 
    
    // 初始化合約實例
    contract = new web3.eth.Contract(contractABI, contractAddress);
    
    console.log("當前連接帳戶:", account);
    alert("錢包連接成功: " + account);
    
  } catch (error) {
    console.error("錢包連接失敗:", error);
    alert("連接失敗: " + error.message);
  }
}

// 表單提交處理
document.getElementById("policyForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const statusDiv = document.getElementById("status");
    statusDiv.innerHTML = "<p>處理中...</p>";

    // ======== 新增檢查 ========
    if (!account) {
      alert("請先點擊「連接錢包」按鈕連接帳戶");
      return;
    }
  
    if (!contract) {
      alert("合約未初始化，請重新連接錢包");
      return;
    }

    try {
      // 參數驗證
      if (!account) throw new Error("請先連接錢包");
      if (!contract) throw new Error("合約未初始化");

      // ========== 新增加密配置 ==========
      const ENCRYPTION_KEY = CryptoJS.enc.Utf8.parse("32-ByteSecretKey-123456789012"); // 32字節密鑰
      const IV = CryptoJS.enc.Utf8.parse("16-ByteInitVector"); // 16字節初始化向量

      // AES加密函數
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
      // ========== 加密結束 ==========

      // 收集並加密表單資料
      const params = {
          _policyNumber: document.getElementById("policyNumber").value,
          // 加密敏感欄位
          _policyHolder: document.getElementById("policyHolder").value,
          _insuredPerson: document.getElementById("insuredPerson").value,
          _insuranceAmount: document.getElementById("insuranceAmount").value, 
          _premiumPeriod: parseInt(document.getElementById("premiumPeriod").value),
          _premiumAmount: document.getElementById("premiumAmount").value,
          _startDate: Math.floor(new Date(document.getElementById("startDate").value).getTime() / 1000),
          // 加密受益人資訊
          _beneficiary: encryptField(document.getElementById("beneficiary").value),
          _growthRate: parseInt(document.getElementById("growthRate").value),
          _declaredInterestRate: parseInt(document.getElementById("declaredInterestRate").value),
          _pdfHash: document.getElementById("pdfHash").value
      };

      console.log("加密後參數:", {
          ...params,
          _policyHolder: "<加密資料>",
          _insuredPerson: "<加密資料>",
          _beneficiary: "<加密資料>"
      });

      // 建構交易（參數順序需與合約嚴格一致）
      const tx = contract.methods.addPolicy(
          params._policyNumber,
          params._policyHolder,    // 加密後的投保人
          params._insuredPerson,   // 加密後的被保險人
          params._insuranceAmount,
          params._premiumPeriod,
          params._premiumAmount,
          params._startDate,
          params._beneficiary,     // 加密後的受益人
          params._growthRate,
          params._declaredInterestRate,
          params._pdfHash
      );

      // 估算Gas
      const gas = await tx.estimateGas({ from: account })
          .catch(err => {
              console.error("Gas估算失敗:", err);
              throw new Error(`交易預檢失敗: ${err.message}`);
          });

      // 發送交易
      const receipt = await tx.send({
          from: account,
          gas: Math.floor(gas * 1.2),  // 增加20%緩衝
          gasPrice: await web3.eth.getGasPrice()
      })
      .on('transactionHash', hash => {
          statusDiv.innerHTML = `<p>交易已廣播，等待確認...<br>交易哈希: ${hash}</p>`;
      });

      console.log("交易成功:", receipt);
      statusDiv.innerHTML = `
          <p style="color:green">✅ 交易成功！</p>
          <p>區塊高度: ${receipt.blockNumber}</p>
          <p>交易哈希: ${receipt.transactionHash}</p>
      `;

    } catch (error) {
      console.error("交易失敗:", error);
      statusDiv.innerHTML = `
          <p style="color:red">❌ 交易失敗</p>
          <p>錯誤訊息: ${error.message}</p>
          ${error.stack ? `<pre>${error.stack}</pre>` : ''}
      `;
    }
});
