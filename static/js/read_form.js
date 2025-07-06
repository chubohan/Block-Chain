// 創建小星星動畫
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

const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; // 替換為實際合約地址
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
	}
]; // 保持與之前提供的ABI一致

let insuranceContract = null;

// 連接錢包函數（改造後）
async function connectWallet() {
    try {
        if (!window.ethereum) throw new Error("請安裝MetaMask");
        
        // 初始化Provider
        const provider = new ethers.BrowserProvider(window.ethereum);
        await provider.send("eth_requestAccounts", []);
        
        // 獲取Signer
        const signer = await provider.getSigner();
        // 初始化合約實例
        insuranceContract = new ethers.Contract(
            "0x5FbDB2315678afecb367f032d93F642f64180aa3", // 替換實際地址
            contractABI,
            signer
        );
        
        // 驗證合約連接
        console.log("合約實例:", insuranceContract);
        console.log("合約地址:", await insuranceContract.getAddress());
        // 更新錢包狀態
        const address = await signer.getAddress();
        document.getElementById("walletAddress").textContent = 
            `你的錢包:${address.slice(0,6)}...${address.slice(-4)}`;
    }
    catch (error) {
        console.error("連接錯誤:", error);
        alert(`連接失敗: ${error.message}`);
    }
}

// UI狀態更新函數
function updateUI() {
    const btn = document.getElementById('connectBtn');
    if (walletState.isConnected) {
        btn.innerHTML = "✔️ 已連接";
        btn.style.backgroundColor = "#4CAF50";
    } else {
        btn.innerHTML = "🔗 連接錢包";
        btn.style.backgroundColor = "#f44336";
    }
}
/* 
// ========== 加密解密配置 ==========
const ENCRYPTION_CONFIG = {
    key: CryptoJS.enc.Utf8.parse("32-ByteSecretKey-123456789012"), // 必須與加密時一致
    iv: CryptoJS.enc.Utf8.parse("16-ByteInitVector"), // 必須與加密時一致
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
};

// 解密函數（安全增強版）
function decryptField(cipherText) {
    if (!cipherText || typeof cipherText !== 'string') {
        console.warn("無效的密文輸入");
        return "N/A";
    }

    try {
        // 驗證是否為合法Base64格式
        if (!/^[A-Za-z0-9+/=]+$/.test(cipherText)) {
            throw new Error("密文格式無效");
        }

        const bytes = CryptoJS.AES.decrypt(
            cipherText,
            ENCRYPTION_CONFIG.key,
            { 
                iv: ENCRYPTION_CONFIG.iv,
                mode: ENCRYPTION_CONFIG.mode,
                padding: ENCRYPTION_CONFIG.padding
            }
        );
        
        const decrypted = bytes.toString(CryptoJS.enc.Utf8);
        
        // 驗證解密結果
        if (!decrypted) {
            throw new Error("解密結果為空");
        }
        
        return decrypted;
    } catch (error) {
        console.error(`解密失敗 (${cipherText.slice(0,10)}...):`, error);
        return "⚠️ 解密錯誤";
    }
}
*/
// 查詢保單
async function queryPolicy() {
	if (!insuranceContract) {
        alert("請先連接錢包！");
        await connectWallet();
        if (!insuranceContract) {
            alert("合約尚未初始化，請重新整理頁面");
            return;
        }
    }
    const policyNumber = document.getElementById("policyNumber").value;
    const resultDiv = document.getElementById("result");
    const loading = document.getElementById("loading");
    
    try {
        if (!policyNumber) throw new Error("請輸入保單號碼");
        
        loading.style.display = "block";
        resultDiv.innerHTML = "";

        // === 核心權限驗證開始 ===
        // 並行獲取必要數據提升性能
        const [currentAddress, policyInfo, isAuthorized] = await Promise.all([
            insuranceContract.runner.address,  // 獲取當前連接地址
            insuranceContract.policies(policyNumber), // 獲取保單基本信息
            insuranceContract.isAuthorized(policyNumber, await insuranceContract.runner.address) // 檢查授權狀態
        ]);

        // 解析保單所有者地址（根據ABI結構，owner在第10位）
        const policyOwner = policyInfo[10]; 

        // 權限驗證邏輯
        const isOwner = currentAddress.toLowerCase() === policyOwner.toLowerCase();
        if (!isOwner && !isAuthorized) {
            throw new Error("您不是保單所有者且未被授權查看此保單");
        }
        // === 核心權限驗證結束 ===

        // 獲取保單數據
        const policyData = await insuranceContract.getPolicy(policyNumber);
        console.log("原始保單數據:", policyData);
        
        // 數值格式化工具函數
        const formatters = {
            weiToEth: (wei) => ethers.formatEther(wei),
            timestampToDate: (timestamp) => {
                if (!timestamp) return '未設置';
                try {
                    return new Date(Number(timestamp) * 1000).toLocaleDateString();
                } catch {
                    return '無效日期';
                }
            },
            bigIntToString: (value) => value.toString(),
            parsePolicyData: (rawData) => ({
                policyHolder: rawData[0],
                insuredPerson: rawData[1],
                insuranceAmount: rawData[2],
                premiumPeriod: Number(rawData[3]),
                premiumAmount: rawData[4],
                startDate: formatters.timestampToDate(rawData[5]),
                beneficiary: rawData[6],
                growthRate: Number(rawData[7]),
                declaredInterestRate: Number(rawData[8]),
                pdfHash: rawData[9]
            })
        };

        // 獲取並格式化數據
        const rawData = await insuranceContract.getPolicy(policyNumber);
        const formattedData = formatters.parsePolicyData(rawData);
        // 渲染數據
        renderPolicy(formattedData); 
        

        
        
    } catch (error) {
        let errorMsg = '查詢保單失敗: ';
        // 增强的错误处理：区分保单不存在和权限错误
            if (error.message.includes("Policy not found") || 
                error.message.includes("execution reverted")) {
                errorMsg+='保單不存在';
            } else if (error.message.includes("Not the policy owner") || 
                       error.message.includes("No permission")) {
                errorMsg+="您沒有查看此保單的權限";
            } else {
                errorMsg += error.message;
            }
            const resultDiv = document.getElementById('result');
            resultDiv.textContent = errorMsg;
            
    }
}

function renderPolicy(data) {
    const html = `
    <div class="policy-info">
        <p>投保人: ${data.policyHolder}</p>
        <p>被保人: ${data.insuredPerson}</p>
        <p>保額: ${data.insuranceAmount} </p>
        <p>繳費年限: ${data.premiumPeriod} 年</p>
        <p>每期保費: ${data.premiumAmount} </p>
        <p>生效日期: ${data.startDate}</p>
        <p>受益人: ${data.beneficiary}</p>
        <p>增額比例: ${data.growthRate}%</p>
        <p>宣告利率: ${data.declaredInterestRate}%</p>
        <!--<p>保單文件: <a href="https://ipfs.io/ipfs/${data.pdfHash}" target="_blank">查看PDF</a></p>-->
    </div>
    `;
    document.getElementById("result").innerHTML = html;
}

function showError(msg) {
    document.getElementById("result").innerHTML = `
        <div class="error">
            ⚠️ ${msg}
        </div>
    `;
}

// 事件綁定
document.getElementById("connectBtn").addEventListener("click", connectWallet);
document.getElementById("queryBtn").addEventListener("click", queryPolicy);

/*以下是授權--------------------------------------------------------------------------*/
// 切換選項卡
function switchTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    document.getElementById(`${tabName}Tab`).classList.add('active');
    document.querySelector(`button[onclick="switchTab('${tabName}')"]`).classList.add('active');
}

// 授予權限
async function grantAuthorization() {
    try {
        const policyNumber = document.getElementById('authPolicyNumber').value;
        const address = document.getElementById('authAddress').value;
        
        // 驗證輸入
        if (!policyNumber || !address) {
            throw new Error("請填寫完整資料");
        }
        if (!ethers.isAddress(address)) {
            throw new Error("請輸入有效的錢包地址");
        }

        // 驗證調用者權限
        const policyOwner = await insuranceContract.policies(policyNumber).then(r => r[10]);
        const currentAddress = await insuranceContract.runner.address;
        
        if (currentAddress.toLowerCase() !== policyOwner.toLowerCase()) {
            throw new Error("只有保單所有者可以授權");
        }

        // 發送授權交易
        showAuthStatus("⏳ 正在提交授權交易...", "processing");
        const tx = await insuranceContract.authorizePolicyAccess(policyNumber, address);
        await tx.wait();
        
        showAuthStatus("✅ 授權成功！", "success");
    } catch (error) {
        console.error("授權失敗:", error);
        showAuthStatus(`❌ 錯誤: ${error.message}`, "error");
    }
}

// 撤銷權限
async function revokeAuthorization() {
    try {
        const policyNumber = document.getElementById('authPolicyNumber').value;
        const address = document.getElementById('authAddress').value;
        
        // 輸入驗證
        if (!policyNumber || !address) {
            throw new Error("請填寫完整資料");
        }
        if (!ethers.isAddress(address)) {
            throw new Error("無效的錢包地址格式");
        }

		// 驗證調用者權限
        const policyOwner = await insuranceContract.policies(policyNumber).then(r => r[10]);
        const currentAddress = await insuranceContract.runner.address;
		if (currentAddress.toLowerCase() !== policyOwner.toLowerCase()) {
            throw new Error("只有保單所有者可以授權");
        }
        
        showAuthStatus("⏳ 正在提交撤銷交易...", "processing");
        const tx = await insuranceContract.revokePolicyAccess(policyNumber, address);
        await tx.wait();
        
        showAuthStatus("✅ 權限撤銷成功！", "success");
    } catch (error) {
        console.error("撤銷權限失敗:", error);
        // 友好錯誤提示
        let errorMsg = error.message;
        if (error.info?.error?.message.includes("caller is not the owner")) {
            errorMsg = "操作被拒絕：您不是保單的所有者";
        }
        showAuthStatus(`❌ 錯誤: ${errorMsg}`, "error");
    }
}

// 狀態顯示函數
function showAuthStatus(message, type) {
    const statusDiv = document.getElementById('authStatus');
    statusDiv.innerHTML = message;
    statusDiv.className = `auth-status ${type}`;

    // 自動清除狀態
    if (type !== 'processing') {
        setTimeout(() => {
            statusDiv.innerHTML = '';
            statusDiv.className = 'auth-status';
        }, 5000);
    }
}