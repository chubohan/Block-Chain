// 创建小星星动画
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

const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; // 替换为实际合约地址
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
]; // 保持与之前提供的ABI一致

let insuranceContract = null;

    // 连接钱包函数（改造后）
async function connectWallet() {
try {
    if (!window.ethereum) throw new Error("请安装MetaMask");
    
    // 初始化Provider
    const provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send("eth_requestAccounts", []);
    
    // 获取Signer
    const signer = await provider.getSigner();
    // 初始化合约实例
    insuranceContract = new ethers.Contract(
        "0x5FbDB2315678afecb367f032d93F642f64180aa3", // 替换实际地址
        contractABI,
        signer
    );
    
// 验证合约连接
console.log("合约实例:", insuranceContract);
    console.log("合约地址:", await insuranceContract.getAddress());
    // 更新钱包状态
    const address = await signer.getAddress();
    document.getElementById("walletAddress").textContent = 
        `你的錢包:${address.slice(0,6)}...${address.slice(-4)}`;
}
    catch (error) {
    console.error("连接错误:", error);
    alert(`连接失败: ${error.message}`);
    }
}
// UI状态更新函数
function updateUI() {
const btn = document.getElementById('connectBtn');
if (walletState.isConnected) {
    btn.innerHTML = "✔️ 已连接";
    btn.style.backgroundColor = "#4CAF50";
} else {
    btn.innerHTML = "🔗 连接钱包";
    btn.style.backgroundColor = "#f44336";
}
}
// ========== 加密解密配置 ==========
const ENCRYPTION_CONFIG = {
key: CryptoJS.enc.Utf8.parse("32-ByteSecretKey-123456789012"), // 必须与加密时一致
iv: CryptoJS.enc.Utf8.parse("16-ByteInitVector"), // 必须与加密时一致
mode: CryptoJS.mode.CBC,
padding: CryptoJS.pad.Pkcs7
};

// 解密函数（安全增强版）
function decryptField(cipherText) {
if (!cipherText || typeof cipherText !== 'string') {
    console.warn("无效的密文输入");
    return "N/A";
}

try {
    // 验证是否为合法Base64格式
    if (!/^[A-Za-z0-9+/=]+$/.test(cipherText)) {
        throw new Error("密文格式无效");
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
    
    // 验证解密结果
    if (!decrypted) {
        throw new Error("解密结果为空");
    }
    
    return decrypted;
} catch (error) {
    console.error(`解密失败 (${cipherText.slice(0,10)}...):`, error);
    return "⚠️ 解密错误";
}
}

    // 查询保单
    async function queryPolicy() {
        const policyNumber = document.getElementById("policyNumber").value;
        const resultDiv = document.getElementById("result");
        const loading = document.getElementById("loading");
        
        try {
            if (!policyNumber) throw new Error("请输入保单号码");
            

            loading.style.display = "block";
            resultDiv.innerHTML = "";

                // === 核心权限验证开始 ===
    // 并行获取必要数据提升性能
    const [currentAddress, policyInfo, isAuthorized] = await Promise.all([
        insuranceContract.runner.address,  // 获取当前连接地址
        insuranceContract.policies(policyNumber), // 获取保单基本信息
        insuranceContract.isAuthorized(policyNumber, await insuranceContract.runner.address) // 检查授权状态
    ]);

    // 解析保单所有者地址（根据ABI结构，owner在第10位）
    const policyOwner = policyInfo[10]; 

    // 权限验证逻辑
    const isOwner = currentAddress.toLowerCase() === policyOwner.toLowerCase();
    if (!isOwner && !isAuthorized) {
        throw new Error("⚠️ 无访问权限：您不是保单所有者且未被授权查看此保单");
    }
    // === 核心权限验证结束 ===



            // 获取保单数据
            const policyData = await insuranceContract.getPolicy(policyNumber);
    console.log("原始保单数据:", policyData);
            
            // 数值格式化工具函数
const formatters = {
weiToEth: (wei) => ethers.formatEther(wei),
timestampToDate: (timestamp) => {
if (!timestamp) return '未设置';
try {
    return new Date(Number(timestamp) * 1000).toLocaleDateString();
} catch {
    return '无效日期';
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

            // 获取并格式化数据
const rawData = await insuranceContract.getPolicy(policyNumber);
const formattedData = formatters.parsePolicyData(rawData);
// 渲染数据
renderPolicy(formattedData);     
        } catch (error) {
            loading.style.display = "none";
            showError(`查询失败: ${error.message}`);
        }
    }
    function renderPolicy(data) {
const html = `
<div class="policy-info">
    
    <p>投保人: ${data.policyHolder}</p>
    <p>被保人: ${data.insuredPerson}</p>
    <p>保额: ${data.insuranceAmount} </p>
    <p>缴费年限: ${data.premiumPeriod} 年</p>
    <p>每期保费: ${data.premiumAmount} </p>
    <p>生效日期: ${data.startDate}</p>
    <p>受益人: ${data.beneficiary}</p>
    <p>增额比例: ${data.growthRate}%</p>
    <p>宣告利率: ${data.declaredInterestRate}%</p>
    <p>保单文件: <a href="https://ipfs.io/ipfs/${data.pdfHash}" target="_blank">查看PDF</a></p>
</div>
`;
document.getElementById("result").innerHTML = html;
}
    function showError(msg) {
        document.getElementById("result").innerHTML = `
            <div class="error">
                ⚠️ ${msg}
                ${msg.includes("权限") ? '<button onclick="connectWallet()">重新连接钱包</button>' : ''}
            </div>
        `;
    }

    // 事件绑定
    document.getElementById("connectBtn").addEventListener("click", connectWallet);
    document.getElementById("queryBtn").addEventListener("click", queryPolicy);
    
    
    
    /*以下是授權--------------------------------------------------------------------------*/
    // 切换选项卡
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

// 授予权限
async function grantAuthorization() {
try {
    const policyNumber = document.getElementById('authPolicyNumber').value;
    const address = document.getElementById('authAddress').value;
    
    // 验证输入
    if (!policyNumber || !address) {
        throw new Error("请填写完整信息");
    }
    if (!ethers.isAddress(address)) {
        throw new Error("请输入有效的钱包地址");
    }

    // 验证调用者权限
    const policyOwner = await insuranceContract.policies(policyNumber).then(r => r[10]);
    const currentAddress = await insuranceContract.runner.address;
    
    if (currentAddress.toLowerCase() !== policyOwner.toLowerCase()) {
        throw new Error("只有保单所有者可以授权");
    }

    // 发送授权交易
    showAuthStatus("⏳ 正在提交授权交易...", "processing");
    const tx = await insuranceContract.authorizePolicyAccess(policyNumber, address);
    await tx.wait();
    
    showAuthStatus("✅ 授权成功！", "success");
} catch (error) {
    console.error("授权失败:", error);
    showAuthStatus(`❌ 错误: ${error.message}`, "error");
}
}

// 撤销权限
async function revokeAuthorization() {
try {
    const policyNumber = document.getElementById('authPolicyNumber').value;
    const address = document.getElementById('authAddress').value;
    
    // 输入验证
    if (!policyNumber || !address) {
        throw new Error("请填写完整信息");
    }
    if (!ethers.isAddress(address)) {
        throw new Error("无效的钱包地址格式");
    }
    
    showAuthStatus("⏳ 正在提交撤销交易...", "processing");
    const tx = await insuranceContract.revokePolicyAccess(policyNumber, address);
    await tx.wait();
    
    showAuthStatus("✅ 权限撤销成功！", "success");
} catch (error) {
    console.error("撤销权限失败:", error);
    // 友好错误提示
    let errorMsg = error.message;
    if (error.info?.error?.message.includes("caller is not the owner")) {
        errorMsg = "操作被拒绝：您不是该保单的所有者";
    }
    showAuthStatus(`❌ 错误: ${error.message}`, "error");
}
}

// 状态显示函数
function showAuthStatus(message, type) {
const statusDiv = document.getElementById('authStatus');
statusDiv.innerHTML = message;
statusDiv.className = `auth-status ${type}`;

// 自动清除状态
if (type !== 'processing') {
    setTimeout(() => {
        statusDiv.innerHTML = '';
        statusDiv.className = 'auth-status';
    }, 5000);
}
}