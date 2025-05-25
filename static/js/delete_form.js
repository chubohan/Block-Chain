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

// 智能合約ABI (根據您的合約編譯後的ABI)
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

// 智能合約地址 (部署後替換為您的合約地址)
const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

let web3;
let contract;
let accounts = [];

// 連接MetaMask錢包
document.getElementById('connectWallet').addEventListener('click', async () => {
    try {
        if (window.ethereum) {
            web3 = new Web3(window.ethereum);
            await window.ethereum.enable();
            
            // 獲取帳戶
            accounts = await web3.eth.getAccounts();
            document.getElementById('walletAddress').textContent = accounts[0];
            
            // 初始化合約
            contract = new web3.eth.Contract(contractABI, contractAddress);
            
            // 啟用刪除按鈕
            document.getElementById('deleteBtn').disabled = false;
            
            // 隱藏連接按鈕
            document.getElementById('connectWallet').style.display = 'none';
            
            showResult('錢包連接成功!', 'success');
        } else {
            showResult('請安裝MetaMask擴展程序!', 'error');
        }
    } catch (error) {
        showResult('連接錢包失敗: ' + error.message, 'error');
    }
});

// 刪除保單
document.getElementById('deleteBtn').addEventListener('click', async () => {
    const policyNumber = document.getElementById('policyNumber').value.trim();
    
    if (!policyNumber) {
        showResult('請輸入保單編號', 'error');
        return;
    }
    
    try {
        // 先檢查保單是否存在
        const policy = await contract.methods.getPolicy(policyNumber).call({ from: accounts[0] });
        
        if (!policy || !policy[0]) {
            showResult('保單不存在', 'error');
            return;
        }
        
        // 執行刪除操作
        showResult('正在刪除保單，請等待交易確認...', 'success');
        
        const result = await contract.methods.deletePolicy(policyNumber)
            .send({ from: accounts[0] });
        
        showResult(`保單 ${policyNumber} 已成功刪除! 交易哈希: ${result.transactionHash}`, 'success');
        document.getElementById('policyNumber').value = '';
    } catch (error) {
        let errorMsg = '刪除保單失敗: ';
        
        if (error.message.includes("Not the policy owner")) {
            errorMsg += '您不是此保單的所有者，無權刪除';
        } else if (error.message.includes("Policy not found")) {
            errorMsg += '保單不存在';
        } else {
            errorMsg += error.message;
        }
        
        showResult(errorMsg, 'error');
    }
});

// 顯示結果
function showResult(message, type) {
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = 'block';
    resultDiv.textContent = message;
    resultDiv.className = 'result ' + type;
}