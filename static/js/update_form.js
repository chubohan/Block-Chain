function createStars() {
    const numStars = 200;
    const starsContainer = document.querySelector(".stars");
    const pageHeight = document.body.scrollHeight;

    for (let i = 0; i < numStars; i++) {
        let star = document.createElement("div");
        star.classList.add("star");

        const x = Math.random() * window.innerWidth;
        const y = Math.random() * pageHeight;
        const duration = Math.random() * 2 + 1;
        const delay = Math.random() * 5;

        star.style.top = `${y}px`;
        star.style.left = `${x}px`;
        star.style.animationDuration = `${duration}s`;
        star.style.animationDelay = `${delay}s`;

        starsContainer.appendChild(star);
    }
}

createStars(); 

// 全局變量
        let provider, signer, contract;
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

        // 連接錢包
        async function connectWallet() {
            if (window.ethereum) {
                try {
                    await window.ethereum.request({ method: 'eth_requestAccounts' });
                    provider = new ethers.providers.Web3Provider(window.ethereum);
                    signer = provider.getSigner();
                    const address = await signer.getAddress();
                    document.getElementById('walletAddress').innerText = `已連接: ${address}`;
                    
                    contract = new ethers.Contract(contractAddress, contractABI, signer);
                    
                    window.ethereum.on('accountsChanged', (accounts) => {
                        if (accounts.length > 0) {
                            connectWallet();
                        } else {
                            document.getElementById('walletAddress').innerText = '未連接';
                        }
                    });
                } catch (error) {
                    console.error("錢包連接錯誤:", error);
                    alert(`錢包連接失敗: ${error.message}`);
                }
            } else {
                alert('請安裝 MetaMask 擴展程序!');
            }
        }

        // 載入保單
        async function loadPolicy() {
            const policyNumber = document.getElementById('policyNumber').value.trim();
            if (!policyNumber) {
                alert('請輸入保單號碼');
                return;
            }
            
            try {
                const policy = await contract.getPolicy(policyNumber);
                
                // 顯示保單信息
                document.getElementById('policyHolder').value = policy[0];
                document.getElementById('insuredPerson').value = policy[1];
                document.getElementById('beneficiary').value = policy[6];
                
                // 顯示表單
                document.getElementById('policyForm').style.display = 'block';
                document.getElementById('pdfSection').style.display = 'block';
                
                // 重置PDF區域
                document.getElementById('fileName').innerText = '';
                document.getElementById('pdfUpload').value = '';
                
            } catch (error) {
                console.error("載入保單錯誤:", error);
                alert(`載入保單失敗: ${error.message}`);
            }
        }

        // 更新保單
        async function updatePolicy() {
            const policyNumber = document.getElementById('policyNumber').value.trim();
            const policyHolder = document.getElementById('policyHolder').value.trim();
            const insuredPerson = document.getElementById('insuredPerson').value.trim();
            const beneficiary = document.getElementById('beneficiary').value.trim();
            
            if (!policyHolder || !insuredPerson || !beneficiary) {
                alert('請填寫所有必填字段');
                return;
            }
            
            try {
                const tx = await contract.updatePolicy(
                    policyNumber,
                    policyHolder,
                    insuredPerson,
                    beneficiary
                );
                await tx.wait();
                swal("成功!", "保單已更新!", "success");
            } catch (error) {
                console.error("更新保單錯誤:", error);
                alert(`更新失敗: ${error.message}`);
            }
        }

        // 上傳PDF並自動更新到區塊鏈
        async function uploadAndUpdatePDF() {
            const policyNumber = document.getElementById('policyNumber').value.trim();
            const fileInput = document.getElementById('pdfUpload');
            
            if (!policyNumber) {
                alert('請先輸入並載入保單號碼');
                return;
            }
            
            if (fileInput.files.length === 0) {
                alert('請先選擇PDF文件');
                return;
            }

            // 顯示加載狀態
            document.getElementById('pdfStatus').style.display = 'block';
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('policyNumber', policyNumber);

            try {
                // 第一步：上傳文件到後端
                const response = await fetch('/policy/update_pdf', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                if (result.success) {
                    // 第二步：直接更新到區塊鏈（無需用戶干預）
                    const tx = await contract.updatePolicyPDF(policyNumber, result.pdf_hash);
                    await tx.wait();
                    
                    swal("成功!", "PDF已上傳並更新到區塊鏈!", "success");
                } else {
                    throw new Error(result.error || '上傳失敗');
                }
            } catch (error) {
                console.error('PDF更新錯誤:', error);
                alert(`PDF更新失敗: ${error.message}`);
            } finally {
                // 隱藏加載狀態
                document.getElementById('pdfStatus').style.display = 'none';
            }
        }

        // 顯示文件名
        document.getElementById('pdfUpload').addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || '未選擇文件';
            document.getElementById('fileName').innerText = fileName;
        });