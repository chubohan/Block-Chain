// 全域宣告 (必須!)
let web3 = null;
let account = null; // 明確初始化為 null
// 合約地址和 ABI（需與後端一致）



    async function connectWallet() {
      try {
        if (!window.ethereum) throw new Error("請先安裝 MetaMask");

        web3 = new Web3(window.ethereum);
        const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
        account = accounts[0];

        document.getElementById('walletAddress').textContent = account;
        document.getElementById('confirmButton').style.display = "inline-block";

        alert("錢包連接成功：" + account);
      } catch (error) {
        alert("連線失敗：" + error.message);
      }
    }

    async function confirmConnection() {
      try {
        const response = await fetch('/user/save-wallet', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ wallet: account })
        });

        const result = await response.json();
        if (result.success) {
          alert("錢包地址已成功儲存！");
        } else {
          alert("儲存失敗：" + result.message);
        }
      } catch (error) {
        alert("發送請求失敗：" + error.message);
      }
    }