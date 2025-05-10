document.getElementById("familyForm").addEventListener("submit", function(event) {
    event.preventDefault(); // 防止表單刷新

    const idNumber = document.getElementById("idNumber").value;
    const policyList = document.getElementById("familyPolicyList");
    const policyItems = document.getElementById("policyItems");

    // 清空舊的列表
    policyItems.innerHTML = "";

    // 假設這是查詢結果 (實際應該從後端獲取)
    const policies = [
        { name: "健康險", description: "提供醫療保障。" },
        { name: "意外險", description: "涵蓋各類意外事故。" },
        { name: "旅遊保險", description: "旅遊期間的風險保障。" }
    ];

    if (idNumber.trim() !== "") {
        policyList.style.display = "block";
        policies.forEach(policy => {
            let li = document.createElement("li");
            li.innerHTML = `<strong>${policy.name}</strong> - ${policy.description}`;
            policyItems.appendChild(li);
        });
    } else {
        alert("請輸入身份證號碼！");
    }
});

