document.getElementById("loginForm").addEventListener("submit", function(event) {
    event.preventDefault(); // 防止表單刷新

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    if (username === "admin" && password === "password123") {
        alert("登入成功！");
        window.location.href = "index.html"; // 登入後跳轉回首頁
    } else {
        alert("帳號或密碼錯誤，請重試！");
    }
});
