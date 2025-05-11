document.addEventListener('DOMContentLoaded', function () {
    console.log("✅ JavaScript 已載入");

    // 確保選單開關運作
    const menuToggle = document.querySelector('.menu-toggle');
    const navLinks = document.querySelector('.nav-links');

    if (menuToggle && navLinks) {
        menuToggle.addEventListener('click', function () {
            navLinks.classList.toggle('active');
            console.log("✅ 選單已切換");
        });

        // 點擊導航連結後關閉選單（適用於手機版）
        document.querySelectorAll('.nav-links a').forEach(item => {
            item.addEventListener('click', function () {
                navLinks.classList.remove('active');
                console.log("✅ 選單已關閉");
            });
        });
    } else {
        console.error("❌ 找不到 .menu-toggle 或 .nav-links，請檢查 HTML");
    }

    // 綁定按鈕點擊事件
    const buttons = document.querySelectorAll('.button');

    if (buttons.length > 0) {
        buttons.forEach(button => {
            button.addEventListener('click', function () {
                alert(`✅ 按鈕被點擊！按鈕內容：${button.innerText}`);
                console.log(`✅ ${button.innerText} 按鈕被點擊`);
            });
        });
    } else {
        console.error("❌ 沒有找到任何 .button 按鈕，請檢查 HTML");
    }
});

