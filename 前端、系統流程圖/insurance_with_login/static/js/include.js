document.addEventListener('DOMContentLoaded', function () {
    // 動態加載 header
    fetch('static/components/header.html')
        .then(response => response.text())
        .then(data => {
            document.getElementById('header-container').innerHTML = data;
        })
        .catch(error => console.error("❌ 載入 Header 失敗:", error));

    // 動態加載 footer
    fetch('static/components/footer.html')
        .then(response => response.text())
        .then(data => {
            document.getElementById('footer-container').innerHTML = data;
        })
        .catch(error => console.error("❌ 載入 Footer 失敗:", error));
});
