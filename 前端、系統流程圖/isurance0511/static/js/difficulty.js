document.addEventListener("DOMContentLoaded", function () {
    const difficultySpan = document.getElementById("currentDifficulty");
    const statusMessage = document.getElementById("statusMessage");

    // 變更難度功能
    window.changeDifficulty = function () {
        const inputDifficulty = document.getElementById("manualDifficulty").value;

        if (inputDifficulty >= 1 && inputDifficulty <= 5) {
            difficultySpan.innerText = inputDifficulty;
            statusMessage.innerText = `難度已設定為 ${inputDifficulty}`;
            statusMessage.style.color = "green";
        } else {
            statusMessage.innerText = "請輸入 1 到 5 之間的難度等級";
            statusMessage.style.color = "red";
        }
    };
});
