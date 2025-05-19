function checkAgreement() {
    const checkbox = document.getElementById('agreeCheckbox');
    if (!checkbox.checked) {
    alert('請勾選「我已閱讀並同意上述聲明」');
    return false;
    }
    return true;
}

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