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