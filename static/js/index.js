// Navbar隱藏顯示的邏輯
let lastScrollTop = 0;
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    let currentScroll = window.pageYOffset || document.documentElement.scrollTop;
    
    if (currentScroll > lastScrollTop) {
        navbar.classList.add('hidden'); // 向下滾動隱藏navbar
    } else {
        navbar.classList.remove('hidden'); // 向上滾動顯示navbar
    }
    lastScrollTop = currentScroll <= 0 ? 0 : currentScroll; // 防止滾動條小於0
});

// Function to create random stars
const starCount = 100;
const starsContainer = document.getElementById('stars');

for (let i = 0; i < starCount; i++) {
    const star = document.createElement('div');
    star.classList.add('star');
    star.style.width = `${Math.random() * 3 + 1}px`; // Random size
    star.style.height = star.style.width; // Ensure it's a circle
    star.style.top = `${Math.random() * 100}vh`; // Random vertical position
    star.style.left = `${Math.random() * 100}vw`; // Random horizontal position
    star.style.animationDuration = `${Math.random() * 2 + 1}s`; // Random twinkle speed
    starsContainer.appendChild(star);
}