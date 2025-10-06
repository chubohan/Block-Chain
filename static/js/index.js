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