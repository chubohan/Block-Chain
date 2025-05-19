        const starContainer = document.querySelector('.stars');

        // 產生閃爍小星星
        const starCount = 150;
        for (let i = 0; i < starCount; i++) {
            const star = document.createElement('div');
            star.classList.add('star');
            const size = Math.random() * 2 + 1;
            star.style.width = `${size}px`;
            star.style.height = `${size}px`;
            star.style.top = `${Math.random() * 100}vh`;
            star.style.left = `${Math.random() * 100}vw`;
            star.style.animationDuration = `${1 + Math.random() * 3}s`;
            star.style.opacity = Math.random();
            starContainer.appendChild(star);
        }

        // 定時產生流星
        function createShootingStar() {
            const star = document.createElement('div');
            star.classList.add('shooting-star');
            star.style.top = `${Math.random() * 30 + 10}vh`; // 頂部範圍
            star.style.left = `${Math.random() * 100}vw`;
            starContainer.appendChild(star);

            setTimeout(() => {
                star.remove();
            }, 1000);
        }

        setInterval(createShootingStar, 3000);

        const starsContainer = document.querySelector('.stars');

  // 生成流星
  function createShootingStar() {
    const shootingStar = document.createElement('div');
    shootingStar.classList.add('shooting-star');
    shootingStar.style.top = `${Math.random()*50}vh`;
    shootingStar.style.left = `${Math.random()*80}vw`;
    starsContainer.appendChild(shootingStar);

    shootingStar.addEventListener('animationend', () => {
      shootingStar.remove();
    });
  }

  // 每3-6秒生成一顆流星
  setInterval(() => {
    createShootingStar();
  }, 3000 + Math.random()*3000);