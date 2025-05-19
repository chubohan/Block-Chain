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

function handleCredentialResponse(response) {
            fetch('/auth/google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ credential: response.credential })
            })
            .then(res => res.json())
            .then(data => window.location.href = '/profile')
            .catch(err => console.error('Google 登入失敗:', err));
        }