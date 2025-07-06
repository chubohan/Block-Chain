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

        function handleGoogleLogin(response) {
            // 修改请求地址为 /user/auth/google
            fetch('/user/auth/google', {  // 添加蓝图前缀 /user
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ credential: response.credential })
            })
            .then(res => res.json())
            .then(data => {
                if (data.redirect) {
                    window.location.href = data.redirect;
                }
            });
        }