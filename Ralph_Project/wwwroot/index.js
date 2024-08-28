document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('register-form');
    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;

        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }

        const response = await fetch('https://localhost:7023/api/Authenticate/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                email: email,
                password: password
            }),
        });

        const result = await response.json();

        if (response.ok) {
            alert('Registration successful!');
            window.location.href = 'login.html'; // Redirect to login page
        } else {
            alert(result.message);
        }
    });
});
