document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const changePasswordForm = document.getElementById('changePasswordForm');

    loginForm.addEventListener('submit', function(event) {
        event.preventDefault();
        handleLogin();
    });

    changePasswordForm.addEventListener('submit', function(event) {
        event.preventDefault();
        handleChangePassword();
    });

    // Check if the user is already logged in by checking for a token in localStorage
    if (!localStorage.getItem('token')) {
        showLogin();
    } else {
        showControlPanel();
        fetchMacs();
    }
});


function showLogin() {
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('controlPanelSection').style.display = 'none';
}

function showControlPanel() {
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('controlPanelSection').style.display = 'block';
}

function handleLogin() {
    const usernameInput = document.getElementById('usernameInput');
    const passwordInput = document.getElementById('passwordInput');
    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput.value, password: passwordInput.value })
    })
    .then(response => response.json())
    .then(data => {
        if (data.token && data.user_id) {
            localStorage.setItem('token', data.token); // Save the token in localStorage
            localStorage.setItem('user_id', data.user_id); // Save the user ID in localStorage

            if (data.must_change_password) {
                // If the user must change the password, display the change password form
                if (confirm('You must change your password before continuing.')) {
                    document.getElementById('loginForm').style.display = 'none';
                    document.getElementById('changePasswordForm').style.display = 'block';
                } else {
                    document.getElementById('loginForm').style.display = 'block';
                    document.getElementById('changePasswordForm').style.display = 'none';
                }
            } else {
                // Otherwise, show the control panel
                showControlPanel();
                fetchMacs();
            }
        } else {
            alert('Invalid username or password.');
        }
    })
    .catch(error => {
        console.error('Error during login:', error);
        alert('Failed to log in. Please check your connection and try again.');
    });
}

function handleChangePassword() {
    const newPasswordInput = document.getElementById('newPasswordInput');
    const newPassword = newPasswordInput.value;

    if (newPassword.length >= 8 && /[a-z]/i.test(newPassword) && /[0-9]/.test(newPassword)) {
        fetch('/update-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            },
            body: JSON.stringify({new_password: newPassword, user_id: localStorage.getItem('user_id')})
        })
        
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Password changed successfully.');
                document.getElementById('loginSection').style.display = 'none';
                document.getElementById('controlPanelSection').style.display = 'block';
            } else {
                alert('Failed to change password.');
            }
        });
    } else {
        alert('Password does not meet complexity requirements.');
    }
}

function fetchMacs() {
    fetch('/macs', {
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
    })
    .then(response => response.json())
    .then(data => {
        const macList = document.getElementById('macList');
        macList.innerHTML = '';
        data.forEach(mac => {
            let listItem = document.createElement('li');
            listItem.textContent = mac;
            let deleteButton = document.createElement('button');
            deleteButton.textContent = 'Delete';
            deleteButton.onclick = () => deleteMac(mac);
            let wakeButton = document.createElement('button');
            wakeButton.textContent = 'Wake';
            wakeButton.onclick = () => wakeMac(mac);
            listItem.appendChild(deleteButton);
            listItem.appendChild(wakeButton);
            macList.appendChild(listItem);
        });
    });
}

function addMac() {
    const macInput = document.getElementById('macInput');
    fetch('/macs', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: JSON.stringify({ mac: macInput.value })
    }).then(response => {
        if (response.ok) {
            macInput.value = '';
            fetchMacs();
        } else {
            alert('Failed to add MAC address');
        }
    });
}

function deleteMac(mac) {
    fetch(`/macs/${mac}`, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
    }).then(response => {
        if (response.ok) {
            fetchMacs();
        } else {
            alert('Failed to delete MAC address');
        }
    });
}

function wakeMac(mac) {
    fetch(`/macs/${mac}/wake`, {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
    }).then(response => {
        if (response.ok) {
            alert('Wake signal sent');
        } else {
            alert('Failed to send wake signal');
        }
    });
}

