const API_PATHS = {
    verify: '/audio/api/admin/verify',
    files: '/audio/api/admin/files',
    whitelist: '/audio/api/admin/whitelist',
    logs: '/audio/api/admin/logs'
};

// 验证管理员身份
async function verifyAdmin() {
    const password = document.getElementById('adminKey').value;
    if (!password) {
        alert('请输入管理密钥');
        return;
    }

    try {
        const response = await fetch(API_PATHS.verify, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();
        if (response.ok) {
            // 保存token
            localStorage.setItem('admin_token', data.token);
            // 显示管理面板
            document.getElementById('loginPanel').style.display = 'none';
            document.getElementById('adminPanel').style.display = 'block';
            // 加载初始数据
            loadFiles();
        } else {
            alert(data.message || '验证失败');
        }
    } catch (error) {
        console.error('验证失败:', error);
        alert('验证失败，请重试');
    }
}

// 切换标签页
function switchTab(tabName) {
    // 隐藏所有标签页
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // 显示选中的标签页
    document.getElementById(`${tabName}Tab`).classList.add('active');
    event.target.classList.add('active');

    // 加载对应数据
    switch(tabName) {
        case 'files':
            loadFiles();
            break;
        case 'whitelist':
            loadWhitelist();
            break;
        case 'logs':
            loadLogs();
            break;
    }
}

// 登出
function logout() {
    localStorage.removeItem('admin_token');
    document.getElementById('loginPanel').style.display = 'block';
    document.getElementById('adminPanel').style.display = 'none';
    document.getElementById('adminKey').value = '';
}

// 页面加载时检查登录状态
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('admin_token');
    if (token) {
        document.getElementById('loginPanel').style.display = 'none';
        document.getElementById('adminPanel').style.display = 'block';
        loadFiles();
    }
}); 