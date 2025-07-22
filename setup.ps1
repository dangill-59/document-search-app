#!/bin/bash

echo "🚀 Setting up Document Management System..."

# Create directory structure
mkdir -p public/shared
mkdir -p uploads
mkdir -p images

# Move files to correct locations
echo "📁 Organizing files..."
mv index.html public/ 2>/dev/null || echo "index.html already in place"
mv indexadmin.html public/ 2>/dev/null || echo "indexadmin.html already in place"

# Create package.json if it doesn't exist
if [ ! -f package.json ]; then
    echo "📦 Creating package.json..."
    cat > package.json << EOF
{
  "name": "document-management-system",
  "version": "1.0.0",
  "description": "Business Document Management System with Role-Based Access",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "multer": "^1.4.5",
    "better-sqlite3": "^8.7.0",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.2",
    "uuid": "^9.0.0",
    "sharp": "^0.32.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  },
  "author": "Your Name",
  "license": "MIT"
}
EOF
fi

# Install dependencies
echo "📥 Installing dependencies..."
npm install

# Create shared login page
echo "🔐 Creating shared login page..."
cat > public/login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Management System - Login</title>
    <style>
        :root {
            --primary-color: #667eea;
            --primary-dark: #764ba2;
            --white: #ffffff;
            --text-dark: #333333;
            --text-light: #666666;
            --shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            --border-radius: 12px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: var(--border-radius);
            padding: 3rem;
            max-width: 400px;
            width: 100%;
            text-align: center;
            box-shadow: var(--shadow);
            animation: slideUp 0.5s ease-out;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        h1 {
            color: var(--primary-color);
            margin-bottom: 0.5rem;
            font-size: 1.8rem;
        }

        .subtitle {
            color: var(--text-light);
            margin-bottom: 2rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
            text-align: left;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--text-dark);
        }

        input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        button {
            width: 100%;
            padding: 12px 24px;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            color: var(--white);
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 8px;
            margin-top: 1rem;
            display: none;
        }

        .demo-info {
            margin-top: 2rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 0.9rem;
            color: var(--text-light);
        }

        .loading {
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid transparent;
            border-top: 2px solid currentColor;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>📁 Document Management</h1>
        <p class="subtitle">Business Document Management System</p>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" value="admin" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" value="admin123" required autocomplete="current-password">
            </div>
            <button type="submit" id="loginBtn">
                <span id="loginText">Sign In</span>
                <div id="loginLoader" class="loading"></div>
            </button>
        </form>
        
        <div id="loginError" class="error"></div>
        
        <div class="demo-info">
            <strong>Demo Credentials:</strong><br>
            Username: admin<br>
            Password: admin123
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('loginBtn');
            const loginText = document.getElementById('loginText');
            const loginLoader = document.getElementById('loginLoader');
            const errorDiv = document.getElementById('loginError');
            
            // Show loading state
            loginBtn.disabled = true;
            loginText.style.display = 'none';
            loginLoader.style.display = 'block';
            errorDiv.style.display = 'none';
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok && data.token) {
                    localStorage.setItem('dms_token', data.token);
                    
                    // Redirect based on user permissions
                    const isAdmin = data.user.permissions?.includes('admin_access');
                    window.location.href = isAdmin ? '/admin' : '/search';
                } else {
                    throw new Error(data.error || 'Login failed');
                }
            } catch (error) {
                errorDiv.textContent = error.message;
                errorDiv.style.display = 'block';
            } finally {
                // Reset loading state
                loginBtn.disabled = false;
                loginText.style.display = 'inline';
                loginLoader.style.display = 'none';
            }
        });

        // Check if already logged in
        if (localStorage.getItem('dms_token')) {
            fetch('/api/auth/validate', {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('dms_token')}` }
            })
            .then(response => response.json())
            .then(data => {
                if (data.user) {
                    const isAdmin = data.user.permissions?.includes('admin_access');
                    window.location.href = isAdmin ? '/admin' : '/search';
                }
            })
            .catch(() => {
                localStorage.removeItem('dms_token');
            });
        }
    </script>
</body>
</html>
EOF

# Update server.js to serve static files and handle routing
echo "🔧 Adding routing to server.js..."

# Add the routing code to server.js (you'll need to manually add this)
cat >> server.js << 'EOF'

// Serve static files and handle routing
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/search', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'indexadmin.html'));
});

// Catch-all route for client-side routing
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.redirect('/');
    }
});
EOF

echo "✅ Setup complete!"
echo ""
echo "🚀 To start the system:"
echo "   npm start"
echo ""
echo "🌐 Then visit: http://localhost:3000"
echo "🔐 Login with: admin / admin123"
echo ""
echo "📋 Admin users will see the full admin interface"
echo "👤 Regular users will see the search interface"