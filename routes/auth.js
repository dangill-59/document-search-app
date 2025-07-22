const express = require('express');
const router = express.Router();

// Login endpoint
router.post('/login', (req, res) => {
    try {
        console.log('🔐 Login attempt received:', req.body);
        
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                error: 'Missing credentials',
                message: 'Username and password are required' 
            });
        }
        
        // Simple hardcoded check for testing
        if (username === 'admin' && password === 'admin123') {
            console.log('✅ Login successful for:', username);
            
            res.json({ 
                token: 'mock-jwt-token-12345',
                user: {
                    id: 1,
                    username: 'admin',
                    first_name: 'Admin',
                    last_name: 'User',
                    role_name: 'admin',
                    email: 'admin@example.com',
                    permissions: ['admin_access', 'user_view', 'project_view', 'project_create', 'document_view', 'document_create']
                }
            });
        } else {
            console.log('❌ Login failed for:', username);
            
            res.status(401).json({ 
                error: 'Invalid credentials',
                message: 'Username or password is incorrect' 
            });
        }
    } catch (error) {
        console.error('💥 Login error:', error);
        res.status(500).json({ 
            error: 'Login failed',
            message: 'An error occurred during login',
            details: error.message 
        });
    }
});

// Validate token endpoint
router.get('/validate', (req, res) => {
    try {
        console.log('🔍 Token validation requested');
        
        res.json({
            user: {
                id: 1,
                username: 'admin',
                first_name: 'Admin',
                last_name: 'User',
                role_name: 'admin',
                email: 'admin@example.com',
                permissions: ['admin_access', 'user_view', 'project_view']
            }
        });
    } catch (error) {
        console.error('💥 Token validation error:', error);
        res.status(500).json({ 
            error: 'Validation failed',
            message: error.message 
        });
    }
});

console.log('🔗 Auth routes loaded');
module.exports = router;