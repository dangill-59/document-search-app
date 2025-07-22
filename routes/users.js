const express = require('express');
const router = express.Router();

// Get users
router.get('/', (req, res) => {
    try {
        console.log('👥 Users requested');
        
        res.json([
            {
                id: 1,
                username: 'admin',
                email: 'admin@example.com',
                first_name: 'Admin',
                last_name: 'User',
                role_name: 'admin',
                status: 'active',
                last_login: new Date().toISOString()
            },
            {
                id: 2,
                username: 'john.doe',
                email: 'john@example.com',
                first_name: 'John',
                last_name: 'Doe',
                role_name: 'user',
                status: 'active',
                last_login: new Date(Date.now() - 86400000).toISOString()
            }
        ]);
    } catch (error) {
        console.error('💥 Users fetch error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch users',
            message: error.message 
        });
    }
});

// Create user
router.post('/', (req, res) => {
    try {
        const userData = req.body;
        console.log('👤 Creating user:', userData.username);
        
        res.status(201).json({
            id: Date.now(),
            ...userData,
            status: 'active',
            created_at: new Date().toISOString(),
            message: 'User created successfully'
        });
    } catch (error) {
        console.error('💥 User creation error:', error);
        res.status(500).json({ 
            error: 'Failed to create user',
            message: error.message 
        });
    }
});

console.log('👥 User routes loaded');
module.exports = router;