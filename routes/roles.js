const express = require('express');
const router = express.Router();

// Get roles
router.get('/', (req, res) => {
    try {
        console.log('🔐 Roles requested');
        
        res.json([
            {
                id: 1,
                name: 'admin',
                description: 'Full system access',
                permissions: ['admin_access', 'user_view', 'user_create', 'project_view', 'project_create'],
                user_count: 1
            },
            {
                id: 2,
                name: 'user',
                description: 'Standard user access',
                permissions: ['project_view', 'document_view'],
                user_count: 3
            }
        ]);
    } catch (error) {
        console.error('💥 Roles fetch error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch roles',
            message: error.message 
        });
    }
});

// Create role
router.post('/', (req, res) => {
    try {
        const { name, description, permissions } = req.body;
        console.log('🔐 Creating role:', name);
        
        res.status(201).json({
            id: Date.now(),
            name,
            description,
            permissions,
            user_count: 0,
            message: 'Role created successfully'
        });
    } catch (error) {
        console.error('💥 Role creation error:', error);
        res.status(500).json({ 
            error: 'Failed to create role',
            message: error.message 
        });
    }
});

console.log('🔐 Role routes loaded');
module.exports = router;