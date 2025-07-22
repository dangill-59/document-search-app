const express = require('express');
const router = express.Router();

// Get projects
router.get('/', (req, res) => {
    try {
        console.log('📁 Projects requested');
        
        res.json([
            {
                id: 1,
                name: 'Sample Project',
                description: 'A sample project for testing the DMS system',
                created_at: new Date().toISOString(),
                created_by_name: 'Admin',
                document_count: 5,
                status: 'active'
            },
            {
                id: 2,
                name: 'Website Redesign',
                description: 'Redesigning the company website with new branding',
                created_at: new Date(Date.now() - 86400000).toISOString(),
                created_by_name: 'John Doe',
                document_count: 12,
                status: 'active'
            },
            {
                id: 3,
                name: 'Security Audit',
                description: 'Annual security audit and compliance review',
                created_at: new Date(Date.now() - 172800000).toISOString(),
                created_by_name: 'Jane Smith',
                document_count: 8,
                status: 'planning'
            }
        ]);
    } catch (error) {
        console.error('💥 Projects fetch error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch projects',
            message: error.message 
        });
    }
});

// Create project
router.post('/', (req, res) => {
    try {
        const { name, description, status } = req.body;
        console.log('📁 Creating project:', { name, description, status });
        
        res.status(201).json({
            id: Date.now(),
            name,
            description,
            status: status || 'active',
            created_at: new Date().toISOString(),
            created_by_name: 'Admin',
            document_count: 0,
            message: 'Project created successfully'
        });
    } catch (error) {
        console.error('💥 Project creation error:', error);
        res.status(500).json({ 
            error: 'Failed to create project',
            message: error.message 
        });
    }
});

console.log('📁 Project routes loaded');
module.exports = router;