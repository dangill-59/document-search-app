const express = require('express');
const router = express.Router();

// Get documents
router.get('/', (req, res) => {
    try {
        console.log('📄 Documents requested');
        
        res.json([
            {
                id: 1,
                title: 'Sample Document',
                description: 'A sample document for testing',
                project_id: 1,
                project_name: 'Sample Project',
                created_at: new Date().toISOString(),
                created_by_name: 'Admin',
                total_pages: 3,
                type: 'general'
            },
            {
                id: 2,
                title: 'Project Proposal',
                description: 'Initial project proposal document',
                project_id: 2,
                project_name: 'Website Redesign',
                created_at: new Date(Date.now() - 86400000).toISOString(),
                created_by_name: 'John Doe',
                total_pages: 15,
                type: 'document'
            }
        ]);
    } catch (error) {
        console.error('💥 Documents fetch error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch documents',
            message: error.message 
        });
    }
});

console.log('📄 Document routes loaded');
module.exports = router;