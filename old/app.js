// =====================================================
// Main App.js with Security Integration
// Save as: app.js (in your project root)
// =====================================================

const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// Middleware Setup
// =====================================================

// CORS configuration
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const method = req.method;
    const url = req.url;
    const ip = req.ip || req.connection.remoteAddress;
    
    console.log(`[${timestamp}] ${method} ${url} - ${ip}`);
    next();
});

// Static file serving
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'uploads')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// =====================================================
// Route Imports
// =====================================================

const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const documentRoutes = require('./routes/documents');
const userRoutes = require('./routes/users');
const roleRoutes = require('./routes/roles');

// Optional routes (uncomment as you create them)

// =====================================================
// API Routes
// =====================================================

// Health check endpoint (no auth required)
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '2.0.0-security',
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Authentication routes
app.use('/api/auth', authRoutes);

// Project routes
app.use('/api/projects', projectRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/users', userRoutes);
app.use('/api/roles', roleRoutes);

// Additional routes

// =====================================================
// API Documentation Endpoint
// =====================================================

app.get('/api/docs', (req, res) => {
    res.json({
        title: 'Document Management System API',
        version: '2.0.0',
        description: 'API endpoints for DMS with project-level security',
        endpoints: {
            authentication: {
                'POST /api/auth/login': 'User login',
                'POST /api/auth/register': 'User registration',
                'POST /api/auth/refresh': 'Refresh token',
                'GET /api/auth/me': 'Get current user info',
                'POST /api/auth/logout': 'User logout',
                'POST /api/auth/change-password': 'Change password'
            },
            projects: {
                'GET /api/projects': 'Get accessible projects',
                'POST /api/projects': 'Create new project',
                'GET /api/projects/:id': 'Get specific project',
                'PUT /api/projects/:id': 'Update project',
                'DELETE /api/projects/:id': 'Delete project',
                'GET /api/projects/:id/members': 'Get project members',
                'POST /api/projects/:id/members': 'Add project member',
                'PUT /api/projects/:id/members/:userId': 'Update member role',
                'DELETE /api/projects/:id/members/:userId': 'Remove member'
            }
        },
        security: {
            authentication: 'JWT Bearer token required for most endpoints',
            authorization: 'Role-based access control for projects',
            roles: ['owner', 'admin', 'contributor', 'viewer'],
            project_types: ['public', 'internal', 'restricted', 'private']
        }
    });
});

// =====================================================
// Frontend Routes (serve your HTML)
// =====================================================

// Serve your main HTML file from public folder
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve any additional static pages
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Catch all other routes and serve the main HTML (for SPA routing)
app.get('*', (req, res, next) => {
    // Skip API routes
    if (req.url.startsWith('/api/')) {
        return next();
    }
    
    // Serve main HTML file for all other routes
    res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
        if (err) {
            res.status(404).json({ 
                error: 'Page not found',
                message: 'The requested page does not exist'
            });
        }
    });
});
// =====================================================
// Error Handling Middleware
// =====================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        error: 'API endpoint not found',
        message: `The endpoint ${req.method} ${req.url} does not exist`,
        available_endpoints: '/api/docs'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('=== ERROR ===');
    console.error('Time:', new Date().toISOString());
    console.error('URL:', req.url);
    console.error('Method:', req.method);
    console.error('Error:', err);
    console.error('Stack:', err.stack);
    console.error('=============');

    // Don't expose error details in production
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    res.status(err.status || 500).json({
        error: 'Internal server error',
        message: isDevelopment ? err.message : 'Something went wrong',
        ...(isDevelopment && { stack: err.stack }),
        timestamp: new Date().toISOString()
    });
});

// =====================================================
// Graceful Shutdown
// =====================================================

process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

// =====================================================
// Start Server
// =====================================================

const server = app.listen(PORT, () => {
    console.log('');
    console.log('🚀 DMS Server with Security started successfully!');
    console.log('');
    console.log(`📡 Server running on: http://localhost:${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📊 API Documentation: http://localhost:${PORT}/api/docs`);
    console.log(`❤️  Health Check: http://localhost:${PORT}/api/health`);
    console.log('');
    console.log('🔒 Security features enabled:');
    console.log('   ✅ JWT Authentication');
    console.log('   ✅ Project-level access control');
    console.log('   ✅ Role-based permissions (Owner/Admin/Contributor/Viewer)');
    console.log('   ✅ Document classification');
    console.log('   ✅ Access logging and audit trails');
    console.log('   ✅ Input validation and sanitization');
    console.log('');
    console.log('📡 Available API endpoints:');
    console.log('   🔐 POST /api/auth/login          - User login');
    console.log('   👤 POST /api/auth/register       - User registration');
    console.log('   🔄 POST /api/auth/refresh        - Refresh token');
    console.log('   👤 GET  /api/auth/me             - Get current user');
    console.log('   📁 GET  /api/projects            - List accessible projects');
    console.log('   📁 POST /api/projects            - Create new project');
    console.log('   👥 GET  /api/projects/:id/members - Get project members');
    console.log('   👥 POST /api/projects/:id/members - Add project member');
    console.log('');
    console.log('🎯 Ready for requests!');
    console.log('');
});

// =====================================================
// Export for testing
// =====================================================

module.exports = app;