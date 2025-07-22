// =====================================================
// Security Middleware for DMS
// Save as: middleware/security.js
// =====================================================

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const jwt = require('jsonwebtoken');

// Database connection - UPDATE THIS PATH TO YOUR DATABASE FILE
const dbPath = path.join(__dirname, '..', 'database.db'); // Change this if your database is elsewhere
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('✅ Connected to SQLite database:', dbPath);
    }
});

// Promisify database operations for async/await
const dbGet = (query, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) {
                console.error('Database GET error:', err);
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
};

const dbAll = (query, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) {
                console.error('Database ALL error:', err);
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
};

const dbRun = (query, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) {
                console.error('Database RUN error:', err);
                reject(err);
            } else {
                resolve({ id: this.lastID, changes: this.changes });
            }
        });
    });
};

// =====================================================
// Authentication Middleware
// =====================================================

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ 
            error: 'Access token required',
            message: 'Please provide a valid JWT token in Authorization header'
        });
    }

    try {
        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        
        // Get fresh user data from database
        const user = await dbGet(`
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.first_name, 
                u.last_name,
                u.status,
                r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = ? AND u.status = 'active'
        `, [decoded.id]);

        if (!user) {
            return res.status(401).json({ 
                error: 'Invalid token',
                message: 'User not found or inactive'
            });
        }

        // Add user info to request
        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(403).json({ 
                error: 'Token expired',
                message: 'Please login again'
            });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ 
                error: 'Invalid token',
                message: 'Token is malformed'
            });
        } else {
            return res.status(403).json({ 
                error: 'Token verification failed',
                message: error.message
            });
        }
    }
};

// =====================================================
// Project Access Middleware
// =====================================================

const checkProjectAccess = (requiredPermission = 'view') => {
    return async (req, res, next) => {
        try {
            const projectId = req.params.projectId || req.params.id || req.body.projectId;
            const userId = req.user.id;

            if (!projectId) {
                return res.status(400).json({ 
                    error: 'Project ID required',
                    message: 'No project ID provided in request'
                });
            }

            // Check if project exists
            const projectExists = await dbGet('SELECT id FROM projects WHERE id = ?', [projectId]);
            if (!projectExists) {
                return res.status(404).json({ 
                    error: 'Project not found',
                    message: `Project with ID ${projectId} does not exist`
                });
            }

            // Check user's role in project
            const membership = await dbGet(`
                SELECT pm.role, p.permission_type, p.allow_public_view
                FROM project_members pm
                JOIN projects p ON pm.project_id = p.id
                WHERE pm.project_id = ? AND pm.user_id = ? AND pm.status = 'active'
            `, [projectId, userId]);

            let hasAccess = false;
            let userRole = null;

            if (membership) {
                // User is a project member
                userRole = membership.role;
                hasAccess = checkRolePermission(membership.role, requiredPermission);
            } else {
                // Check if project is public and user only needs view access
                const project = await dbGet(
                    'SELECT permission_type, allow_public_view FROM projects WHERE id = ?',
                    [projectId]
                );

                if (project && project.permission_type === 'public' && requiredPermission === 'view') {
                    hasAccess = true;
                    userRole = 'public';
                }
            }

            if (!hasAccess) {
                return res.status(403).json({ 
                    error: 'Insufficient permissions for this project',
                    message: `Required permission: ${requiredPermission}, User role: ${userRole || 'none'}`,
                    required: requiredPermission,
                    userRole: userRole || 'none'
                });
            }

            // Add project info to request for use in route handlers
            req.projectRole = userRole;
            req.projectId = projectId;
            next();

        } catch (error) {
            console.error('Project access check error:', error);
            res.status(500).json({ 
                error: 'Failed to check project access',
                message: 'Internal server error during permission check'
            });
        }
    };
};

// =====================================================
// Permission Checking Functions
// =====================================================

function checkRolePermission(role, permission) {
    const permissions = {
        owner: [
            'view', 'edit', 'delete', 'manage_members', 'manage_settings', 
            'create_documents', 'delete_project', 'transfer_ownership'
        ],
        admin: [
            'view', 'edit', 'delete', 'manage_members', 'manage_settings',
            'create_documents'
        ],
        contributor: [
            'view', 'edit', 'create_documents'
        ],
        viewer: [
            'view'
        ],
        public: [
            'view'
        ]
    };

    return permissions[role]?.includes(permission) || false;
}

async function hasProjectAccess(userId, projectId, requiredPermission = 'view') {
    try {
        const membership = await dbGet(`
            SELECT pm.role, p.permission_type
            FROM project_members pm
            JOIN projects p ON pm.project_id = p.id
            WHERE pm.project_id = ? AND pm.user_id = ? AND pm.status = 'active'
        `, [projectId, userId]);

        if (membership) {
            return checkRolePermission(membership.role, requiredPermission);
        }

        // Check if project is public and only view access is needed
        const project = await dbGet(
            'SELECT permission_type FROM projects WHERE id = ? AND permission_type = ?',
            [projectId, 'public']
        );

        return project && requiredPermission === 'view';
    } catch (error) {
        console.error('Access check error:', error);
        return false;
    }
}

// =====================================================
// Access Logging Functions
// =====================================================

async function logDocumentAccess(documentId, userId, action, ipAddress = null, userAgent = null, details = null) {
    try {
        await dbRun(`
            INSERT INTO document_access_logs (document_id, user_id, action, ip_address, user_agent, details, accessed_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        `, [documentId, userId, action, ipAddress, userAgent, details]);
        
        console.log(`📄 Document access logged: User ${userId} performed ${action} on document ${documentId}`);
    } catch (error) {
        console.error('Failed to log document access:', error);
    }
}

async function logProjectAccess(projectId, userId, action, ipAddress = null, details = null) {
    try {
        await dbRun(`
            INSERT INTO project_access_logs (project_id, user_id, action, ip_address, details, accessed_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        `, [projectId, userId, action, ipAddress, details]);
        
        console.log(`📁 Project access logged: User ${userId} performed ${action} on project ${projectId}`);
    } catch (error) {
        console.error('Failed to log project access:', error);
    }
}

// =====================================================
// Admin Check Middleware
// =====================================================

const requireAdmin = async (req, res, next) => {
    try {
        const userRole = await dbGet(`
            SELECT r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
        `, [req.user.id]);

        if (userRole?.role_name === 'admin') {
            next();
        } else {
            res.status(403).json({ 
                error: 'Admin access required',
                message: 'This endpoint requires administrator privileges'
            });
        }
    } catch (error) {
        res.status(500).json({ 
            error: 'Failed to check admin permissions',
            message: 'Internal server error'
        });
    }
};

// =====================================================
// Utility Functions
// =====================================================

// Get user's projects with their roles
async function getUserProjects(userId) {
    try {
        return await dbAll(`
            SELECT 
                p.id,
                p.name,
                p.permission_type,
                pm.role
            FROM projects p
            LEFT JOIN project_members pm ON p.id = pm.project_id AND pm.user_id = ? AND pm.status = 'active'
            WHERE pm.user_id = ? OR p.permission_type = 'public'
        `, [userId, userId]);
    } catch (error) {
        console.error('Failed to get user projects:', error);
        return [];
    }
}

// Check if user can access document
async function canAccessDocument(userId, documentId, requiredPermission = 'view') {
    try {
        const document = await dbGet(`
            SELECT d.project_id, d.is_private, d.classification
            FROM documents d
            WHERE d.id = ?
        `, [documentId]);

        if (!document) return false;

        // Check project access first
        const hasProjectAccess = await hasProjectAccess(userId, document.project_id, requiredPermission);
        if (!hasProjectAccess) return false;

        // If document is private, user needs contributor+ role
        if (document.is_private && requiredPermission !== 'view') {
            const membership = await dbGet(`
                SELECT role FROM project_members 
                WHERE project_id = ? AND user_id = ? AND status = 'active'
            `, [document.project_id, userId]);

            return membership && ['owner', 'admin', 'contributor'].includes(membership.role);
        }

        return true;
    } catch (error) {
        console.error('Document access check error:', error);
        return false;
    }
}

// =====================================================
// Error Handling
// =====================================================

process.on('SIGINT', () => {
    console.log('🛑 Closing database connection...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('✅ Database connection closed');
        }
        process.exit(0);
    });
});

// =====================================================
// Exports
// =====================================================

module.exports = {
    // Main middleware functions
    authenticateToken,
    checkProjectAccess,
    requireAdmin,
    
    // Permission checking functions
    checkRolePermission,
    hasProjectAccess,
    canAccessDocument,
    
    // Logging functions
    logDocumentAccess,
    logProjectAccess,
    
    // Database utilities
    dbGet,
    dbAll,
    dbRun,
    
    // Utility functions
    getUserProjects
};