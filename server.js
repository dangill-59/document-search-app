// server.js - Enhanced Document Management System Server with PDF Page Splitting, Edit Fields & Soft Delete
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');

// PDF processing libraries - INSTALL THESE FIRST
const pdf2pic = require('pdf2pic');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const UPLOAD_DIR = './uploads';
const IMAGE_DIR = './images';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/images', express.static(IMAGE_DIR));
app.use(express.static('public'));

// Database setup
const db = new Database('dms.db');

// CRITICAL: Enable foreign key constraints (disabled by default in SQLite)
db.pragma('foreign_keys = ON');
console.log('✅ Foreign key constraints enabled');

// Database initialization with enhanced schema and foreign key support
function initializeDatabase() {
    try {
        // Ensure foreign keys are enabled
        db.pragma('foreign_keys = ON');
        console.log('✅ Foreign key constraints enabled during initialization');
        
        db.exec(`
        -- Roles table (must be created first due to foreign key dependencies)
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            permissions TEXT, -- JSON string of permissions
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            role_id INTEGER,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES roles (id)
        );

        -- Projects table (updated with new fields)
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            type TEXT DEFAULT 'custom',
            color TEXT DEFAULT '#667eea',
            status TEXT DEFAULT 'active',
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        );

        -- Project roles table (for role-based access to projects)
        CREATE TABLE IF NOT EXISTS project_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            assigned_by INTEGER,
            assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users (id),
            UNIQUE(project_id, role_id)
        );

        -- Project fields table (custom fields for each project)
        CREATE TABLE IF NOT EXISTS project_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            field_name TEXT NOT NULL,
            field_label TEXT NOT NULL,
            field_type TEXT NOT NULL, -- text, number, date, dropdown, checkbox
            field_options TEXT, -- JSON for dropdown options
            required BOOLEAN DEFAULT 0,
            display_order INTEGER DEFAULT 0,
            FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
        );

        -- Documents table (with soft delete support)
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            document_type TEXT,
            status TEXT DEFAULT 'active',
            total_pages INTEGER DEFAULT 0,
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        );

        -- Document field values (custom field values for documents)
        CREATE TABLE IF NOT EXISTS document_field_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER,
            field_id INTEGER,
            field_value TEXT,
            FOREIGN KEY (document_id) REFERENCES documents (id) ON DELETE CASCADE,
            FOREIGN KEY (field_id) REFERENCES project_fields (id) ON DELETE CASCADE
        );

        -- Document pages table (ENHANCED for page splitting with soft delete)
        CREATE TABLE IF NOT EXISTS document_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER,
            page_number INTEGER,
            file_path TEXT NOT NULL,
            file_name TEXT,
            file_size INTEGER,
            mime_type TEXT,
            thumbnail_path TEXT,
            annotations TEXT, -- JSON string of annotations
            page_order INTEGER DEFAULT 0,
            source_file_name TEXT, -- Original filename if from PDF
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents (id) ON DELETE CASCADE
        );

        -- User project access (kept for granular user access)
        CREATE TABLE IF NOT EXISTS user_project_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            project_id INTEGER,
            access_level TEXT, -- read, edit, delete
            granted_by INTEGER,
            granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
            FOREIGN KEY (granted_by) REFERENCES users (id)
        );

        -- Audit log
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            table_name TEXT,
            record_id INTEGER,
            details TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        `);

        // Function to check if column exists
        function columnExists(tableName, columnName) {
            try {
                const tableInfo = db.prepare(`PRAGMA table_info(${tableName})`).all();
                return tableInfo.some(col => col.name === columnName);
            } catch (error) {
                return false;
            }
        }

        // Add missing columns to existing tables if they don't exist
        const migrations = [
            // Add source_file_name column for PDF splitting
            { 
                table: 'document_pages', 
                column: 'source_file_name', 
                definition: 'TEXT',
                updateExisting: null
            },
            // Add status column to document_pages for soft delete
            { 
                table: 'document_pages', 
                column: 'status', 
                definition: 'TEXT DEFAULT \'active\'',
                updateExisting: "UPDATE document_pages SET status = 'active' WHERE status IS NULL"
            },
            // Projects table migrations
            { 
                table: 'projects', 
                column: 'type', 
                definition: 'TEXT DEFAULT \'custom\'',
                updateExisting: "UPDATE projects SET type = 'custom' WHERE type IS NULL"
            },
            { 
                table: 'projects', 
                column: 'color', 
                definition: 'TEXT DEFAULT \'#667eea\'',
                updateExisting: "UPDATE projects SET color = '#667eea' WHERE color IS NULL"
            },
            { 
                table: 'projects', 
                column: 'status', 
                definition: 'TEXT DEFAULT \'active\'',
                updateExisting: "UPDATE projects SET status = 'active' WHERE status IS NULL"
            },
            { 
                table: 'projects', 
                column: 'updated_at', 
                definition: 'DATETIME',
                updateExisting: "UPDATE projects SET updated_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL"
            },
            
            // Documents table migrations
            { 
                table: 'documents', 
                column: 'status', 
                definition: 'TEXT DEFAULT \'active\'',
                updateExisting: "UPDATE documents SET status = 'active' WHERE status IS NULL"
            },
            { 
                table: 'documents', 
                column: 'updated_at', 
                definition: 'DATETIME',
                updateExisting: "UPDATE documents SET updated_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL"
            },
            
            // Users table migrations
            { 
                table: 'users', 
                column: 'status', 
                definition: 'TEXT DEFAULT \'active\'',
                updateExisting: "UPDATE users SET status = 'active' WHERE status IS NULL"
            },
            { 
                table: 'users', 
                column: 'updated_at', 
                definition: 'DATETIME',
                updateExisting: "UPDATE users SET updated_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL"
            },
            
            // Project fields migrations
            { 
                table: 'project_fields', 
                column: 'field_label', 
                definition: 'TEXT',
                updateExisting: "UPDATE project_fields SET field_label = field_name WHERE field_label IS NULL OR field_label = ''"
            },
            
            // Roles table migrations
            { 
                table: 'roles', 
                column: 'updated_at', 
                definition: 'DATETIME',
                updateExisting: "UPDATE roles SET updated_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL"
            }
        ];

        migrations.forEach(migration => {
            try {
                const { table, column, definition, updateExisting } = migration;
                
                // Check if column exists before trying to add it
                if (!columnExists(table, column)) {
                    // Add the column
                    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
                    console.log(`✅ Added column ${table}.${column}`);
                    
                    // Update existing records if needed
                    if (updateExisting) {
                        const migrationResult = db.prepare(updateExisting).run();
                        if (migrationResult.changes > 0) {
                            console.log(`✅ Updated ${migrationResult.changes} existing records in ${table}.${column}`);
                        }
                    }
                } else {
                    console.log(`⏭️  Column ${table}.${column} already exists`);
                }
            } catch (e) {
                if (!e.message.includes('duplicate column name')) {
                    console.log(`⚠️  Migration warning for ${migration.table}.${migration.column}: ${e.message}`);
                }
            }
        });

        // Create default roles and users with proper foreign key handling
        try {
            const adminRole = db.prepare(`
                INSERT OR IGNORE INTO roles (name, description, permissions) 
                VALUES (?, ?, ?)
            `).run('Administrator', 'Full system access', JSON.stringify([
                'user_create', 'user_edit', 'user_delete', 'user_view',
                'role_create', 'role_edit', 'role_delete', 'role_view',
                'project_create', 'project_edit', 'project_delete', 'project_view',
                'document_create', 'document_edit', 'document_delete', 'document_view',
                'document_scan', 'document_upload', 'document_print', 'document_email',
                'document_annotate', 'admin_access'
            ]));

            // Create user role
            db.prepare(`
                INSERT OR IGNORE INTO roles (name, description, permissions) 
                VALUES (?, ?, ?)
            `).run('User', 'Standard user access', JSON.stringify([
                'document_view', 'document_scan', 'document_upload', 'document_print', 'document_email'
            ]));

            // Create Manager role
            db.prepare(`
                INSERT OR IGNORE INTO roles (name, description, permissions) 
                VALUES (?, ?, ?)
            `).run('Manager', 'Management access to projects and documents', JSON.stringify([
                'project_create', 'project_edit', 'project_view',
                'document_create', 'document_edit', 'document_view',
                'document_scan', 'document_upload', 'document_print', 'document_email'
            ]));

            // Create default admin user with proper role reference
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            db.prepare(`
                INSERT OR IGNORE INTO users (username, email, password, first_name, last_name, role_id) 
                VALUES (?, ?, ?, ?, ?, ?)
            `).run('admin', 'admin@dms.local', hashedPassword, 'System', 'Administrator', 1);

            console.log('✅ Enhanced database initialized successfully');
            console.log('📋 Default admin user: admin / admin123');
            console.log('🔄 PDF page splitting enabled');
            console.log('✏️ Document field editing enabled');
            console.log('🗑️ Document soft delete enabled');
            console.log('🔄 Page drag & drop reordering enabled');
            console.log('🔧 Admin panel endpoints ready');
            console.log('🔗 Foreign key constraints properly configured');
        } catch (seedError) {
            console.error('⚠️  Database seeding failed:', seedError.message);
        }
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        throw error;
    }
}

// Helper function to validate foreign key relationships
function validateForeignKeys() {
    try {
        const foreignKeyCheck = db.prepare('PRAGMA foreign_key_check').all();
        if (foreignKeyCheck.length > 0) {
            console.error('❌ Foreign key violations found:', foreignKeyCheck);
            return false;
        }
        return true;
    } catch (error) {
        console.error('❌ Error checking foreign keys:', error);
        return false;
    }
}

// File upload configuration
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadPath = path.join(UPLOAD_DIR, 'temp');
        await fs.mkdir(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}_${file.originalname}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf|tiff|tif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type. Supported: PDF, JPG, PNG, TIFF'));
        }
    }
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

function authorize(permissions) {
    return (req, res, next) => {
        const user = req.user;
        const userRole = db.prepare('SELECT permissions FROM roles WHERE id = ?').get(user.role_id);
        
        if (!userRole) {
            return res.status(403).json({ error: 'No role assigned' });
        }

        const userPermissions = JSON.parse(userRole.permissions);
        const hasPermission = permissions.some(permission => userPermissions.includes(permission));

        if (!hasPermission && !userPermissions.includes('admin_access')) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        next();
    };
}

function hasProjectAccess(userId, projectId, requiredLevel = 'read') {
    try {
        // Admins always have access
        const userRole = db.prepare(`
            SELECT r.permissions FROM users u 
            JOIN roles r ON u.role_id = r.id 
            WHERE u.id = ?
        `).get(userId);
        
        if (userRole) {
            const permissions = JSON.parse(userRole.permissions || '[]');
            if (permissions.includes('admin_access')) {
                return true;
            }
        }

        // Check role-based project access
        const roleAccess = db.prepare(`
            SELECT pr.id FROM project_roles pr
            JOIN users u ON u.role_id = pr.role_id
            WHERE u.id = ? AND pr.project_id = ?
        `).get(userId, projectId);
        
        if (roleAccess) {
            return true;
        }

        // Check direct user access (fallback)
        const directAccess = db.prepare(`
            SELECT access_level FROM user_project_access 
            WHERE user_id = ? AND project_id = ?
        `).get(userId, projectId);
        
        if (directAccess) {
            const levels = ['read', 'edit', 'delete'];
            const userLevel = levels.indexOf(directAccess.access_level);
            const reqLevel = levels.indexOf(requiredLevel);
            return userLevel >= reqLevel;
        }

        return false;
    } catch (error) {
        console.error('Error checking project access:', error);
        return false;
    }
}

// Enhanced PDF Processing Functions with Logging
async function processPDFPages(file, documentId, documentDir, pagesDir, thumbnailDir) {
    const pageRecords = [];
    
    try {
        console.log(`📄 Starting PDF processing: ${file.originalname} for document ${documentId}`);
        
        // Get current page count for this document
        const lastPage = db.prepare(`
            SELECT MAX(page_number) as max_page FROM document_pages 
            WHERE document_id = ? AND (status IS NULL OR status = 'active')
        `).get(documentId);
        
        let startingPageNumber = (lastPage.max_page || 0) + 1;
        console.log(`📄 Starting page number: ${startingPageNumber}`);
        
        // Configure pdf2pic for high-quality conversion
        const convertOptions = {
            density: 200,           // DPI - higher = better quality
            saveFilename: "page",   // Base filename
            savePath: pagesDir,     // Output directory
            format: "jpg",          // Output format
            width: 1200,            // Max width
            height: 1600            // Max height
        };
        
        // Convert PDF to images
        const convert = pdf2pic.fromPath(file.path, convertOptions);
        const conversionResults = await convert.bulk(-1); // -1 means all pages
        
        console.log(`📄 PDF converted to ${conversionResults.length} pages`);
        
        // Process each converted page
        for (let i = 0; i < conversionResults.length; i++) {
            const conversionResult = conversionResults[i];
            const pageNumber = startingPageNumber + i;
            const originalPageName = `page.${i + 1}.jpg`;
            const finalPageName = `${uuidv4()}_page_${pageNumber}.jpg`;
            const thumbnailName = `thumb_${finalPageName}`;
            
            console.log(`📄 Processing page ${pageNumber} for document ${documentId}`);
            
            // Move page to final location with UUID filename
            const originalPagePath = path.join(pagesDir, originalPageName);
            const finalPagePath = path.join(pagesDir, finalPageName);
            const thumbnailPath = path.join(thumbnailDir, thumbnailName);
            
            // Rename the converted page file
            await fs.rename(originalPagePath, finalPagePath);
            
            // Create thumbnail
            await createThumbnail(finalPagePath, thumbnailPath);
            
            // Get file stats
            const stats = await fs.stat(finalPagePath);
            
            // Save page record to database with status
            const dbInsertResult = db.prepare(`
                INSERT INTO document_pages (
                    document_id, page_number, file_path, file_name, file_size, 
                    mime_type, thumbnail_path, page_order, source_file_name, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                documentId,
                pageNumber,
                finalPagePath,
                `${file.originalname} - Page ${pageNumber}`,
                stats.size,
                'image/jpeg',
                thumbnailPath,
                pageNumber,
                file.originalname,
                'active'
            );
            
            console.log(`✅ Created page ${pageNumber} with ID ${dbInsertResult.lastInsertRowid} for document ${documentId}`);
            
            pageRecords.push({
                id: dbInsertResult.lastInsertRowid,
                page_number: pageNumber,
                file_name: `${file.originalname} - Page ${pageNumber}`,
                file_path: finalPagePath,
                thumbnail_path: thumbnailPath,
                file_size: stats.size,
                source_type: 'pdf',
                document_id: documentId
            });
        }
        
        // Clean up original PDF file
        await fs.unlink(file.path);
        
        console.log(`✅ PDF processing complete: ${pageRecords.length} pages created for document ${documentId}`);
        return pageRecords;
        
    } catch (error) {
        console.error(`❌ PDF processing failed for document ${documentId}:`, error);
        throw new Error(`Failed to process PDF: ${error.message}`);
    }
}

// Process single image file
async function processSingleImage(file, documentId, documentDir, thumbnailDir) {
    console.log(`🖼️ Processing image: ${file.originalname} for document ${documentId}`);
    
    // Get next page number
    const lastPage = db.prepare(`
        SELECT MAX(page_number) as max_page FROM document_pages 
        WHERE document_id = ? AND (status IS NULL OR status = 'active')
    `).get(documentId);
    
    const pageNumber = (lastPage.max_page || 0) + 1;
    
    // Generate unique filename
    const fileName = `${uuidv4()}_${file.originalname}`;
    const finalPath = path.join(documentDir, fileName);
    const thumbnailPath = path.join(thumbnailDir, `thumb_${fileName}.jpg`);
    
    // Move file to permanent location
    await fs.rename(file.path, finalPath);
    
    // Create thumbnail
    await createThumbnail(finalPath, thumbnailPath);
    
    // Save page record with status
    const dbResult = db.prepare(`
        INSERT INTO document_pages (
            document_id, page_number, file_path, file_name, file_size, 
            mime_type, thumbnail_path, page_order, source_file_name, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        documentId,
        pageNumber,
        finalPath,
        file.originalname,
        file.size,
        file.mimetype,
        thumbnailPath,
        pageNumber,
        file.originalname,
        'active'
    );
    
    console.log(`✅ Created image page ${pageNumber} with ID ${dbResult.lastInsertRowid} for document ${documentId}`);
    
    return {
        id: dbResult.lastInsertRowid,
        page_number: pageNumber,
        file_name: file.originalname,
        file_path: finalPath,
        thumbnail_path: thumbnailPath,
        file_size: file.size,
        source_type: 'image',
        document_id: documentId
    };
}

// Enhanced thumbnail creation
async function createThumbnail(imagePath, thumbnailPath) {
    try {
        await sharp(imagePath)
            .resize(200, 200, { 
                fit: 'inside',
                withoutEnlargement: true,
                background: { r: 255, g: 255, b: 255, alpha: 1 }
            })
            .jpeg({ 
                quality: 80,
                progressive: true
            })
            .toFile(thumbnailPath);
        return true;
    } catch (error) {
        console.error('Thumbnail creation failed:', error);
        return false;
    }
}

// ENHANCED File upload route with PDF page splitting and better logging
app.post('/api/documents/:documentId/pages', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const { documentId } = req.params;
        const file = req.file;
        
        console.log(`🔍 UPLOAD DEBUG - Document ID: ${documentId}`);
        console.log(`🔍 UPLOAD DEBUG - File: ${file?.originalname}, Type: ${file?.mimetype}`);
        
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        // Verify document exists BEFORE processing
        const existingDoc = db.prepare('SELECT id, title FROM documents WHERE id = ? AND status = \'active\'').get(documentId);
        if (!existingDoc) {
            console.error(`❌ Document ${documentId} not found!`);
            return res.status(404).json({ error: 'Document not found' });
        }
        
        console.log(`✅ Processing file for document: ${existingDoc.title} (ID: ${documentId})`);
        
        // Create directories
        const documentDir = path.join(IMAGE_DIR, documentId);
        const thumbnailDir = path.join(documentDir, 'thumbnails');
        const pagesDir = path.join(documentDir, 'pages');
        await fs.mkdir(documentDir, { recursive: true });
        await fs.mkdir(thumbnailDir, { recursive: true });
        await fs.mkdir(pagesDir, { recursive: true });
        
        let pageRecords = [];
        
        // Check if file is a PDF
        if (file.mimetype === 'application/pdf') {
            console.log(`📄 Processing PDF: ${file.originalname} for document ${documentId}`);
            pageRecords = await processPDFPages(file, documentId, documentDir, pagesDir, thumbnailDir);
            console.log(`✅ PDF processed: ${pageRecords.length} pages created for document ${documentId}`);
        } else {
            // Handle single image files
            console.log(`🖼️ Processing image: ${file.originalname} for document ${documentId}`);
            const pageRecord = await processSingleImage(file, documentId, documentDir, thumbnailDir);
            pageRecords.push(pageRecord);
            console.log(`✅ Image processed: 1 page created for document ${documentId}`);
        }
        
        // IMPORTANT: Update document page count
        const updateResult = db.prepare(`
            UPDATE documents SET total_pages = total_pages + ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(pageRecords.length, documentId);
        
        console.log(`📊 Updated document ${documentId} page count by ${pageRecords.length}, affected rows: ${updateResult.changes}`);
        
        // Verify the update worked
        const updatedDoc = db.prepare('SELECT id, title, total_pages FROM documents WHERE id = ?').get(documentId);
        console.log(`📊 Document ${documentId} now has ${updatedDoc.total_pages} total pages`);
        
        // Log the upload
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'upload', 'document_pages', documentId, 
            `Uploaded ${pageRecords.length} page(s) from ${file.originalname}`);
        
        res.json({
            success: true,
            message: `Successfully processed ${pageRecords.length} page(s)`,
            pages: pageRecords,
            total_pages: pageRecords.length,
            file_type: file.mimetype === 'application/pdf' ? 'pdf' : 'image',
            document_id: documentId
        });
        
    } catch (error) {
        console.error('❌ File processing error:', error);
        console.error('Stack trace:', error.stack);
        res.status(500).json({ 
            error: 'File processing failed: ' + error.message,
            details: error.stack
        });
    }
});

// Get document pages with enhanced information (only active pages)
app.get('/api/documents/:documentId/pages', authenticateToken, (req, res) => {
    try {
        const { documentId } = req.params;
        
        const pages = db.prepare(`
            SELECT 
                id,
                page_number,
                file_name,
                file_size,
                mime_type,
                thumbnail_path,
                page_order,
                source_file_name,
                created_at,
                CASE 
                    WHEN source_file_name LIKE '%.pdf' THEN 'pdf'
                    WHEN mime_type LIKE 'image/%' THEN 'image'
                    ELSE 'unknown'
                END as source_type
            FROM document_pages 
            WHERE document_id = ? AND (status IS NULL OR status = 'active')
            ORDER BY page_order, page_number
        `).all(documentId);
        
        res.json(pages);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get individual page content
app.get('/api/pages/:pageId/content', authenticateToken, async (req, res) => {
    try {
        const { pageId } = req.params;
        
        const page = db.prepare(`
            SELECT file_path, mime_type, file_name 
            FROM document_pages 
            WHERE id = ? AND (status IS NULL OR status = 'active')
        `).get(pageId);
        
        if (!page) {
            return res.status(404).json({ error: 'Page not found' });
        }
        
        // Check if file exists
        const fileExists = await fs.access(page.file_path).then(() => true).catch(() => false);
        if (!fileExists) {
            return res.status(404).json({ error: 'Page file not found on disk' });
        }
        
        // Set appropriate headers
        res.setHeader('Content-Type', page.mime_type || 'application/octet-stream');
        res.setHeader('Content-Disposition', `inline; filename="${page.file_name}"`);
        
        // Stream the file
        const fileStream = require('fs').createReadStream(page.file_path);
        fileStream.pipe(res);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get page thumbnail
app.get('/api/pages/:pageId/thumbnail', authenticateToken, async (req, res) => {
    try {
        const { pageId } = req.params;
        
        const page = db.prepare(`
            SELECT thumbnail_path, file_name 
            FROM document_pages 
            WHERE id = ? AND (status IS NULL OR status = 'active')
        `).get(pageId);
        
        if (!page || !page.thumbnail_path) {
            return res.status(404).json({ error: 'Thumbnail not found' });
        }
        
        // Check if thumbnail exists
        const thumbExists = await fs.access(page.thumbnail_path).then(() => true).catch(() => false);
        if (!thumbExists) {
            return res.status(404).json({ error: 'Thumbnail file not found' });
        }
        
        // Set headers for thumbnail
        res.setHeader('Content-Type', 'image/jpeg');
        res.setHeader('Content-Disposition', `inline; filename="thumb_${page.file_name}"`);
        
        // Stream the thumbnail
        const thumbStream = require('fs').createReadStream(page.thumbnail_path);
        thumbStream.pipe(res);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete individual page (soft delete)
app.delete('/api/pages/:pageId', authenticateToken, authorize(['document_edit']), async (req, res) => {
    try {
        const { pageId } = req.params;
        
        const page = db.prepare(`
            SELECT document_id, file_path, thumbnail_path, file_name 
            FROM document_pages 
            WHERE id = ? AND (status IS NULL OR status = 'active')
        `).get(pageId);
        
        if (!page) {
            return res.status(404).json({ error: 'Page not found' });
        }
        
        // Soft delete the page
        db.prepare('UPDATE document_pages SET status = \'inactive\' WHERE id = ?').run(pageId);
        
        // Update document page count
        const remainingPages = db.prepare(`
            SELECT COUNT(*) as count FROM document_pages 
            WHERE document_id = ? AND (status IS NULL OR status = 'active')
        `).get(page.document_id);
        
        db.prepare(`
            UPDATE documents SET total_pages = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `).run(remainingPages.count, page.document_id);
        
        // Log the deletion
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'delete', 'document_pages', pageId, `Soft deleted page: ${page.file_name}`);
        
        res.json({ 
            success: true, 
            message: 'Page marked as inactive',
            remaining_pages: remainingPages.count
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Reorder document pages (NEW ENDPOINT)
app.put('/api/documents/:documentId/pages/reorder', authenticateToken, authorize(['document_edit']), (req, res) => {
    try {
        const { documentId } = req.params;
        const { page_order } = req.body;
        
        console.log(`🔄 Reordering pages for document ${documentId}`);
        
        // Validate input
        if (!page_order || !Array.isArray(page_order) || page_order.length === 0) {
            return res.status(400).json({ error: 'Page order array is required' });
        }
        
        // Check if document exists and user has access
        const document = db.prepare(`
            SELECT d.*, p.id as project_id
            FROM documents d
            LEFT JOIN projects p ON d.project_id = p.id
            WHERE d.id = ? AND d.status = 'active'
        `).get(documentId);
        
        if (!document) {
            return res.status(404).json({ error: 'Document not found' });
        }
        
        // Check project access
        if (!hasProjectAccess(req.user.id, document.project_id)) {
            return res.status(403).json({ error: 'Access denied to this project' });
        }
        
        // Validate that all page IDs belong to this document
        const existingPages = db.prepare(`
            SELECT id FROM document_pages 
            WHERE document_id = ? AND (status IS NULL OR status = 'active')
        `).all(documentId);
        
        const existingPageIds = existingPages.map(p => p.id);
        const providedPageIds = page_order.map(p => p.page_id);
        
        // Check that all provided page IDs exist and belong to this document
        for (const pageId of providedPageIds) {
            if (!existingPageIds.includes(pageId)) {
                return res.status(400).json({ 
                    error: `Page ID ${pageId} does not belong to document ${documentId} or is inactive` 
                });
            }
        }
        
        // Check that all existing pages are included in the reorder
        if (existingPageIds.length !== providedPageIds.length) {
            return res.status(400).json({ 
                error: `All active pages must be included in reorder. Expected ${existingPageIds.length}, got ${providedPageIds.length}` 
            });
        }
        
        const transaction = db.transaction(() => {
            // Update page numbers and page order
            const updateStmt = db.prepare(`
                UPDATE document_pages 
                SET page_number = ?, page_order = ?
                WHERE id = ? AND document_id = ?
            `);
            
            let updatedCount = 0;
            
            page_order.forEach((pageUpdate) => {
                const result = updateStmt.run(
                    pageUpdate.new_page_number,
                    pageUpdate.new_page_number,
                    pageUpdate.page_id,
                    documentId
                );
                
                if (result.changes > 0) {
                    updatedCount++;
                    console.log(`✅ Updated page ${pageUpdate.page_id} to position ${pageUpdate.new_page_number}`);
                }
            });
            
            // Update document's updated_at timestamp
            db.prepare(`
                UPDATE documents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(documentId);
            
            return updatedCount;
        });
        
        const updatedCount = transaction();
        
        // Log the reorder
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'update', 'documents', documentId, `Reordered ${updatedCount} pages in document: ${document.title}`);
        
        console.log(`✅ Successfully reordered ${updatedCount} pages for document ${documentId}`);
        
        res.json({ 
            success: true, 
            message: `Successfully reordered ${updatedCount} pages`,
            updated_pages: updatedCount
        });
        
    } catch (error) {
        console.error('❌ Error reordering pages:', error);
        res.status(500).json({ error: 'Failed to reorder pages: ' + error.message });
    }
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = db.prepare(`
            SELECT u.*, r.name as role_name, r.permissions 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.username = ? AND u.status = 'active'
        `).get(username);

        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({
            id: user.id,
            username: user.username,
            role_id: user.role_id,
            permissions: JSON.parse(user.permissions || '[]')
        }, JWT_SECRET, { expiresIn: '24h' });

        // Log login
        db.prepare(`
            INSERT INTO audit_log (user_id, action, details, ip_address) 
            VALUES (?, ?, ?, ?)
        `).run(user.id, 'login', 'User logged in', req.ip);

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role_name: user.role_name,
                permissions: JSON.parse(user.permissions || '[]')
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Token validation route
app.get('/api/auth/validate', authenticateToken, (req, res) => {
    try {
        const user = db.prepare(`
            SELECT u.*, r.name as role_name, r.permissions 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.id = ? AND u.status = 'active'
        `).get(req.user.id);

        if (!user) {
            return res.status(401).json({ error: 'User not found or inactive' });
        }

        res.json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role_name: user.role_name,
                permissions: JSON.parse(user.permissions || '[]')
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// User management routes (Admin only)
app.get('/api/users', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const users = db.prepare(`
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.status != 'deleted'
            ORDER BY u.created_at DESC
        `).all();

        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/users/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;
        
        const user = db.prepare(`
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.id = ? AND u.status != 'deleted'
        `).get(id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/users', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { username, email, password, first_name, last_name, role_id, status } = req.body;

        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        // Check if username or email already exists
        const existingUser = db.prepare(`
            SELECT id FROM users WHERE (username = ? OR email = ?) AND status != 'deleted'
        `).get(username, email);

        if (existingUser) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        // Validate role_id if provided
        if (role_id) {
            const roleExists = db.prepare('SELECT id FROM roles WHERE id = ?').get(role_id);
            if (!roleExists) {
                return res.status(400).json({ error: 'Invalid role ID' });
            }
        }

        // Hash password
        const hashedPassword = bcrypt.hashSync(password, 10);

        const result = db.prepare(`
            INSERT INTO users (username, email, password, first_name, last_name, role_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(username, email, hashedPassword, first_name || null, last_name || null, role_id || null, status || 'active');

        // Log the creation
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'create', 'users', result.lastInsertRowid, `Created user: ${username}`);

        res.status(201).json({ id: result.lastInsertRowid, message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/users/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;
        const { username, email, password, first_name, last_name, role_id, status } = req.body;

        // Check if user exists
        const existingUser = db.prepare('SELECT * FROM users WHERE id = ? AND status != \'deleted\'').get(id);
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if username or email is taken by another user
        const duplicateUser = db.prepare(`
            SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ? AND status != 'deleted'
        `).get(username, email, id);

        if (duplicateUser) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        // Validate role_id if provided
        if (role_id) {
            const roleExists = db.prepare('SELECT id FROM roles WHERE id = ?').get(role_id);
            if (!roleExists) {
                return res.status(400).json({ error: 'Invalid role ID' });
            }
        }

        // Prepare update data
        let updateQuery = `
            UPDATE users SET 
                username = ?, email = ?, first_name = ?, last_name = ?, 
                role_id = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        `;
        let params = [username, email, first_name || null, last_name || null, role_id || null, status || 'active'];

        // Add password if provided
        if (password && password.trim()) {
            updateQuery += `, password = ?`;
            params.push(bcrypt.hashSync(password, 10));
        }

        updateQuery += ` WHERE id = ?`;
        params.push(id);

        const result = db.prepare(updateQuery).run(...params);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Log the update
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'update', 'users', id, `Updated user: ${username}`);

        res.json({ message: 'User updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/users/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;

        // Check if user exists
        const existingUser = db.prepare('SELECT username FROM users WHERE id = ? AND status != \'deleted\'').get(id);
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Prevent deleting yourself
        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        // Soft delete
        const result = db.prepare(`
            UPDATE users SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = ?
        `).run(id);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Log the deletion
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'delete', 'users', id, `Deleted user: ${existingUser.username}`);

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Role management routes (Admin only)
app.get('/api/roles', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const roles = db.prepare(`
            SELECT r.*, COUNT(u.id) as user_count
            FROM roles r
            LEFT JOIN users u ON r.id = u.role_id AND u.status = 'active'
            GROUP BY r.id
            ORDER BY r.created_at DESC
        `).all();

        // Parse permissions JSON
        roles.forEach(role => {
            role.permissions = JSON.parse(role.permissions || '[]');
        });

        res.json(roles);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/roles/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;
        
        const role = db.prepare(`
            SELECT r.*, COUNT(u.id) as user_count
            FROM roles r
            LEFT JOIN users u ON r.id = u.role_id AND u.status = 'active'
            WHERE r.id = ?
            GROUP BY r.id
        `).get(id);

        if (!role) {
            return res.status(404).json({ error: 'Role not found' });
        }

        role.permissions = JSON.parse(role.permissions || '[]');
        res.json(role);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/roles', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { name, description, permissions } = req.body;

        // Validation
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'Role name is required' });
        }

        // Check if role name already exists
        const existingRole = db.prepare('SELECT id FROM roles WHERE name = ?').get(name.trim());
        if (existingRole) {
            return res.status(409).json({ error: 'Role name already exists' });
        }

        const result = db.prepare(`
            INSERT INTO roles (name, description, permissions)
            VALUES (?, ?, ?)
        `).run(name.trim(), description || null, JSON.stringify(permissions || []));

        // Log the creation
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'create', 'roles', result.lastInsertRowid, `Created role: ${name}`);

        res.status(201).json({ id: result.lastInsertRowid, message: 'Role created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/roles/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, permissions } = req.body;

        // Check if role exists
        const existingRole = db.prepare('SELECT name FROM roles WHERE id = ?').get(id);
        if (!existingRole) {
            return res.status(404).json({ error: 'Role not found' });
        }

        // Check if name is taken by another role
        const duplicateRole = db.prepare('SELECT id FROM roles WHERE name = ? AND id != ?').get(name.trim(), id);
        if (duplicateRole) {
            return res.status(409).json({ error: 'Role name already exists' });
        }

        // Check if updated_at column exists
        const tableInfo = db.prepare('PRAGMA table_info(roles)').all();
        const hasUpdatedAt = tableInfo.some(col => col.name === 'updated_at');

        let updateQuery = `UPDATE roles SET name = ?, description = ?, permissions = ?`;
        let params = [name.trim(), description || null, JSON.stringify(permissions || [])];

        if (hasUpdatedAt) {
            updateQuery += `, updated_at = CURRENT_TIMESTAMP`;
        }

        updateQuery += ` WHERE id = ?`;
        params.push(id);

        const result = db.prepare(updateQuery).run(...params);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Role not found' });
        }

        // Log the update
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'update', 'roles', id, `Updated role: ${name}`);

        res.json({ message: 'Role updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/roles/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;

        // Check if role exists
        const existingRole = db.prepare('SELECT name FROM roles WHERE id = ?').get(id);
        if (!existingRole) {
            return res.status(404).json({ error: 'Role not found' });
        }

        // Check if role is in use
        const usersWithRole = db.prepare('SELECT COUNT(*) as count FROM users WHERE role_id = ? AND status = \'active\'').get(id);
        if (usersWithRole.count > 0) {
            return res.status(400).json({ error: `Cannot delete role: ${usersWithRole.count} users are assigned to this role` });
        }

        const result = db.prepare('DELETE FROM roles WHERE id = ?').run(id);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Role not found' });
        }

        // Log the deletion
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'delete', 'roles', id, `Deleted role: ${existingRole.name}`);

        res.json({ message: 'Role deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Project management routes
app.get('/api/projects', authenticateToken, (req, res) => {
    try {
        let query = `
            SELECT p.*, u.username as created_by_name,
                   COUNT(DISTINCT d.id) as document_count
            FROM projects p
            LEFT JOIN users u ON p.created_by = u.id
            LEFT JOIN documents d ON p.id = d.project_id AND d.status = 'active'
        `;
        
        // If not admin, filter by user access
        const userPermissions = req.user.permissions;
        if (!userPermissions.includes('admin_access')) {
            query += `
                WHERE p.status = 'active' AND (
                    p.id IN (
                        SELECT pr.project_id FROM project_roles pr
                        JOIN users u ON u.role_id = pr.role_id
                        WHERE u.id = ?
                    ) OR
                    p.id IN (
                        SELECT upa.project_id FROM user_project_access upa
                        WHERE upa.user_id = ?
                    )
                )
            `;
        } else {
            query += ` WHERE p.status = 'active'`;
        }
        
        query += ` GROUP BY p.id ORDER BY p.created_at DESC`;
        
        const projects = userPermissions.includes('admin_access') 
            ? db.prepare(query).all()
            : db.prepare(query).all(req.user.id, req.user.id);
        
        // Get index fields and assigned roles for each project
        projects.forEach(project => {
            // Get index fields
            const fields = db.prepare(`
                SELECT field_name as name, field_label as label, field_type as type, 
                       field_options as options, required, display_order
                FROM project_fields 
                WHERE project_id = ? 
                ORDER BY display_order, id
            `).all(project.id);
            
            project.index_fields = fields.map(field => ({
                ...field,
                options: field.options ? JSON.parse(field.options) : [],
                required: !!field.required
            }));

            // Get assigned roles
            const assignedRoles = db.prepare(`
                SELECT r.id, r.name, r.description
                FROM project_roles pr
                JOIN roles r ON pr.role_id = r.id
                WHERE pr.project_id = ?
                ORDER BY r.name
            `).all(project.id);
            
            project.assigned_roles = assignedRoles;
        });
        
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get single project by ID
app.get('/api/projects/:id', authenticateToken, (req, res) => {
    try {
        const { id } = req.params;
        
        // Check project access
        if (!hasProjectAccess(req.user.id, id)) {
            return res.status(404).json({ error: 'Project not found or access denied' });
        }
        
        const project = db.prepare(`
            SELECT p.*, u.username as created_by_name,
                   COUNT(DISTINCT d.id) as document_count
            FROM projects p
            LEFT JOIN users u ON p.created_by = u.id
            LEFT JOIN documents d ON p.id = d.project_id AND d.status = 'active'
            WHERE p.id = ? AND p.status != 'deleted'
            GROUP BY p.id
        `).get(id);
        
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        // Get project fields
        const fields = db.prepare(`
            SELECT field_name as name, field_label as label, field_type as type, 
                   field_options as options, required, display_order
            FROM project_fields 
            WHERE project_id = ? 
            ORDER BY display_order, id
        `).all(project.id);
        
        project.index_fields = fields.map(field => ({
            ...field,
            options: field.options ? JSON.parse(field.options) : [],
            required: !!field.required
        }));

        // Get assigned roles
        const assignedRoles = db.prepare(`
            SELECT r.id, r.name, r.description
            FROM project_roles pr
            JOIN roles r ON pr.role_id = r.id
            WHERE pr.project_id = ?
            ORDER BY r.name
        `).all(project.id);
        
        project.assigned_roles = assignedRoles;
        
        res.json(project);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create new project (Admin only)
app.post('/api/projects', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { name, description, type, color, status, assigned_roles, index_fields } = req.body;

        console.log(`📝 Creating project with data:`, {
            name,
            assigned_roles,
            index_fields_count: index_fields?.length || 0
        });

        // Validation
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'Project name is required' });
        }

        if (!assigned_roles || assigned_roles.length === 0) {
            return res.status(400).json({ error: 'At least one role must be assigned to the project' });
        }

        // CRITICAL: Validate that all role IDs exist and are valid integers
        const validRoles = [];
        for (const roleId of assigned_roles) {
            if (!Number.isInteger(roleId) || roleId <= 0) {
                return res.status(400).json({ error: `Invalid role ID: ${roleId}. Must be a positive integer.` });
            }

            const roleExists = db.prepare('SELECT id FROM roles WHERE id = ?').get(roleId);
            if (!roleExists) {
                return res.status(400).json({ error: `Role with ID ${roleId} does not exist` });
            }
            validRoles.push(roleId);
        }

        console.log(`✅ Validated ${validRoles.length} roles:`, validRoles);

        const transaction = db.transaction(() => {
            // Ensure foreign keys are enabled for this transaction
            db.pragma('foreign_keys = ON');

            // Create project
            const projectResult = db.prepare(`
                INSERT INTO projects (name, description, type, color, status, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                name.trim(), 
                description || null, 
                type || 'custom',
                color || '#667eea',
                status || 'active',
                req.user.id
            );

            const projectId = projectResult.lastInsertRowid;
            console.log(`✅ Created project with ID: ${projectId}`);

            // Assign roles to project with validation
            const roleAssignInsert = db.prepare(`
                INSERT INTO project_roles (project_id, role_id, assigned_by)
                VALUES (?, ?, ?)
            `);

            validRoles.forEach((roleId, index) => {
                try {
                    const insertResult = roleAssignInsert.run(projectId, roleId, req.user.id);
                    console.log(`✅ Assigned role ${roleId} to project ${projectId} (insert ID: ${insertResult.lastInsertRowid})`);
                } catch (roleError) {
                    console.error(`❌ Failed to assign role ${roleId} to project ${projectId}:`, roleError.message);
                    throw new Error(`Failed to assign role ${roleId}: ${roleError.message}`);
                }
            });

            // Add custom fields
            if (index_fields && index_fields.length > 0) {
                const fieldInsert = db.prepare(`
                    INSERT INTO project_fields (project_id, field_name, field_label, field_type, field_options, required, display_order)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `);

                index_fields.forEach((field, index) => {
                    try {
                        // Validate field data
                        if (!field.name || !field.label) {
                            throw new Error(`Field at index ${index} is missing name or label`);
                        }

                        const insertResult = fieldInsert.run(
                            projectId,
                            field.name,
                            field.label,
                            field.type,
                            JSON.stringify(field.options || []),
                            field.required ? 1 : 0,
                            index
                        );
                        console.log(`✅ Created custom field "${field.name}" for project ${projectId} (insert ID: ${insertResult.lastInsertRowid})`);
                    } catch (fieldError) {
                        console.error(`❌ Failed to create field "${field.name}":`, fieldError.message);
                        throw new Error(`Failed to create field "${field.name}": ${fieldError.message}`);
                    }
                });
            }

            // Verify foreign key integrity
            const foreignKeyCheck = db.prepare('PRAGMA foreign_key_check').all();
            if (foreignKeyCheck.length > 0) {
                console.error('❌ Foreign key violations detected:', foreignKeyCheck);
                throw new Error('Foreign key constraint violations detected');
            }

            console.log(`✅ Successfully created project ${projectId}`);
            return projectId;
        });

        const projectId = transaction();

        // Log the creation
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'create', 'projects', projectId, `Created project: ${name}`);

        res.status(201).json({ id: projectId, message: 'Project created successfully' });
    } catch (error) {
        console.error('❌ Project creation error:', error);
        
        // Provide more specific error messages
        if (error.message.includes('FOREIGN KEY constraint failed')) {
            res.status(400).json({ 
                error: 'Foreign key constraint failed. This usually means you\'re trying to assign non-existent roles or there\'s a data integrity issue.',
                details: error.message 
            });
        } else if (error.message.includes('UNIQUE constraint failed')) {
            res.status(409).json({ 
                error: 'Duplicate data detected. A role might already be assigned to this project.',
                details: error.message 
            });
        } else {
            res.status(500).json({ 
                error: 'Project creation failed: ' + error.message,
                details: error.stack 
            });
        }
    }
});

// *** UPDATED PROJECT UPDATE ROUTE WITH FOREIGN KEY FIX ***
app.put('/api/projects/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, type, color, status, assigned_roles, index_fields } = req.body;

        console.log(`📝 Updating project ${id} with data:`, {
            name,
            assigned_roles,
            index_fields_count: index_fields?.length || 0
        });

        // Check if project exists
        const existingProject = db.prepare('SELECT name FROM projects WHERE id = ? AND status != \'deleted\'').get(id);
        if (!existingProject) {
            return res.status(404).json({ error: 'Project not found' });
        }

        // Validation
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'Project name is required' });
        }

        if (!assigned_roles || assigned_roles.length === 0) {
            return res.status(400).json({ error: 'At least one role must be assigned to the project' });
        }

        // CRITICAL: Validate that all role IDs exist and are valid integers
        const validRoles = [];
        for (const roleId of assigned_roles) {
            if (!Number.isInteger(roleId) || roleId <= 0) {
                return res.status(400).json({ error: `Invalid role ID: ${roleId}. Must be a positive integer.` });
            }

            const roleExists = db.prepare('SELECT id FROM roles WHERE id = ?').get(roleId);
            if (!roleExists) {
                return res.status(400).json({ error: `Role with ID ${roleId} does not exist` });
            }
            validRoles.push(roleId);
        }

        console.log(`✅ Validated ${validRoles.length} roles:`, validRoles);

        // Use transaction with explicit foreign key check and SAFE field handling
        const transaction = db.transaction(() => {
            // Ensure foreign keys are enabled for this transaction
            db.pragma('foreign_keys = ON');

            // Update project basic info
            const result = db.prepare(`
                UPDATE projects SET 
                    name = ?, description = ?, type = ?, color = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(name.trim(), description || null, type || 'custom', color || '#667eea', status || 'active', id);

            if (result.changes === 0) {
                throw new Error('Project not found');
            }

            // Clear existing role assignments (this is safe)
            const deleteRolesResult = db.prepare('DELETE FROM project_roles WHERE project_id = ?').run(id);
            console.log(`🗑️ Deleted ${deleteRolesResult.changes} existing role assignments`);

            // Insert new role assignments with validation
            const roleAssignInsert = db.prepare(`
                INSERT INTO project_roles (project_id, role_id, assigned_by)
                VALUES (?, ?, ?)
            `);

            validRoles.forEach((roleId, index) => {
                try {
                    const insertResult = roleAssignInsert.run(id, roleId, req.user.id);
                    console.log(`✅ Assigned role ${roleId} to project ${id} (insert ID: ${insertResult.lastInsertRowid})`);
                } catch (roleError) {
                    console.error(`❌ Failed to assign role ${roleId} to project ${id}:`, roleError.message);
                    throw new Error(`Failed to assign role ${roleId}: ${roleError.message}`);
                }
            });

            // *** SAFE FIELD HANDLING - This is the key fix ***
            if (index_fields && Array.isArray(index_fields)) {
                // Check if there are existing document field values that might be affected
                const existingDocValues = db.prepare(`
                    SELECT COUNT(*) as count 
                    FROM document_field_values dfv 
                    JOIN project_fields pf ON dfv.field_id = pf.id 
                    WHERE pf.project_id = ?
                `).get(id);

                if (existingDocValues.count > 0) {
                    // SAFE UPDATE: Don't delete, just update existing fields and add new ones
                    console.log(`📋 Project ${id} has ${existingDocValues.count} document values - using safe update`);
                    
                    // Get existing fields
                    const existingFields = db.prepare(`
                        SELECT id, field_name, field_type, field_options, required, display_order 
                        FROM project_fields 
                        WHERE project_id = ?
                        ORDER BY display_order
                    `).all(id);

                    // Update or insert each field
                    index_fields.forEach((field, index) => {
                        const existingField = existingFields.find(ef => ef.field_name === field.name);
                        
                        if (existingField) {
                            // Update existing field
                            const updateField = db.prepare(`
                                UPDATE project_fields 
                                SET field_type = ?, field_options = ?, required = ?, display_order = ?
                                WHERE id = ?
                            `);
                            updateField.run(
                                field.type,
                                JSON.stringify(field.options || []),
                                field.required ? 1 : 0,
                                index,
                                existingField.id
                            );
                            console.log(`✅ Updated field: ${field.name}`);
                        } else {
                            // Insert new field
                            const insertField = db.prepare(`
                                INSERT INTO project_fields (project_id, field_name, field_label, field_type, field_options, required, display_order)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            `);
                            insertField.run(
                                id,
                                field.name,
                                field.label || field.name,
                                field.type,
                                JSON.stringify(field.options || []),
                                field.required ? 1 : 0,
                                index
                            );
                            console.log(`✅ Added new field: ${field.name}`);
                        }
                    });

                    // Remove fields that are no longer in the new list (only if no document values reference them)
                    const fieldNamesToKeep = index_fields.map(f => f.name);
                    existingFields.forEach(existingField => {
                        if (!fieldNamesToKeep.includes(existingField.field_name)) {
                            // Check if this specific field has document values
                            const fieldValueCount = db.prepare(`
                                SELECT COUNT(*) as count 
                                FROM document_field_values 
                                WHERE field_id = ?
                            `).get(existingField.id);

                            if (fieldValueCount.count === 0) {
                                // Safe to delete - no document values reference this field
                                const deleteField = db.prepare('DELETE FROM project_fields WHERE id = ?');
                                deleteField.run(existingField.id);
                                console.log(`🗑️ Removed unused field: ${existingField.field_name}`);
                            } else {
                                console.log(`⚠️ Keeping field ${existingField.field_name} - has ${fieldValueCount.count} document values`);
                            }
                        }
                    });
                } else {
                    // NO DOCUMENT VALUES: Safe to delete and recreate all fields
                    console.log(`📋 Project ${id} has no document values - using full recreate`);
                    
                    const deleteFieldsResult = db.prepare('DELETE FROM project_fields WHERE project_id = ?').run(id);
                    console.log(`🗑️ Deleted ${deleteFieldsResult.changes} existing custom fields`);

                    // Insert new custom fields
                    const fieldInsert = db.prepare(`
                        INSERT INTO project_fields (project_id, field_name, field_label, field_type, field_options, required, display_order)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    `);

                    index_fields.forEach((field, index) => {
                        try {
                            // Validate field data
                            if (!field.name || !field.label) {
                                throw new Error(`Field at index ${index} is missing name or label`);
                            }

                            const insertResult = fieldInsert.run(
                                id,
                                field.name,
                                field.label,
                                field.type,
                                JSON.stringify(field.options || []),
                                field.required ? 1 : 0,
                                index
                            );
                            console.log(`✅ Created custom field "${field.name}" for project ${id} (insert ID: ${insertResult.lastInsertRowid})`);
                        } catch (fieldError) {
                            console.error(`❌ Failed to create field "${field.name}":`, fieldError.message);
                            throw new Error(`Failed to create field "${field.name}": ${fieldError.message}`);
                        }
                    });
                }
            }

            // Verify foreign key integrity
            const foreignKeyCheck = db.prepare('PRAGMA foreign_key_check').all();
            if (foreignKeyCheck.length > 0) {
                console.error('❌ Foreign key violations detected:', foreignKeyCheck);
                throw new Error('Foreign key constraint violations detected');
            }

            console.log(`✅ Successfully updated project ${id}`);
        });

        // Execute the transaction
        transaction();

        // Log the update
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'update', 'projects', id, `Updated project: ${name}`);

        res.json({ message: 'Project updated successfully' });

    } catch (error) {
        console.error('❌ Project update error:', error);
        
        // Provide more specific error messages
        if (error.message.includes('FOREIGN KEY constraint failed')) {
            res.status(400).json({ 
                error: 'Foreign key constraint failed. This usually means you\'re trying to assign non-existent roles or there\'s a data integrity issue.',
                details: error.message 
            });
        } else if (error.message.includes('UNIQUE constraint failed')) {
            res.status(409).json({ 
                error: 'Duplicate data detected. A role might already be assigned to this project.',
                details: error.message 
            });
        } else {
            res.status(500).json({ 
                error: 'Project update failed: ' + error.message,
                details: error.stack 
            });
        }
    }
});

// Delete project (Admin only)
app.delete('/api/projects/:id', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const { id } = req.params;

        // Check if project exists
        const existingProject = db.prepare('SELECT name FROM projects WHERE id = ? AND status != \'deleted\'').get(id);
        if (!existingProject) {
            return res.status(404).json({ error: 'Project not found' });
        }

        // Check if project has documents
        const documentCount = db.prepare('SELECT COUNT(*) as count FROM documents WHERE project_id = ? AND status = \'active\'').get(id);
        if (documentCount.count > 0) {
            return res.status(400).json({ error: `Cannot delete project: ${documentCount.count} documents are still active in this project` });
        }

        // Soft delete
        const result = db.prepare(`
            UPDATE projects SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = ?
        `).run(id);

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }

        // Clean up role assignments (CASCADE should handle this, but let's be explicit)
        db.prepare('DELETE FROM project_roles WHERE project_id = ?').run(id);

        // Log the deletion
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'delete', 'projects', id, `Deleted project: ${existingProject.name}`);

        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create document (ENHANCED with role-based access)
app.post('/api/projects/:projectId/documents', authenticateToken, authorize(['document_create']), (req, res) => {
    try {
        const { projectId } = req.params;
        const { title, description, document_type, index_values } = req.body;
        
        console.log(`📝 Creating document: "${title}" in project ${projectId}`);
        
        // Validation
        if (!title || title.trim().length === 0) {
            return res.status(400).json({ error: 'Document title is required' });
        }
        
        // Check project access
        if (!hasProjectAccess(req.user.id, projectId)) {
            return res.status(404).json({ error: 'Project not found or access denied' });
        }
        
        const transaction = db.transaction(() => {
            // Create document
            const docResult = db.prepare(`
                INSERT INTO documents (project_id, title, description, document_type, created_by)
                VALUES (?, ?, ?, ?, ?)
            `).run(projectId, title.trim(), description || null, document_type || 'general', req.user.id);
            
            const documentId = docResult.lastInsertRowid;
            console.log(`✅ Created document with ID: ${documentId}`);
            
            // Save field values if provided
            if (index_values && Object.keys(index_values).length > 0) {
                const fieldValueInsert = db.prepare(`
                    INSERT INTO document_field_values (document_id, field_id, field_value)
                    VALUES (?, ?, ?)
                `);
                
                const projectFields = db.prepare(`
                    SELECT id, field_name FROM project_fields WHERE project_id = ?
                `).all(projectId);
                
                projectFields.forEach(field => {
                    const fieldValue = index_values[field.field_name];
                    if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
                        fieldValueInsert.run(documentId, field.id, fieldValue.toString());
                    }
                });
            }
            
            return documentId;
        });
        
        const documentId = transaction();
        
        // Log creation
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'create', 'documents', documentId, `Created document: ${title}`);
        
        res.status(201).json({ 
            id: documentId, 
            success: true,
            message: 'Document created successfully' 
        });
    } catch (error) {
        console.error('Error creating document:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get documents by project (ENHANCED with role-based access - only active documents)
app.get('/api/projects/:projectId/documents', authenticateToken, (req, res) => {
    try {
        const { projectId } = req.params;
        const { search } = req.query;
        
        // Check project access
        if (!hasProjectAccess(req.user.id, projectId)) {
            return res.status(404).json({ error: 'Project not found or access denied' });
        }
        
        let query = `
            SELECT d.*, u.username as created_by_name
            FROM documents d
            LEFT JOIN users u ON d.created_by = u.id
            WHERE d.project_id = ? AND d.status = 'active'
        `;
        
        let params = [projectId];
        
        if (search) {
            query += ` AND (d.title LIKE ? OR d.description LIKE ?)`;
            params.push(`%${search}%`, `%${search}%`);
        }
        
        query += ` ORDER BY d.updated_at DESC`;
        
        const documents = db.prepare(query).all(...params);
        
        // Get document field values
        documents.forEach(doc => {
            const fieldValues = db.prepare(`
                SELECT pf.field_name, pf.field_type, dfv.field_value
                FROM document_field_values dfv
                JOIN project_fields pf ON dfv.field_id = pf.id
                WHERE dfv.document_id = ?
            `).all(doc.id);
            
            doc.index_values = fieldValues.reduce((acc, fv) => {
                acc[fv.field_name] = fv.field_value;
                return acc;
            }, {});
        });
        
        res.json(documents);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single document by ID (ENHANCED with role-based access - only active documents)
app.get('/api/documents/:id', authenticateToken, (req, res) => {
    try {
        const { id } = req.params;
        
        let query = `
            SELECT d.*, 
                   p.name as project_name,
                   u.username as created_by_name,
                   COUNT(dp.id) as page_count
            FROM documents d
            LEFT JOIN projects p ON d.project_id = p.id
            LEFT JOIN users u ON d.created_by = u.id
            LEFT JOIN document_pages dp ON d.id = dp.document_id AND (dp.status IS NULL OR dp.status = 'active')
            WHERE d.id = ? AND d.status = 'active'
        `;
        
        let params = [id];
        
        // If not admin, check user access (including role-based access)
        const userPermissions = req.user.permissions;
        if (!userPermissions.includes('admin_access')) {
            query += `
                AND (
                    p.id IN (
                        SELECT pr.project_id FROM project_roles pr
                        JOIN users u ON u.role_id = pr.role_id
                        WHERE u.id = ?
                    ) OR
                    p.id IN (
                        SELECT upa.project_id FROM user_project_access upa
                        WHERE upa.user_id = ?
                    )
                )
            `;
            params.push(req.user.id, req.user.id);
        }
        
        query += ` GROUP BY d.id`;
        
        const document = db.prepare(query).get(...params);
        
        if (!document) {
            return res.status(404).json({ error: 'Document not found or access denied' });
        }
        
        // Get document field values
        const fieldValues = db.prepare(`
            SELECT pf.field_name, pf.field_type, dfv.field_value
            FROM document_field_values dfv
            JOIN project_fields pf ON dfv.field_id = pf.id
            WHERE dfv.document_id = ?
        `).all(document.id);
        
        document.index_values = fieldValues.reduce((acc, fv) => {
            acc[fv.field_name] = fv.field_value;
            return acc;
        }, {});
        
        res.json(document);
    } catch (error) {
        console.error('Error fetching document:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update document index fields (NEW ENDPOINT)
app.put('/api/documents/:id', authenticateToken, authorize(['document_edit']), (req, res) => {
    try {
        const { id } = req.params;
        const { index_values } = req.body;
        
        // Check if document exists and user has access
        const document = db.prepare(`
            SELECT d.*, p.id as project_id
            FROM documents d
            LEFT JOIN projects p ON d.project_id = p.id
            WHERE d.id = ? AND d.status = 'active'
        `).get(id);
        
        if (!document) {
            return res.status(404).json({ error: 'Document not found' });
        }
        
        // Check project access
        if (!hasProjectAccess(req.user.id, document.project_id)) {
            return res.status(403).json({ error: 'Access denied to this project' });
        }
        
        const transaction = db.transaction(() => {
            // Update the document's updated_at timestamp
            db.prepare(`
                UPDATE documents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(id);
            
            // Clear existing field values
            db.prepare(`
                DELETE FROM document_field_values WHERE document_id = ?
            `).run(id);
            
            // Insert new field values if provided
            if (index_values && Object.keys(index_values).length > 0) {
                const fieldValueInsert = db.prepare(`
                    INSERT INTO document_field_values (document_id, field_id, field_value)
                    VALUES (?, ?, ?)
                `);
                
                const projectFields = db.prepare(`
                    SELECT id, field_name FROM project_fields WHERE project_id = ?
                `).all(document.project_id);
                
                projectFields.forEach(field => {
                    const fieldValue = index_values[field.field_name];
                    if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
                        fieldValueInsert.run(id, field.id, fieldValue.toString());
                    }
                });
            }
        });
        
        transaction();
        
        // Log the update
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'update', 'documents', id, `Updated document index fields: ${document.title}`);
        
        res.json({ 
            success: true, 
            message: 'Document updated successfully' 
        });
        
    } catch (error) {
        console.error('Error updating document:', error);
        res.status(500).json({ error: error.message });
    }
});

// Soft delete document (NEW ENDPOINT)
app.delete('/api/documents/:id', authenticateToken, authorize(['document_delete']), (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if document exists and user has access
        const document = db.prepare(`
            SELECT d.*, p.id as project_id
            FROM documents d
            LEFT JOIN projects p ON d.project_id = p.id
            WHERE d.id = ? AND d.status = 'active'
        `).get(id);
        
        if (!document) {
            return res.status(404).json({ error: 'Document not found' });
        }
        
        // Check project access
        if (!hasProjectAccess(req.user.id, document.project_id)) {
            return res.status(403).json({ error: 'Access denied to this project' });
        }
        
        const transaction = db.transaction(() => {
            // Soft delete the document
            const docResult = db.prepare(`
                UPDATE documents SET status = 'inactive', updated_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(id);
            
            if (docResult.changes === 0) {
                throw new Error('Document not found');
            }
            
            // Soft delete all associated pages
            const pagesResult = db.prepare(`
                UPDATE document_pages SET status = 'inactive' WHERE document_id = ?
            `).run(id);
            
            console.log(`📊 Soft deleted document ${id} and ${pagesResult.changes} pages`);
            
            return pagesResult.changes;
        });
        
        const deletedPages = transaction();
        
        // Log the deletion
        db.prepare(`
            INSERT INTO audit_log (user_id, action, table_name, record_id, details) 
            VALUES (?, ?, ?, ?, ?)
        `).run(req.user.id, 'delete', 'documents', id, `Soft deleted document: ${document.title} (${deletedPages} pages)`);
        
        res.json({ 
            success: true, 
            message: `Document and ${deletedPages} pages marked as inactive`,
            deleted_pages: deletedPages
        });
        
    } catch (error) {
        console.error('Error deleting document:', error);
        res.status(500).json({ error: error.message });
    }
});

// Debug endpoint to check foreign key status (Admin only)
app.get('/api/debug/foreign-keys', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const foreignKeysEnabled = db.pragma('foreign_keys');
        const foreignKeyCheck = db.prepare('PRAGMA foreign_key_check').all();
        
        res.json({
            foreign_keys_enabled: !!foreignKeysEnabled,
            violations: foreignKeyCheck,
            violations_count: foreignKeyCheck.length,
            message: foreignKeyCheck.length === 0 ? 'No foreign key violations' : 'Foreign key violations detected'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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

// Debug endpoint to check document page counts (Admin only)
app.get('/api/debug/documents', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        const documents = db.prepare(`
            SELECT d.id, d.title, d.total_pages, 
                   COUNT(CASE WHEN dp.status IS NULL OR dp.status = 'active' THEN 1 END) as actual_active_pages,
                   COUNT(dp.id) as total_pages_in_db,
                   d.status as doc_status
            FROM documents d
            LEFT JOIN document_pages dp ON d.id = dp.document_id
            WHERE d.status = 'active'
            GROUP BY d.id
            HAVING d.total_pages != actual_active_pages
            ORDER BY d.created_at DESC
        `).all();
        
        res.json({
            mismatched_documents: documents.length,
            documents: documents
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Fix page count mismatches (Admin only)
app.post('/api/debug/fix-page-counts', authenticateToken, authorize(['admin_access']), (req, res) => {
    try {
        let fixedCount = 0;
        
        const transaction = db.transaction(() => {
            const documents = db.prepare(`
                SELECT d.id, COUNT(CASE WHEN dp.status IS NULL OR dp.status = 'active' THEN 1 END) as actual_pages
                FROM documents d
                LEFT JOIN document_pages dp ON d.id = dp.document_id
                WHERE d.status = 'active'
                GROUP BY d.id
            `).all();
            
            const updateStmt = db.prepare(`
                UPDATE documents SET total_pages = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
            `);
            
            documents.forEach(doc => {
                const result = updateStmt.run(doc.actual_pages, doc.id);
                if (result.changes > 0) {
                    fixedCount++;
                }
            });
        });
        
        transaction();
        
        res.json({
            success: true,
            message: `Fixed page counts for ${fixedCount} documents`,
            fixed_count: fixedCount
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Catch-all route for client-side routing
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.redirect('/');
    }
});

// Initialize and start server
async function startServer() {
    try {
        // Create upload directories
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        await fs.mkdir(IMAGE_DIR, { recursive: true });
        
        // Initialize database
        initializeDatabase();
        
        // Verify foreign key constraints are working
        const fkEnabled = db.pragma('foreign_keys');
        console.log(`🔗 Foreign key constraints: ${fkEnabled ? 'ENABLED ✅' : 'DISABLED ❌'}`);
        
        app.listen(PORT, () => {
            console.log(`🚀 Enhanced Document Management System server running on port ${PORT}`);
            console.log(`📋 Default admin user: admin / admin123`);
            console.log(`🌐 Frontend URL: http://localhost:${PORT}`);
            console.log(`🔧 Admin Panel URL: http://localhost:${PORT}/admin`);
            console.log(`🔄 PDF page splitting enabled`);
            console.log(`✏️ Document field editing enabled`);
            console.log(`🗑️ Document soft delete enabled`);
            console.log(`🔄 Page drag & drop reordering enabled`);
            console.log(`🔗 Foreign key constraints properly enabled`);
            console.log(`📁 File storage: ${path.resolve(IMAGE_DIR)}`);
            console.log(`✅ Enhanced server ready for PDF uploads, editing, and management!`);
            console.log(`🛠️ Foreign key constraint fix applied for project updates`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();