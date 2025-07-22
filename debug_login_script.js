// debug-login.js - Run this script to debug and fix login issues
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');

console.log('🔍 Starting login debug process...');

// Initialize database connection
const db = new Database('dms.db');

// Enable foreign keys
db.pragma('foreign_keys = ON');

function debugDatabase() {
    console.log('\n📊 Database Debug Information:');
    
    try {
        // Check if tables exist
        const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
        console.log('📋 Tables found:', tables.map(t => t.name));
        
        // Check roles table
        console.log('\n👥 Roles in database:');
        const roles = db.prepare('SELECT * FROM roles').all();
        roles.forEach(role => {
            console.log(`  - ID: ${role.id}, Name: ${role.name}, Permissions: ${role.permissions}`);
        });
        
        // Check users table
        console.log('\n👤 Users in database:');
        const users = db.prepare('SELECT id, username, email, role_id, status FROM users').all();
        users.forEach(user => {
            console.log(`  - ID: ${user.id}, Username: ${user.username}, Email: ${user.email}, Role: ${user.role_id}, Status: ${user.status}`);
        });
        
        // Check admin user specifically
        console.log('\n🔐 Admin user check:');
        const adminUser = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
        if (adminUser) {
            console.log('✅ Admin user found:', {
                id: adminUser.id,
                username: adminUser.username,
                email: adminUser.email,
                role_id: adminUser.role_id,
                status: adminUser.status,
                has_password: !!adminUser.password
            });
            
            // Test password
            const testPassword = bcrypt.compareSync('admin123', adminUser.password);
            console.log(`🔑 Password test result: ${testPassword ? 'PASS ✅' : 'FAIL ❌'}`);
        } else {
            console.log('❌ Admin user NOT found!');
        }
        
        // Check foreign key constraints
        console.log('\n🔗 Foreign key constraint check:');
        const foreignKeyCheck = db.prepare('PRAGMA foreign_key_check').all();
        if (foreignKeyCheck.length === 0) {
            console.log('✅ No foreign key violations');
        } else {
            console.log('❌ Foreign key violations found:', foreignKeyCheck);
        }
        
    } catch (error) {
        console.error('❌ Database debug error:', error);
    }
}

function recreateAdminUser() {
    console.log('\n🔄 Recreating admin user...');
    
    try {
        const transaction = db.transaction(() => {
            // Ensure admin role exists
            let adminRoleId;
            const existingAdminRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('Administrator');
            
            if (existingAdminRole) {
                adminRoleId = existingAdminRole.id;
                console.log('✅ Admin role exists with ID:', adminRoleId);
            } else {
                console.log('🔄 Creating admin role...');
                const roleResult = db.prepare(`
                    INSERT INTO roles (name, description, permissions) 
                    VALUES (?, ?, ?)
                `).run('Administrator', 'Full system access', JSON.stringify([
                    'user_create', 'user_edit', 'user_delete', 'user_view',
                    'role_create', 'role_edit', 'role_delete', 'role_view',
                    'project_create', 'project_edit', 'project_delete', 'project_view',
                    'document_create', 'document_edit', 'document_delete', 'document_view',
                    'document_scan', 'document_upload', 'document_print', 'document_email',
                    'document_annotate', 'admin_access'
                ]));
                adminRoleId = roleResult.lastInsertRowid;
                console.log('✅ Created admin role with ID:', adminRoleId);
            }
            
            // Delete existing admin user if it exists
            const deleteResult = db.prepare('DELETE FROM users WHERE username = ?').run('admin');
            if (deleteResult.changes > 0) {
                console.log('🗑️ Deleted existing admin user');
            }
            
            // Create new admin user
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            const userResult = db.prepare(`
                INSERT INTO users (username, email, password, first_name, last_name, role_id, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run('admin', 'admin@dms.local', hashedPassword, 'System', 'Administrator', adminRoleId, 'active');
            
            console.log('✅ Created new admin user with ID:', userResult.lastInsertRowid);
            
            return userResult.lastInsertRowid;
        });
        
        const newUserId = transaction();
        console.log('🎉 Admin user recreated successfully with ID:', newUserId);
        
        // Verify the new user
        const verifyUser = db.prepare('SELECT * FROM users WHERE id = ?').get(newUserId);
        const passwordTest = bcrypt.compareSync('admin123', verifyUser.password);
        console.log('🔍 Verification - Password test:', passwordTest ? 'PASS ✅' : 'FAIL ❌');
        
    } catch (error) {
        console.error('❌ Error recreating admin user:', error);
    }
}

function testApiEndpoint() {
    console.log('\n🌐 Testing API endpoint...');
    
    const fetch = require('node-fetch');
    
    // Test login endpoint
    fetch('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: 'admin',
            password: 'admin123'
        })
    })
    .then(response => {
        console.log('📡 API Response Status:', response.status);
        return response.json();
    })
    .then(data => {
        if (data.token) {
            console.log('✅ Login API test SUCCESSFUL');
            console.log('🎟️ Token received:', data.token.substring(0, 20) + '...');
        } else {
            console.log('❌ Login API test FAILED');
            console.log('📝 Response:', data);
        }
    })
    .catch(error => {
        console.log('❌ API test error:', error.message);
        
        if (error.message.includes('ECONNREFUSED')) {
            console.log('💡 Suggestion: Make sure the server is running on port 3000');
        }
    });
}

// Run all debug functions
console.log('🚀 Running comprehensive debug...\n');

debugDatabase();
recreateAdminUser();

// Wait a moment then test API
setTimeout(() => {
    testApiEndpoint();
}, 1000);

console.log('\n📝 Debug script completed. Check the output above for issues.');
console.log('💡 If you see errors, try:');
console.log('   1. Delete dms.db file and restart the server');
console.log('   2. Check if port 3000 is in use by another application');
console.log('   3. Make sure all npm dependencies are installed');
console.log('   4. Check browser network tab for API request errors');