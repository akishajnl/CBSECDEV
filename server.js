require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

// --- Database Models ---
const User = require('./models/User'); 
const AuditLog = require('./models/AuditLog');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Database Connection ---
connectDB();

// --- Middleware ---
// Parse URL-encoded bodies (for HTML forms) and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Secure Session Management
app.use(session({
    secret: process.env.SESSION_SECRET || 'gapfinder_secure_super_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true only if using HTTPS in production
        httpOnly: true, // Prevents client-side JS from reading the cookie
        maxAge: 1000 * 60 * 60 // 1 hour session validity
    }
}));

// Set View Engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));


// --- API Routing ---
app.use('/auth', authRoutes);


// --- View Routing ---
// IMPORTANT: These must be placed ABOVE the error handlers!

// Landing Page
app.get('/', (req, res) => {
    res.render('index');
});

// Login Page
app.get('/login', (req, res) => {
    res.render('login');
});

// Registration Page
app.get('/register', (req, res) => {
    res.render('register');
});

// Forgot Password Page 
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

// --- SECURE DASHBOARD ROUTES ---

// Secure Coordinator Dashboard (Role A)
app.get('/coordinator', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    res.render('coordinator-dashboard'); 
});

// Secure Tutor Dashboard (Role B)
app.get('/tutor', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    res.render('tutor-dashboard'); 
});

// Secure Admin Dashboard GET 
app.get('/admin', async (req, res) => {
    // SECURITY CHECK: Must be logged in AND have the 'Administrator' role
    if (!req.session || !req.session.userId || req.session.role !== 'Administrator') {
        return res.redirect('/login');
    }
    
    try {
        // Fetch users but exclude other Administrators to prevent accidental lockouts
        const allUsers = await User.find({ role: { $ne: 'Administrator' } }).select('username role');
        
        // Filter users into dedicated arrays for the frontend dropdowns
        const coordinators = allUsers.filter(u => u.role === 'Role A');
        const tutors = allUsers.filter(u => u.role === 'Role B');
        
        // Fetch the latest 50 logs from newest to oldest
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(50);
        
        console.log(`[SYS LOG] Admin Dashboard loaded. Coordinators: ${coordinators.length}, Tutors: ${tutors.length}`);
        
        res.render('admin-dashboard', { 
            coordinators: coordinators, 
            tutors: tutors, 
            logs: logs,
            error: req.query.error || null, 
            success: req.query.success || null 
        }); 
    } catch (error) {
        console.error("Error loading admin dashboard:", error);
        res.status(500).render('error');
    }
});


// Secure Admin Privilege Escalation/Demotion POST
app.post('/admin/promote', async (req, res) => {
    // 1. STRICT AUTHORIZATION CHECK
    if (!req.session || !req.session.userId || req.session.role !== 'Administrator') {
        return res.status(403).render('error', { error: "Forbidden: You do not have sufficient privileges to perform this action." });
    }

    try {
        const { targetUsername, newRole } = req.body;
        const validRoles = ['Administrator', 'Role A', 'Role B'];

        // 2. Validate input
        if (!validRoles.includes(newRole)) {
            return res.redirect('/admin?error=Invalid role selected.');
        }

        // 3. Find the target user in the database
        const targetUser = await User.findOne({ username: targetUsername });
        if (!targetUser) {
            return res.redirect('/admin?error=User not found. Please check the spelling.');
        }

        // 4. Update the role and save
        targetUser.role = newRole;
        await targetUser.save();

        // 5. Save event to the Audit Log database
        let actionType = newRole === 'Role B' ? 'Demotion' : 'Promotion';
        let badge = newRole === 'Role B' ? 'bg-warning text-dark' : 'bg-success';
        
        await AuditLog.create({
            eventType: `Role ${actionType}`,
            badgeColor: badge,
            userIdentifier: req.session.username, // The admin who did it
            details: `Changed role of ${targetUsername} to ${newRole}`
        });

        console.log(`[AUDIT LOG] Administrator (${req.session.username}) updated role of ${targetUsername} to ${newRole}`);
        
        // 6. Redirect back with a success message
        res.redirect('/admin?success=Privilege successfully updated for ' + targetUsername);

    } catch (error) {
        console.error("Privilege Update Error:", error);
        res.status(500).render('error');
    }
});

// Secure Admin Route to Clear Logs
app.post('/admin/logs/clear', async (req, res) => {
    if (!req.session || !req.session.userId || req.session.role !== 'Administrator') {
        return res.status(403).render('error', { error: "Forbidden." });
    }

    try {
        await AuditLog.deleteMany({}); // Wipes the entire collection
        
        // Create a single log noting that the wipe occurred
        await AuditLog.create({
            eventType: 'System Wiped',
            badgeColor: 'bg-danger',
            userIdentifier: req.session.username,
            details: 'Administrator manually cleared all audit logs.'
        });

        res.redirect('/admin?success=Audit logs successfully cleared.');
    } catch (error) {
        console.error("Error clearing logs:", error);
        res.redirect('/admin?error=Failed to clear logs.');
    }
});


// --- SECURE PROFILE ROUTES ---

// Security Center Route
app.get('/profile/security', async (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    
    try {
        // Fetch fresh user data so the activity logs are accurate
        const user = await User.findById(req.session.userId);
        
        res.render('security', { 
            user: user, 
            lastSuccess: req.session.lastSuccess, 
            lastFail: req.session.lastFail,
            previousFailures: req.session.previousFailures || 0,
            error: null, 
            success: null 
        });
    } catch (error) {
        console.error("Profile Security Route Error:", error);
        res.status(500).render('error');
    }
});

// Step 1: Prompt for Security Question before changing password
app.get('/profile/security/verify-prompt', async (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    
    try {
        const user = await User.findById(req.session.userId);
        res.render('verify-password-update', { 
            user: user, 
            error: null 
        });
    } catch (error) {
        console.error("Password Update Prompt Error:", error);
        res.status(500).render('error');
    }
});


// --- Error Handlers ---
// IMPORTANT: These MUST be the very last middleware/routes in the file!

// 404 Catch-All 
app.use((req, res, next) => {
    res.status(404).render('error', { error: "The page you are looking for does not exist." });
});

// Global Error Handler 
app.use((err, req, res, next) => {
    console.error("🔥 Global Error Caught:", err.stack);
    res.status(500).render('error', { error: "We are unable to process your request at this time. This event has been logged securely." });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 GapFinder server securely running on http://localhost:${PORT}`);
});