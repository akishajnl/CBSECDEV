// middleware/auth.js

const authMiddleware = {
    // 1. General Authentication & Inactivity Check 
    requireAuth: (req, res, next) => {
        // First check if they have a session at all
        if (!req.session || !req.session.userId) {
            return res.redirect('/login');
        }

        // --- Inactivity (Idle Timeout) Tracking ---
        const now = Date.now();
        const maxIdleTime = 15 * 60 * 1000; // 15 minutes in milliseconds

        // Check if the session has been idle for longer than the maximum allowed time
        if (req.session.lastActivity && (now - req.session.lastActivity > maxIdleTime)) {
            console.log(`[SECURITY - TIMEOUT] Session destroyed due to inactivity for user: ${req.session.username}`);
            
            return req.session.destroy((err) => {
                if (err) console.error('Session destruction error on timeout:', err);
                res.clearCookie('connect.sid'); // Wipe the cookie from the browser
                
                // Redirect to login with a timeout flag so the frontend can display a message
                return res.redirect('/login?timeout=true');
            });
        }

        // If they are active, update their last activity timestamp for this request
        req.session.lastActivity = now;
        
        // They are allowed in, proceed to the route
        return next();
    },

    // 2. Role-Based Access Control Check
    // Note: It is best practice to chain requireAuth BEFORE requireRole in your routes
    // Example: router.get('/admin', requireAuth, requireRole('Administrator'), adminController.getDashboard);
    requireRole: (requiredRole) => {
        return (req, res, next) => {
            // Ensure they are logged in and their role matches what is required
            if (req.session && req.session.userId && req.session.role === requiredRole) {
                return next(); // Proceed to the route
            }
            
            // If they fail the role check, deny access safely and log the attempt
            console.log(`[SECURITY - BLOCKED] User ${req.session.username || 'Unknown'} attempted to access a ${requiredRole} route.`);
            return res.status(403).render('error', { error: "Forbidden: You do not have sufficient privileges to view this resource." });
        };
    }
};

module.exports = authMiddleware;