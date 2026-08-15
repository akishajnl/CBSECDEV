// middleware/auth.js

const authMiddleware = {
    // 1. General Authentication Check (Is the user logged in?)
    requireAuth: (req, res, next) => {
        if (req.session && req.session.userId) {
            return next(); // They are allowed in, proceed to the route
        }
        // If not, instantly reject and redirect
        return res.redirect('/login');
    },

    // 2. Role-Based Access Control Check (Are they an Admin?)
    requireRole: (requiredRole) => {
        return (req, res, next) => {
            // First ensure they are logged in and their role matches what is required
            if (req.session && req.session.userId && req.session.role === requiredRole) {
                return next(); // Proceed to the route
            }
            // If they fail the role check, deny access safely
            console.log(`[SECURITY - BLOCKED] User ${req.session.username || 'Unknown'} attempted to access a ${requiredRole} route.`);
            return res.status(403).render('error', { error: "Forbidden: You do not have sufficient privileges to view this resource." });
        };
    }
};

module.exports = authMiddleware;