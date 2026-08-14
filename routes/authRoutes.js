const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// POST route for submitting the registration form
router.post('/register', authController.registerUser);

// POST route for submitting the login form
router.post('/login', authController.loginUser);

// POST route for looking up the username (Forgot Password Step 1)
router.post('/verify-username', authController.verifyUsernameForReset);

// POST route for resetting the actual password (Forgot Password Step 2)
router.post('/reset-password', authController.resetPassword);

// Add this line to authRoutes.js
router.post('/update-password', authController.updatePassword);

// Handle logout
router.get('/logout', authController.logoutUser);

// Security Center Password Update Workflow
router.post('/security/verify-answer', authController.verifySecurityAnswerForUpdate);
router.post('/security/update', authController.updatePassword);

module.exports = router;