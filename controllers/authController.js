const bcrypt = require('bcrypt');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

const authController = {
    // Handle User Registration
    registerUser: async (req, res) => {
        try {
            const { username, password, confirmPassword, securityQuestion, securityAnswer } = req.body;

            // 1. Basic Validation: Ensure passwords match
            if (password !== confirmPassword) {
                return res.render('register', { error: "Passwords do not match." });
            }

            // Security Control 2.1.5 & 2.1.6: Enforce complexity and length requirements established by policy or regulation
            // Policy: Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number, and 1 special character.
            const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            
            if (!complexityRegex.test(password)) {
                // Security Control 2.3.1: All validation failures should result in input rejection. Sanitizing should not be used
                return res.render('register', { 
                    error: "Password does not meet complexity requirements. It must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character." 
                });
            }

            // Security Control 2.1.9: Strict enforcement of predefined, uncommon security questions
            const allowedQuestions = [
                "What is the name of a college you applied to but didn't attend?",
                "What was the name of the first school you remember attending?",
                "Where was the destination of your most memorable school field trip?",
                "What was your maths teacher's surname in your 8th year of school?",
                "What was the name of your first stuffed toy?",
                "What was your driving instructor's first name?",
                "What was the first concert you attended?"
            ];

            // Validate that the submitted question strictly matches one of the predefined options
            if (!allowedQuestions.includes(securityQuestion)) {
                return res.render('register', { 
                    error: "Invalid security question selected. Please choose a valid option from the dropdown menu." 
                });
            }

            // 2. Check if username already exists
            const existingUser = await User.findOne({ username });
            if (existingUser) {
                return res.render('register', { error: "Username is already taken." });
            }

            // 3. Security Control 2.1.3: Only cryptographically strong one-way salted hashes of passwords are stored
            const saltRounds = 12; 
            const passwordHash = await bcrypt.hash(password, saltRounds);
            
            // Hash the security answer as well
            const securityAnswerHash = await bcrypt.hash(securityAnswer.toLowerCase().trim(), saltRounds);

            // 4. Create the new user object (Defaults to Role B)
            const newUser = new User({
                username,
                passwordHash,
                securityQuestion,
                securityAnswerHash,
                lastPasswordChange: Date.now() // Added timestamp for minimum age policy
            });

            // 5. Save to MongoDB
            await newUser.save();

            // 6. Redirect to login upon success
            res.redirect('/login?registered=true');

        } catch (error) {
            // Security Control 2.4.1: Use error handlers that do not display debugging or stack trace information
            console.error(error); 
            res.status(500).render('error'); 
        }
    },

    // Handle User Login
    loginUser: async (req, res) => {
        try {
            const { username, password } = req.body;
            
            // Security Control 2.1.4: Authentication failure responses should not indicate which part of the authentication data was incorrect
            const genericAuthError = "Invalid username and/or password."; 

            const user = await User.findOne({ username });

            if (!user) {
                // Security Control 2.4.6: Log all authentication attempts, especially failures
                console.log(`[AUTH LOG - FAILURE] Unknown username attempted: ${username}`);
                return res.render('login', { error: genericAuthError });
            }

            // Security Control 2.1.8: Enforce account disabling after an established number of invalid login attempts
            if (user.accountLockedUntil && user.accountLockedUntil > Date.now()) {
                console.log(`[AUTH LOG - BLOCKED] Locked account attempted login: ${username}`);
                
                // Format the exact unlock time into a user-friendly string
                const unlockTime = new Date(user.accountLockedUntil).toLocaleTimeString([], { 
                    hour: '2-digit', 
                    minute: '2-digit' 
                });
                
                return res.render('login', { 
                    error: `Account is temporarily disabled due to too many invalid login attempts. Please try again after ${unlockTime}.` 
                });
            }

            // Compare the hashed password
            const isMatch = await bcrypt.compare(password, user.passwordHash);

            if (!isMatch) {
                // Increment failed attempts
                user.failedLoginAttempts += 1;
                user.lastFailedLogin = Date.now();
                console.log(`[AUTH LOG - FAILURE] Invalid password for: ${username}`);

                // Log the failed attempt to the Admin Dashboard 
                await AuditLog.create({
                    eventType: 'Auth Failure',
                    badgeColor: 'bg-warning text-dark',
                    userIdentifier: username,
                    details: `Failed login attempt (${user.failedLoginAttempts} failures).`
                });

                // Lock the account if it reaches 5 failed attempts
                if (user.failedLoginAttempts >= 5) {
                    user.accountLockedUntil = new Date(Date.now() + 15 * 60000); 
                    console.log(`[AUTH LOG - LOCKOUT] Account locked for 15 mins: ${username}`);
                    
                    // Log the critical lockout event to the Admin Dashboard
                    await AuditLog.create({
                        eventType: 'Account Lockout',
                        badgeColor: 'bg-danger',
                        userIdentifier: username,
                        details: 'Account temporarily locked due to 5 consecutive failed login attempts.'
                    });
                }

                await user.save();
                return res.render('login', { error: genericAuthError });
            }

            // --- Authentication Successful ---
            
            // Security Control 2.1.12: The last use (successful or unsuccessful) of a user account should be reported to the user at their next successful login
            const lastSuccess = user.lastSuccessfulLogin;
            const lastFail = user.lastFailedLogin;
            
            // Capture the number of failed attempts before resetting
            const previousFailures = user.failedLoginAttempts;

            // Reset lockout counters and update successful login time
            user.failedLoginAttempts = 0;
            user.accountLockedUntil = null;
            user.lastSuccessfulLogin = Date.now();
            await user.save();

            // Set the exact properties that server.js is looking for directly on req.session
            req.session.userId = user._id;
            req.session.username = user.username;
            req.session.role = user.role;
            req.session.lastSuccess = lastSuccess;
            req.session.lastFail = lastFail;
            req.session.previousFailures = previousFailures; // Stored in session for the frontend

            // Force the session to save BEFORE redirecting to prevent race conditions
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    return res.status(500).render('error');
                }

                console.log(`[AUTH LOG - SUCCESS] User logged in: ${username}`);

                // Direct the user to the correct dashboard based on their role
                if (user.role === 'Administrator') {
                    return res.redirect('/admin');
                } else if (user.role === 'Role A') {
                    return res.redirect('/coordinator');
                } else {
                    return res.redirect('/tutor');
                }
            });

        } catch (error) {
            console.error(error);
            // Security Control 2.4.2: Implement generic error messages and use custom error pages
            res.status(500).render('error');
        }
    },

    // Step 1 of Recovery: Check username and retrieve question
    verifyUsernameForReset: async (req, res) => {
        try {
            const { username } = req.body;
            const user = await User.findOne({ username });

            if (!user) {
                // Return a generic error to prevent username enumeration
                return res.render('forgot-password', { error: "If that username exists, the next step would load. Please check your spelling." });
            }

            // Render the next step, passing the username and their specific question
            res.render('reset-password', { 
                username: user.username, 
                securityQuestion: user.securityQuestion 
            });

        } catch (error) {
            console.error(error);
            res.status(500).render('error');
        }
    },

    // Step 2 of Recovery: Verify answer and change password
    resetPassword: async (req, res) => {
        try {
            const { username, securityAnswer, newPassword, confirmNewPassword } = req.body;
            
            // 1. Basic matching validation
            if (newPassword !== confirmNewPassword) {
                const user = await User.findOne({ username });
                return res.render('reset-password', { username, securityQuestion: user.securityQuestion, error: "Passwords do not match." });
            }

            // 2. Strict Complexity Validation
            const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            if (!complexityRegex.test(newPassword)) {
                const user = await User.findOne({ username });
                return res.render('reset-password', { username, securityQuestion: user.securityQuestion, error: "New password does not meet complexity requirements." });
            }

            const user = await User.findOne({ username });

            // --- Prevent Password Reuse During Recovery ---
            const isSameAsOld = await bcrypt.compare(newPassword, user.passwordHash);
            if (isSameAsOld) {
                return res.render('reset-password', { 
                    username, 
                    securityQuestion: user.securityQuestion, 
                    error: "Your new password must be different from your current password." 
                });
            }

            // 3. Verify Security Answer (compare hashed input against stored hash)
            const isAnswerCorrect = await bcrypt.compare(securityAnswer.toLowerCase().trim(), user.securityAnswerHash);

            if (!isAnswerCorrect) {
                console.log(`[AUTH LOG - RECOVERY FAILURE] Failed reset attempt for: ${username}`);
                return res.render('reset-password', { username, securityQuestion: user.securityQuestion, error: "Incorrect security answer." });
            }

            // 4. Update the password
            const saltRounds = 12;
            user.passwordHash = await bcrypt.hash(newPassword, saltRounds);
            user.lastPasswordChange = Date.now(); // Added timestamp for minimum age policy
            
            // Reset any active account lockouts since they successfully verified identity
            user.failedLoginAttempts = 0;
            user.accountLockedUntil = null;
            
            await user.save();
            console.log(`[AUTH LOG - RECOVERY SUCCESS] Password reset for: ${username}`);

            // Redirect back to login with a success message flag
            res.redirect('/login?reset=true');

        } catch (error) {
            console.error(error);
            res.status(500).render('error');
        }
    },

    // Step 1 of Security Center Update: Verify Security Question before rendering update form
    verifySecurityAnswerForUpdate: async (req, res) => {
        try {
            if (!req.session || !req.session.userId) {
                return res.redirect('/login');
            }

            const { securityAnswer } = req.body;
            const user = await User.findById(req.session.userId);

            const isAnswerCorrect = await bcrypt.compare(securityAnswer.toLowerCase().trim(), user.securityAnswerHash);

            if (!isAnswerCorrect) {
                console.log(`[AUTH LOG - SECURITY] Failed security question check for password change: ${user.username}`);
                return res.render('verify-password-update', { 
                    user, 
                    error: "Incorrect security answer. Access denied." 
                });
            }

            // Mark session as authorized for this critical operation
            req.session.passwordChangeAuthorized = true;

            res.render('security-update-form', { user, error: null, success: null });

        } catch (error) {
            console.error(error);
            res.status(500).render('error');
        }
    },

    // Step 2 of Security Center Update: Process Password Change, then Force Logout
    updatePassword: async (req, res) => {
        try {
            if (!req.session || !req.session.userId) {
                return res.redirect('/login');
            }

            // Ensure security question challenge was successfully completed first
            if (!req.session.passwordChangeAuthorized) {
                return res.redirect('/profile/security/verify-prompt');
            }

            const { currentPassword, newPassword, confirmNewPassword } = req.body;
            const user = await User.findById(req.session.userId);

            // --- Minimum Password Age Check (1 Day) ---
            if (user.lastPasswordChange) {
                const oneDayInMs = 24 * 60 * 60 * 1000;
                const timeSinceLastChange = Date.now() - new Date(user.lastPasswordChange).getTime();
                
                if (timeSinceLastChange < oneDayInMs) {
                    const hoursLeft = Math.ceil((oneDayInMs - timeSinceLastChange) / (1000 * 60 * 60));
                    return res.render('security-update-form', { 
                        user, 
                        error: `Security Policy: Passwords must be at least 1 day old. Try again in ${hoursLeft} hour(s).`, 
                        success: null 
                    });
                }
            }

            // 1. Verify current password
            const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
            if (!isMatch) {
                return res.render('security-update-form', { user, error: "Current password is incorrect.", success: null });
            }

            // 2. Ensure new passwords match
            if (newPassword !== confirmNewPassword) {
                return res.render('security-update-form', { user, error: "New passwords do not match.", success: null });
            }

            // 3. Enforce complexity requirements
            const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            if (!complexityRegex.test(newPassword)) {
                return res.render('security-update-form', { user, error: "New password does not meet complexity requirements.", success: null });
            }

            // 4. Ensure the new password isn't the same as the old password
            const isSameAsOld = await bcrypt.compare(newPassword, user.passwordHash);
            if (isSameAsOld) {
                return res.render('security-update-form', { user, error: "New password cannot be the same as your current password.", success: null });
            }

            // 5. Update and save
            const saltRounds = 12;
            user.passwordHash = await bcrypt.hash(newPassword, saltRounds);
            user.lastPasswordChange = Date.now(); 
            await user.save();
            
            console.log(`[AUTH LOG - SECURITY] User successfully changed password: ${user.username}`);

            // --- SECURITY REQUIREMENT: Destroy session and force back to login ---
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destruction error after password update:', err);
                }
                res.clearCookie('connect.sid');
                return res.redirect('/login?passwordChanged=true');
            });

        } catch (error) {
            console.error(error);
            res.status(500).render('error');
        }
    }, 

    // Handle User Logout
    logoutUser: (req, res) => {
        // Destroy the session to clear all secure data from the server
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destruction error:', err);
                return res.status(500).render('error');
            }
            
            // Clear the session cookie from the user's browser
            res.clearCookie('connect.sid'); 
            
            console.log('[AUTH LOG - LOGOUT] User successfully logged out.');
            
            // Redirect back to the index/landing page
            res.redirect('/');
        });
    }
};

module.exports = authController;