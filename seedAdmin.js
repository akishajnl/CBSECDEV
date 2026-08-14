// Load environment variables so we can connect to the database
require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const connectDB = require('./config/db');
const User = require('./models/User'); 

const seedAdmin = async () => {
    // 1. Connect to MongoDB
    await connectDB();

    try {
        // 2. Check if an admin already exists to prevent duplicates
        const existingAdmin = await User.findOne({ role: 'Administrator' });
        
        if (existingAdmin) {
            console.log("🛑 An Administrator account already exists in the database. Seeding aborted.");
            process.exit(0);
        }

        // 3. Define the admin credentials (change the password later!)
        const adminUsername = 'gapfinder_admin';
        const rawPassword = 'SecureAdmin@2026!';
        const securityQuestion = 'What is the first name of your lead thesis collaborator?';
        const rawSecurityAnswer = 'axl';

        // 4. Hash the password and security answer securely
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(rawPassword, saltRounds);
        const securityAnswerHash = await bcrypt.hash(rawSecurityAnswer, saltRounds);

        // 5. Build the Admin User object
        const newAdmin = new User({
            username: adminUsername,
            passwordHash: passwordHash,
            securityQuestion: securityQuestion,
            securityAnswerHash: securityAnswerHash,
            role: 'Administrator' // Explicitly overriding the Role B default
        });

        // 6. Save to the database
        await newAdmin.save();
        
        console.log(`✅ Success! Administrator account '${adminUsername}' has been seeded.`);
        console.log(`🔑 Temporary Password: ${rawPassword}`);
        console.log(`⚠️  Action Required: Log in and change this password immediately.`);
        
        process.exit(0);

    } catch (error) {
        console.error("❌ Error seeding the database:", error);
        process.exit(1);
    }
};

// Execute the function
seedAdmin();