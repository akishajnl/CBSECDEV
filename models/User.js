const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Required for the new security methods

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    passwordHash: {
        type: String,
        required: true
        // Only cryptographically strong one-way salted hashes are stored here
    },
    role: {
        type: String,
        enum: ['Administrator', 'Role A', 'Role B'],
        default: 'Role B'
    },
    // Security Control: Custom security question for password resets
    securityQuestion: {
        type: String,
        required: true
    },
    securityAnswerHash: {
        type: String,
        required: true
    },
    // Security Control: Account disabling after invalid login attempts
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    accountLockedUntil: {
        type: Date,
        default: null
    },
    // Security Control: Password age restrictions
    lastPasswordChange: {
        type: Date,
        default: Date.now
    },
    // Security Control: Reporting last use to the user
    lastSuccessfulLogin: {
        type: Date,
        default: null
    },
    lastFailedLogin: {
        type: Date,
        default: null
    }
}, { timestamps: true });


// --- ADVANCED SECURITY METHODS ---

// 1. Hook to automatically update the 'lastPasswordChange' timestamp 
//    This triggers automatically right before the document saves to the database

userSchema.pre('save', function() {
    if (this.isModified('passwordHash')) {
        this.lastPasswordChange = Date.now();
    }
});

// 2. Helper method to securely verify a password login attempt
userSchema.methods.isValidPassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.passwordHash);
};

// 3. Helper method to securely verify the security question answer
userSchema.methods.isValidSecurityAnswer = async function(candidateAnswer) {
    // Ensures the answer is evaluated consistently (lowercase and trimmed of spaces)
    return await bcrypt.compare(candidateAnswer.toLowerCase().trim(), this.securityAnswerHash);
};

module.exports = mongoose.model('User', userSchema);