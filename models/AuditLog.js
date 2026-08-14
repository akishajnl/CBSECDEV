const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    timestamp: { 
        type: Date, 
        default: Date.now 
    },
    eventType: { 
        type: String, 
        required: true 
    },
    badgeColor: { 
        type: String, 
        default: 'bg-secondary' 
    },
    userIdentifier: { 
        type: String, 
        required: true 
    },
    details: { 
        type: String, 
        required: true 
    }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);