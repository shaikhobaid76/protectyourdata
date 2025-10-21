const mongoose = require('mongoose');

const imageSchema = new mongoose.Schema({
    imageId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    imageData: {
        type: String,
        required: true
    },
    message: {
        type: String,
        default: ""
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 86400 // 24 hours in seconds
    },
    expiresAt: {
        type: Date,
        required: true,
        index: true
    },
    viewCount: {
        type: Number,
        default: 0
    },
    allowDownload: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

// TTL index for auto-deletion after expiresAt
imageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// TTL index for auto-deletion after 24 hours (backup)
imageSchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });

module.exports = mongoose.model('Image', imageSchema);