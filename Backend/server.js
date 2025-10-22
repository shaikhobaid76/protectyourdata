const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
const MONGODB_URI = "mongodb+srv://shaobaid76:Skobaid%40247786@cluster0.jejfh2z.mongodb.net/hidden_messenger?retryWrites=true&w=majority";

console.log('🔗 Connecting to MongoDB...');

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ MongoDB Connected Successfully!');
})
.catch((error) => {
    console.error('❌ MongoDB Connection Failed:', error.message);
});

// Simple Image Model
const imageSchema = new mongoose.Schema({
    imageId: String,
    imageData: String,
    message: String,
    expiresAt: Date,
    allowDownload: Boolean,
    createdAt: { type: Date, default: Date.now }
});

const Image = mongoose.model('Image', imageSchema);

// Routes

// Health check
app.get('/api/health', (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
    res.json({ 
        success: true, 
        message: 'Server is running!',
        database: dbStatus,
        timestamp: new Date().toISOString()
    });
});

// Save image
app.post('/api/images', async (req, res) => {
    try {
        console.log('📨 Received image save request');
        
        const { imageId, imageData, message, expiresAt, allowDownload } = req.body;
        
        // Basic validation
        if (!imageId || !imageData) {
            return res.status(400).json({
                success: false,
                message: 'Image ID and data are required'
            });
        }

        const newImage = new Image({
            imageId,
            imageData,
            message: message || "",
            expiresAt: new Date(expiresAt),
            allowDownload: allowDownload || false
        });
        
        await newImage.save();
        
        console.log('✅ Image saved successfully:', imageId);
        
        res.json({
            success: true,
            imageId: imageId,
            message: 'Image saved successfully'
        });
        
    } catch (error) {
        console.error('❌ Error saving image:', error.message);
        res.status(500).json({
            success: false,
            message: 'Failed to save image: ' + error.message
        });
    }
});

// Get image
app.get('/api/images/:imageId', async (req, res) => {
    try {
        const { imageId } = req.params;
        console.log('📥 Fetching image:', imageId);
        
        const image = await Image.findOne({ imageId });
        
        if (!image) {
            return res.status(404).json({
                success: false,
                message: 'Image not found'
            });
        }
        
        // Check expiration
        if (new Date() > new Date(image.expiresAt)) {
            await Image.deleteOne({ imageId });
            return res.status(410).json({
                success: false,
                message: 'Image has expired'
            });
        }
        
        console.log('✅ Image found:', imageId);
        
        res.json({
            success: true,
            imageData: image.imageData,
            message: image.message,
            expiresAt: image.expiresAt,
            allowDownload: image.allowDownload
        });
        
    } catch (error) {
        console.error('❌ Error retrieving image:', error.message);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve image: ' + error.message
        });
    }
});

// Get all images (for debugging)
app.get('/api/images', async (req, res) => {
    try {
        const images = await Image.find({}).sort({ createdAt: -1 }).limit(10);
        res.json({
            success: true,
            count: images.length,
            images: images.map(img => ({
                imageId: img.imageId,
                createdAt: img.createdAt,
                expiresAt: img.expiresAt
            }))
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Health check: https://protectyourdata-backend-1.onrender.com/api/health`);
    console.log(`📍 Server accessible from: http://0.0.0.0:${PORT}`);
});