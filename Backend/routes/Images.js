const express = require('express');
const router = express.Router();
const Image = require('../models/Image');

// Save image to database
router.post('/', async (req, res) => {
    try {
        console.log('📨 Received image save request');
        const { imageId, imageData, message, expiresAt, allowDownload } = req.body;
        
        // Validate required fields
        if (!imageId || !imageData || !expiresAt) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: imageId, imageData, expiresAt'
            });
        }

        // Validate image data size
        if (imageData.length > 10 * 1024 * 1024) { // 10MB limit
            return res.status(400).json({
                success: false,
                message: 'Image data too large (max 10MB)'
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
        
        res.status(201).json({
            success: true,
            imageId: newImage.imageId,
            message: 'Image saved successfully'
        });
        
    } catch (error) {
        console.error('❌ Error saving image:', error);
        
        // Handle duplicate key error
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Image ID already exists'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Failed to save image to database',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get image from database
router.get('/:imageId', async (req, res) => {
    try {
        const { imageId } = req.params;
        console.log('📥 Fetching image:', imageId);
        
        const image = await Image.findOne({ imageId });
        
        if (!image) {
            console.log('❌ Image not found:', imageId);
            return res.status(404).json({
                success: false,
                message: 'Image not found or expired'
            });
        }
        
        // Check if image has expired
        if (new Date() > image.expiresAt) {
            console.log('⏰ Image expired, deleting:', imageId);
            await Image.deleteOne({ imageId });
            return res.status(410).json({
                success: false,
                message: 'Image has expired'
            });
        }
        
        // Increment view count
        image.viewCount += 1;
        await image.save();
        
        console.log('✅ Image retrieved successfully:', imageId, 'Views:', image.viewCount);
        
        res.json({
            success: true,
            imageData: image.imageData,
            message: image.message,
            viewCount: image.viewCount,
            expiresAt: image.expiresAt,
            allowDownload: image.allowDownload
        });
        
    } catch (error) {
        console.error('❌ Error retrieving image:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve image from database',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Delete image manually
router.delete('/:imageId', async (req, res) => {
    try {
        const { imageId } = req.params;
        
        const result = await Image.deleteOne({ imageId });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Image not found'
            });
        }
        
        console.log('🗑️ Image deleted manually:', imageId);
        
        res.json({
            success: true,
            message: 'Image deleted successfully'
        });
        
    } catch (error) {
        console.error('❌ Error deleting image:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete image'
        });
    }
});

// Get all images (for debugging)
router.get('/', async (req, res) => {
    try {
        const images = await Image.find({})
            .select('imageId createdAt expiresAt viewCount allowDownload')
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json({
            success: true,
            count: images.length,
            images: images
        });
        
    } catch (error) {
        console.error('❌ Error fetching images:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch images'
        });
    }
});

module.exports = router;