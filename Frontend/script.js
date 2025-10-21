// Constants
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const EMOJI_ALPHABET = [
    "🟠","🔵","🟢","🟣","🟡","🔴","⚫","⚪",
    "🟥","🟦","🟩","🟪","🟨","🟧","🟫","🔶",
    "🔷","🔳","🔲","⭐","✨","💫","🔥","❄️",
    "🌟","🌙","☀️","☁️","⚡","💥","💧","🍀",
    "🌈","🌊","🍎","🍓","🍇","🥑","🍋","🍉",
    "🍒","🍍","🥥","🥕","🌶️","🍄","🌽","🍅",
    "🎵","🎯","🎲","🎮","🎧","📌","📎","🔔",
    "🔑","🔒","🔓","📷","✈️","🚀","🚩","🏁"
];

// MongoDB Configuration
const API_BASE_URL = "https://protectyourdata-backend.onrender.com/";

// Create emoji mappings
const emojiMap = {};
const emojiReverseMap = {};
BASE64_CHARS.split("").forEach((ch, i) => {
    emojiMap[ch] = EMOJI_ALPHABET[i];
    emojiReverseMap[EMOJI_ALPHABET[i]] = ch;
});

// Initialize variables
let currentTab = 'encrypt';
let selectedImage = null;
let imageExpiryTimer = null;
let allowDownload = false;
let currentDecryptedImage = null;

// ✅ ADD THIS FUNCTION - Generate Unique ID (FIXED)
function generateUniqueId() {
    const timestamp = Date.now().toString(36);
    const randomStr = Math.random().toString(36).substr(2, 9);
    return `img_${timestamp}_${randomStr}`;
}

// Screenshot Protection Functions
function setupScreenshotProtection() {
    // Prevent right-click context menu
    document.addEventListener('contextmenu', function(e) {
        if (e.target.closest('.protected-image-container')) {
            e.preventDefault();
            setStatus("Right-click is disabled for protected images", "warning");
        }
    });
    
    // Prevent drag and drop
    document.addEventListener('dragstart', function(e) {
        if (e.target.closest('.protected-image-container')) {
            e.preventDefault();
        }
    });
    
    // Detect screenshot attempts
    document.addEventListener('keydown', function(e) {
        // Detect Print Screen key
        if (e.key === 'PrintScreen' || (e.ctrlKey && e.key === 'p')) {
            const protectedImages = document.querySelectorAll('.protected-image-container img');
            if (protectedImages.length > 0) {
                setStatus("Screenshot protection active - images are protected", "warning");
            }
        }
    });
    
    // Add overlay on hover for protected images
    const protectedContainers = document.querySelectorAll('.protected-image-container');
    protectedContainers.forEach(container => {
        const overlay = container.querySelector('.protected-image-overlay');
        const img = container.querySelector('img');
        const canvas = container.querySelector('canvas');
        
        if (img && canvas) {
            // Draw image to canvas for additional protection
            img.onload = function() {
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
            };
        }
        
        container.addEventListener('mouseenter', function() {
            if (overlay) overlay.classList.add('active');
        });
        
        container.addEventListener('mouseleave', function() {
            if (overlay) overlay.classList.remove('active');
        });
        
        // Prevent image selection
        container.addEventListener('selectstart', function(e) {
            e.preventDefault();
        });
    });
}

// Helper functions
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(b64) {
    const binary = window.atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// PBKDF2 derive key from password and salt
async function deriveKey(passwordStr, salt) {
    const enc = new TextEncoder();
    const pwKey = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(passwordStr),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 150000,
            hash: "SHA-256",
        },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    return key;
}

// Encrypt: returns base64(payload) where payload = salt(16) + iv(12) + ciphertext
async function encryptText(plaintext, passwordStr) {
    setStatus("Encrypting...", "info");
    try {
        const enc = new TextEncoder();
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(passwordStr, salt.buffer);
        const ct = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            enc.encode(plaintext)
        );
        // concat salt + iv + ct
        const payload = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
        payload.set(salt, 0);
        payload.set(iv, salt.byteLength);
        payload.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);
        const b64 = arrayBufferToBase64(payload.buffer);
        setStatus("Encrypted successfully!", "success");
        return b64;
    } catch (e) {
        setStatus("Encryption failed: " + e.message, "error");
        throw e;
    }
}

async function decryptBase64Payload(b64Payload, passwordStr) {
    try {
        const payloadBuf = base64ToArrayBuffer(b64Payload);
        const payload = new Uint8Array(payloadBuf);
        const salt = payload.slice(0, 16);
        const iv = payload.slice(16, 28);
        const ct = payload.slice(28);
        const key = await deriveKey(passwordStr, salt.buffer);
        const ptBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
        const dec = new TextDecoder();
        setStatus("Decrypted successfully!", "success");
        return dec.decode(ptBuf);
    } catch (e) {
        setStatus("Decryption failed: " + e.message, "error");
        throw e;
    }
}

// Format conversion functions
function base64ToEmoji(b64) {
    return b64
        .split("")
        .map((ch) => (ch === "=" ? "🔚" : emojiMap[ch] || "❓"))
        .join("");
}

function emojiToBase64(emojiStr) {
    let b64 = emojiStr;
    b64 = b64.split("🔚").join("=");
    for (const [ch, em] of Object.entries(emojiMap)) {
        const re = new RegExp(em.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&"), "g");
        b64 = b64.replace(re, ch);
    }
    return b64;
}

function base64ToHex(b64) {
    const bytes = new Uint8Array(base64ToArrayBuffer(b64));
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBase64(hex) {
    const hexStr = hex.replace(/[^0-9a-fA-F]/g, "");
    const bytes = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    return arrayBufferToBase64(bytes.buffer);
}

function base64ToBinary(b64) {
    const bytes = new Uint8Array(base64ToArrayBuffer(b64));
    return Array.from(bytes).map((b) => b.toString(2).padStart(8, "0")).join(" ");
}

function binaryToBase64(binary) {
    const binaryStr = binary.replace(/[^01]/g, "");
    const bytes = new Uint8Array(binaryStr.length / 8);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(binaryStr.substr(i * 8, 8), 2);
    }
    return arrayBufferToBase64(bytes.buffer);
}

// MongoDB API functions - DATABASE MEIN 2 HOURS FIXED
async function saveImageToDatabase(imageData, message, allowDownload) {
    try {
        setStatus("Please Wait...", "info");
        
        const imageId = generateUniqueId();
        
        // ✅ DATABASE: Fixed 2 hours (120 minutes) - MongoDB Atlas mein 2 hours baad delete
        const expiryTime = new Date();
        expiryTime.setHours(expiryTime.getHours() + 2); // 2 hours fixed for database
        
        const imageRecord = {
            imageId: imageId,
            imageData: imageData,
            message: message || "",
            expiresAt: expiryTime.toISOString(),
            allowDownload: allowDownload
        };
        
        console.log("📤 Sending to backend - Database expiry: 2 hours");
        
        const response = await fetch(`${API_BASE_URL}/images`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(imageRecord)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        
        if (result.success) {
            console.log("✅ Save successful - Database auto-delete: 2 hours");
            return result.imageId;
        } else {
            throw new Error(result.message || "Unknown error");
        }
    } catch (error) {
        console.error("❌ Save image error:", error);
        setStatus(`❌ Failed to save: ${error.message}`, "error");
        throw error;
    }
}

async function getImageFromDatabase(imageId) {
    try {
        
        console.log("📥 Fetching image:", imageId);
        const response = await fetch(`${API_BASE_URL}/images/${imageId}`);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        
        if (result.success) {
            console.log("✅ Image retrieved");
            return result;
        } else {
            throw new Error(result.message || "Unknown error");
        }
        
    } catch (error) {
        console.error("❌ Get image error:", error);
        setStatus(`❌ Failed to retrieve: ${error.message}`, "error");
        throw error;
    }
}

// Download function
function downloadImage(imageData, fileName) {
    const link = document.createElement('a');
    link.href = imageData;
    link.download = fileName || 'encrypted_image.png';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setStatus("Image downloaded successfully!", "success");
}

// Image handling functions
function handleImageUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    if (!file.type.match('image.*')) {
        setStatus("Please select an image file.", "error");
        return;
    }
    
    // Check file size (limit to 5MB)
    if (file.size > 5 * 1024 * 1024) {
        setStatus("Image size should be less than 5MB.", "error");
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        selectedImage = {
            name: file.name,
            type: file.type,
            size: file.size,
            data: e.target.result
        };
        
        // Show preview
        document.getElementById('imagePreview').src = e.target.result;
        document.getElementById('imagePreviewContainer').classList.remove('hidden');
        document.getElementById('imageInfo').textContent = `${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
        document.getElementById('fileInputLabel').textContent = file.name;
        
        // Show display time options (1-5 minutes for frontend only)
        document.getElementById('autoDeleteTimeContainer').classList.remove('hidden');
        
        // Setup screenshot protection for the preview
        setTimeout(() => {
            setupScreenshotProtection();
        }, 100);
        
        setStatus("Image uploaded successfully!", "success");
    };
    reader.readAsDataURL(file);
}

function clearImage() {
    selectedImage = null;
    document.getElementById('imagePreviewContainer').classList.add('hidden');
    document.getElementById('imageInput').value = '';
    document.getElementById('fileInputLabel').textContent = 'Choose an image file...';
    
    // Hide display time options
    document.getElementById('autoDeleteTimeContainer').classList.add('hidden');
    
    // Reset download toggle
    allowDownload = false;
    document.getElementById('toggleSwitch').classList.remove('active');
}

function showDecryptedImage(imageData, displayTime, allowDownloadFlag, fileName) {
    document.getElementById('imageOutput').src = imageData;
    document.getElementById('imageOutputContainer').classList.remove('hidden');
    
    // Store current image data for download
    currentDecryptedImage = {
        data: imageData,
        fileName: fileName || 'decrypted_image.png',
        allowDownload: allowDownloadFlag
    };
    
    // Enable/disable download button based on permission
    const downloadBtn = document.getElementById('downloadImageBtn');
    if (allowDownloadFlag) {
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = '<i class="fas fa-download mr-2"></i> Download Image';
    } else {
        downloadBtn.disabled = true;
        downloadBtn.innerHTML = '<i class="fas fa-ban mr-2"></i> Download Not Allowed';
    }
    
    // Calculate remaining time for display (user selected time)
    const displayExpiryTime = new Date();
    displayExpiryTime.setMinutes(displayExpiryTime.getMinutes() + parseInt(displayTime));
    const remainingDisplayTime = Math.max(0, Math.floor((displayExpiryTime - new Date()) / 1000 / 60));
    
    document.getElementById('imageOutputInfo').textContent = `Image will disappear in ${remainingDisplayTime} minutes (Database auto-delete: 2 hours)`;
    
    // Setup screenshot protection for the decrypted image
    setTimeout(() => {
        setupScreenshotProtection();
    }, 100);
    
    // Set timer to remove image from frontend after user selected time
    if (imageExpiryTimer) clearTimeout(imageExpiryTimer);
    imageExpiryTimer = setTimeout(() => {
        document.getElementById('imageOutputContainer').classList.add('hidden');
        currentDecryptedImage = null;
        setStatus(`Image hidden after ${displayTime} minutes (Still in database for 2 hours total)`, "info");
    }, parseInt(displayTime) * 60 * 1000);
}

// UI Functions
function setStatus(message, type = "info") {
    const statusEl = document.createElement('div');
    statusEl.className = `status-message`;
    statusEl.textContent = message;
    document.body.appendChild(statusEl);
    
    setTimeout(() => {
        statusEl.remove();
    }, 3000);
}

function clearEncryptSection() {
    document.getElementById('plainText').value = '';
    document.getElementById('password').value = '';
    document.getElementById('encodedOutput').innerHTML = '<p class="text-gray-400">Your encrypted message will appear here...</p>';
    document.getElementById('encodedOutput').classList.add('text-gray-400');
    clearImage();
}

function clearDecryptSection() {
    document.getElementById('decryptInput').value = '';
    document.getElementById('decryptPassword').value = '';
    document.getElementById('decryptedOutput').innerHTML = '<p class="text-gray-400">Your decrypted message will appear here...</p>';
    document.getElementById('decryptedOutput').classList.add('text-gray-400');
    document.getElementById('imageOutputContainer').classList.add('hidden');
    currentDecryptedImage = null;
    if (imageExpiryTimer) {
        clearTimeout(imageExpiryTimer);
        imageExpiryTimer = null;
    }
}

function switchTab(tabName) {
    // Clear the other tab's content when switching
    if (tabName === 'encrypt') {
        clearDecryptSection();
    } else {
        clearEncryptSection();
    }
    
    // Update tab UI
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Show/hide sections
    if (tabName === 'encrypt') {
        document.getElementById('encrypt-section').classList.remove('hidden');
        document.getElementById('decrypt-section').classList.add('hidden');
    } else {
        document.getElementById('encrypt-section').classList.add('hidden');
        document.getElementById('decrypt-section').classList.remove('hidden');
    }
    
    currentTab = tabName;
}

async function handleEncryptClick() {
    const plain = document.getElementById('plainText').value;
    const password = document.getElementById('password').value;
    const outputFormat = document.getElementById('outputFormat').value;
    const displayTime = document.getElementById('deleteTime').value; // User selected display time (1-5 min)
    const encodedOutput = document.getElementById('encodedOutput');
    
    if (!plain && !selectedImage) return setStatus("Please enter text or upload an image to encrypt.", "error");
    if (!password) return setStatus("Please set a password for encryption.", "error");
    
    try {
        let encryptedData;
        
        if (selectedImage) {
            // Save image to database with FIXED 2 hours expiry
            const imageId = await saveImageToDatabase(selectedImage.data, plain, allowDownload);
            
            // Create marker with image ID, USER SELECTED DISPLAY TIME, and download permission
            const imageMarker = `[IMAGE_ID:${imageId}|DISPLAY_TIME:${displayTime}|DOWNLOAD:${allowDownload}]${plain || ''}`;
            encryptedData = await encryptText(imageMarker, password);
        } else {
            // Encrypt only text
            encryptedData = await encryptText(plain, password);
        }
        
        let out = encryptedData;
        
        // Convert to selected format
        if (outputFormat === "hex") {
            out = base64ToHex(encryptedData);
        } else if (outputFormat === "emoji") {
            out = base64ToEmoji(encryptedData);
        } else if (outputFormat === "binary") {
            out = base64ToBinary(encryptedData);
        }
        
        encodedOutput.innerHTML = `<p class="break-words">${out}</p>`;
        encodedOutput.classList.remove('text-gray-400');
    } catch (e) {
        // error already set in status
    }
}

async function handleDecryptClick() {
    const decryptInput = document.getElementById('decryptInput').value;
    const decryptPassword = document.getElementById('decryptPassword').value;
    const decryptFormat = document.getElementById('decryptFormat').value;
    const decryptedOutput = document.getElementById('decryptedOutput');
    
    if (!decryptInput) return setStatus("Please paste encrypted text to decrypt.", "error");
    if (!decryptPassword) return setStatus("Please enter password to decrypt.", "error");
    
    try {
        let b64 = decryptInput;
        
        // Convert from selected format back to base64
        if (decryptFormat === "hex") {
            b64 = hexToBase64(decryptInput);
        } else if (decryptFormat === "emoji") {
            b64 = emojiToBase64(decryptInput);
        } else if (decryptFormat === "binary") {
            b64 = binaryToBase64(decryptInput);
        }
        
        // Auto-detect: if the pasted input contains any of our emoji alphabet, prefer emoji decoding
        const containsEmoji = EMOJI_ALPHABET.some((e) => decryptInput.includes(e));
        if (containsEmoji && decryptFormat !== "emoji") {
            b64 = emojiToBase64(decryptInput);
        }

        const pt = await decryptBase64Payload(b64, decryptPassword);
        
        // Check if the decrypted content contains an image ID
        const imageMatch = pt.match(/\[IMAGE_ID:(.*?)\|DISPLAY_TIME:(.*?)\|DOWNLOAD:(.*?)\](.*)/);
        if (imageMatch) {
            const imageId = imageMatch[1];
            const displayTime = imageMatch[2]; // User selected display time (1-5 min)
            const allowDownloadFlag = imageMatch[3] === 'true';
            const message = imageMatch[4];
            
            try {
                // Retrieve image from database (will work only for 2 hours total)
                const imageRecord = await getImageFromDatabase(imageId);
                
                // Show the image with USER SELECTED DISPLAY TIME
                showDecryptedImage(imageRecord.imageData, displayTime, allowDownloadFlag, selectedImage?.name);
                
                // Show the message if any
                if (message) {
                    decryptedOutput.innerHTML = `<p class="break-words">${message}</p>`;
                } else {
                    decryptedOutput.innerHTML = `<p class="break-words">Image decrypted successfully! (Display: ${displayTime} min | Database: 2 hours)</p>`;
                }
            } catch (error) {
                decryptedOutput.innerHTML = `<p class="break-words text-red-400">${error.message}</p>`;
            }
        } else {
            decryptedOutput.innerHTML = `<p class="break-words">${pt}</p>`;
        }
        
        decryptedOutput.classList.remove('text-gray-400');
    } catch (e) {
        // status set in decrypt
    }
}

async function handlePasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        document.getElementById('decryptInput').value = text;
        setStatus("Pasted from clipboard!", "success");
    } catch (err) {
        setStatus("Failed to paste from clipboard", "error");
    }
}

function handleCopy(text, elementId) {
    if (!text || text.includes("will appear here")) return setStatus("Nothing to copy.", "error");
    navigator.clipboard
        .writeText(text)
        .then(() => setStatus("Copied to clipboard!", "success"))
        .catch((e) => setStatus("Copy failed: " + e.message, "error"));
}

function clearEncrypt() {
    clearEncryptSection();
    setStatus("Encrypt section cleared", "info");
}

function clearDecrypt() {
    clearDecryptSection();
    setStatus("Decrypt section cleared", "info");
}

// Test backend connection on page load
async function initializeApp() {
    try {
        console.log("🔗 Testing backend connection...");
        const response = await fetch(`${API_BASE_URL}/health`);
        const result = await response.json();
        
        if (result.success) {
            console.log("✅ Backend connected:", result);
        } else {
            throw new Error("Backend health check failed");
        }
    } catch (error) {
        console.error("❌ Backend connection failed:", error);
        setStatus("❌ Backend connection failed - Make sure server is running on port 5000", "error");
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    
    // Set up event listeners
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function() {
            switchTab(this.getAttribute('data-tab'));
        });
    });
    
    document.getElementById('encryptBtn').addEventListener('click', handleEncryptClick);
    document.getElementById('decryptBtn').addEventListener('click', handleDecryptClick);
    document.getElementById('copyEncodedBtn').addEventListener('click', () => {
        const text = document.getElementById('encodedOutput').textContent;
        handleCopy(text, 'encodedOutput');
    });
    document.getElementById('copyDecryptedBtn').addEventListener('click', () => {
        const text = document.getElementById('decryptedOutput').textContent;
        handleCopy(text, 'decryptedOutput');
    });
    document.getElementById('clearEncryptBtn').addEventListener('click', clearEncrypt);
    document.getElementById('clearDecryptBtn').addEventListener('click', clearDecrypt);
    document.getElementById('imageInput').addEventListener('change', handleImageUpload);
    document.getElementById('pasteBtn').addEventListener('click', handlePasteFromClipboard);
    document.getElementById('downloadImageBtn').addEventListener('click', () => {
        if (currentDecryptedImage && currentDecryptedImage.allowDownload) {
            downloadImage(currentDecryptedImage.data, currentDecryptedImage.fileName);
        }
    });
    
    // Download toggle event
    document.getElementById('downloadToggle').addEventListener('click', function() {
        allowDownload = !allowDownload;
        const toggleSwitch = document.getElementById('toggleSwitch');
        if (allowDownload) {
            toggleSwitch.classList.add('active');
            setStatus("Download enabled - Users can download this image", "success");
        } else {
            toggleSwitch.classList.remove('active');
            setStatus("Download disabled - Users cannot download this image", "info");
        }
    });
    
    // Initialize screenshot protection
    setupScreenshotProtection();
});