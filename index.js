require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const OpenAI = require('openai'); // Added for AI features

// Models (Ensure these files exist in your 'models' folder)
const User = require('./models/User');
const Note = require('./models/Note');
const Notification = require('./models/Notification');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// OpenAI Config
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY, 
});

// Multer Storage for Image Uploads
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { folder: 'notifications' },
});
const upload = multer({ storage: storage });

// --- AUTH MIDDLEWARE (FIXED) ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  // Check if header exists and has the 'Bearer ' prefix
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ error: "No token provided or invalid format" });
  }

  // Extract the token (remove "Bearer " string)
  const token = authHeader.split(' ')[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded; // Attach user data to request
    next();
  });
};

const verifyAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: "Access denied. Admins only." });
  }
  next();
};

// --- ROUTES ---

// 1. Auth: Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, role });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ error: "Server error during signup" });
  }
});

// 2. Auth: Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    // Create Token
    const token = jwt.sign(
      { id: user._id, role: user.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// 3. Notes (User Feature) - CRUD
app.get('/api/notes', verifyToken, async (req, res) => {
  try {
    const notes = await Note.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) {
    res.status(500).json({ error: "Error fetching notes" });
  }
});

app.post('/api/notes', verifyToken, async (req, res) => {
  try {
    const newNote = new Note({ userId: req.user.id, content: req.body.content });
    await newNote.save();
    res.json(newNote);
  } catch (err) {
    res.status(500).json({ error: "Error saving note" });
  }
});

// 4. NEW ROUTE: AI Summarization (Fixes Network/CORS Error)
app.post('/api/ai/summarize', verifyToken, async (req, res) => {
  try {
    const { text } = req.body;
    
    const response = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: "You are a helpful assistant that summarizes notes." },
        { role: "user", content: `Summarize this text: ${text}` }
      ],
      max_tokens: 150
    });

    res.json({ content: response.choices[0].message.content });
  } catch (err) {
    console.error("OpenAI Error:", err);
    res.status(500).json({ error: "Failed to fetch summary" });
  }
});

// 5. Notifications (Admin Feature - Upload)
app.post('/api/notifications', verifyToken, verifyAdmin, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Image is required" });

    const newNotif = new Notification({
      message: req.body.message,
      imageUrl: req.file.path
    });
    await newNotif.save();
    res.json(newNotif);
  } catch (err) {
    console.error("Upload Error:", err);
    res.status(500).json({ error: "Error uploading notification" });
  }
});

// 6. Public: Get Notifications
app.get('/api/notifications', async (req, res) => {
  try {
    const notifs = await Notification.find().sort({ createdAt: -1 });
    res.json(notifs);
  } catch (err) {
    res.status(500).json({ error: "Error fetching notifications" });
  }
});

// Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
