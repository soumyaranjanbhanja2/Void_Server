require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
// ✅ Import OpenAI
const OpenAI = require('openai'); 

// --- MODELS ---
const User = require('./models/User');
const Note = require('./models/Note');
const Notification = require('./models/Notification');

const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- DATABASE ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- CONFIGURATION ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ✅ OPENAI SETUP
if (!process.env.OPENAI_API_KEY) {
  console.error("❌ ERROR: OPENAI_API_KEY is missing!");
}

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY, 
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { folder: 'notifications' },
});
const upload = multer({ storage: storage });

// --- AUTH MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ error: "No token provided" });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded;
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

// 1. Auth
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, role });
    await newUser.save();
    res.status(201).json({ message: 'User created' });
  } catch (err) { res.status(500).json({ error: "Signup error" }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role });
  } catch (err) { res.status(500).json({ error: "Login error" }); }
});

// 2. Notes
app.get('/api/notes', verifyToken, async (req, res) => {
  try {
    const notes = await Note.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) { res.status(500).json({ error: "Error fetching notes" }); }
});

app.post('/api/notes', verifyToken, async (req, res) => {
  try {
    const title = req.body.title || (req.body.content ? req.body.content.substring(0, 30) + "..." : "Untitled");
    const newNote = new Note({ userId: req.user.id, title, content: req.body.content });
    await newNote.save();
    res.json(newNote);
  } catch (err) { res.status(500).json({ error: "Error saving note" }); }
});

app.delete('/api/notes/:id', verifyToken, async (req, res) => {
  try {
    await Note.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ message: "Note deleted" });
  } catch (err) { res.status(500).json({ error: "Error deleting note" }); }
});

// --- 3. AI SUMMARY (SWITCHED TO OPENAI) ---
app.post('/api/ai/summarize', verifyToken, async (req, res) => {
  try {
    const { text } = req.body;
    if(!text) return res.status(400).json({error: "Text is required"});

    console.log("🤖 OpenAI Request for:", text.substring(0, 20) + "...");

    // ✅ Using GPT-4o-mini (Cheapest & Fast) or gpt-3.5-turbo
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini", // Cost-effective model
      messages: [
        { role: "system", content: "You are a helpful assistant that summarizes notes concisely in bullet points." },
        { role: "user", content: text }
      ],
      max_tokens: 200,
    });

    const textOutput = response.choices[0].message.content;

    console.log("✅ OpenAI Success");
    res.json({ content: textOutput });

  } catch (err) {
    console.error("❌ OpenAI Error Details:", err); 
    
    // Check for Quota Error specifically
    if (err.status === 429) {
        return res.status(429).json({ error: "OpenAI Quota Exceeded. Check billing." });
    }

    res.status(500).json({ error: "AI Service Failed", details: err.message });
  }
});

// 4. Notifications
app.post('/api/notifications', verifyToken, verifyAdmin, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Image is required" });
    const newNotif = new Notification({ message: req.body.message, imageUrl: req.file.path });
    await newNotif.save();
    res.json(newNotif);
  } catch (err) { res.status(500).json({ error: "Upload error" }); }
});

app.get('/api/notifications', async (req, res) => {
  try {
    const notifs = await Notification.find().sort({ createdAt: -1 });
    res.json(notifs);
  } catch (err) { res.status(500).json({ error: "Fetch error" }); }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
