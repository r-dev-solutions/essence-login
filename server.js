const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors'); // Add this line
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

const app = express();
app.use(bodyParser.json());
app.use(cors({
    methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

// Mock user database
const users = [{
    id: 1,
    username: 'testuser', // Changed from email
    password: '$2a$10$ExampleHash'
}];

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body; // Changed from email
    
    try {
        // Find user
        const user = await User.findOne({ username }); // Changed from email
        if (!user) return res.status(400).send('User not found');

        // Check password
        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid password');

        // Create and assign token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.header('auth-token', token).send({ token });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
    res.send('This is protected content');
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const token = req.header('auth-token');
    if (!token) return res.status(401).send('Access denied');

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid token');
    }
}

// User registration endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).send('Username already exists');

        // Hash password
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        // Create new user
        const newUser = new User({
            username,
            password: hashedPassword
        });

        // Save user to database
        await newUser.save();
        res.status(201).send('User registered successfully');
    } catch (err) {
        console.error('Registration error:', err); // Add detailed error logging
        res.status(500).send(`Server error: ${err.message}`);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));