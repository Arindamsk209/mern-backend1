const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET || 'asdfe45we45w345wegw345werjktjwertkj'; // Make sure to use process.env
const port = process.env.PORT || 4000;

app.use(cors({
  credentials: true,
  origin: ['https://fascinating-truffle-d8d0b4.netlify.app'], // Ensure only the front-end is allowed
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());
app.use(cookieParser());

mongoose.connect('mongodb+srv://arindamsingh209:arindam@cluster1.29d0mug.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Login Page
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (!userDoc) {
    return res.status(400).json('User not found');
  }
  
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    // logged in
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) return res.status(500).json({ error: 'Failed to create token' });
      res.cookie('token', token, { httpOnly: true, secure: true }); // Ensure secure cookie in production
      res.json({
        id: userDoc._id,
        username,
        token,
      });
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

// Register Page
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e.message); // Improved error response
  }
});

// Create Post Page
app.post('/post', async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const { title, summary, content, cover } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover,
      author: info.id,
    });
    res.json(postDoc);
  });
});

// Edit Post Page
app.put('/post', async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const { id, title, summary, content, cover } = req.body;
    const postDoc = await Post.findByIdAndUpdate(id, {
      title,
      summary,
      content,
      cover,
    }, { new: true }); // Return the updated document
    res.json(postDoc);
  });
});

// Get User Profile
app.get('/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract Bearer token

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const userDoc = await User.findById(info.id);
    if (!userDoc) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(userDoc);
  });
});

// Show the post at home page
app.get('/post', async (req, res) => {
  const posts = await Post.find()
    .populate('author', ['username'])
    .sort({ createdAt: -1 })
    .limit(20);
  
  res.json(posts);
});

// Logout
app.post('/logout', async (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// Post Page
app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', ['username']);
  if (!postDoc) {
    return res.status(404).json({ error: 'Post not found' });
  }
  res.json(postDoc);
});

app.listen(port, () => { 
  console.log(`Server is running on port ${port}`);
});
