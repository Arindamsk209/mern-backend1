const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User'); 
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET || 'your-default-secret'; // Use environment variable for JWT secret
const port = process.env.PORT || 4000;

const corsOptions = {
  origin: 'https://fascinating-truffle-d8d0b4.netlify.app', // Your frontend URL
  credentials: true, // Allow credentials (JWT cookies)
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods
};

const app = express();
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

mongoose.connect('mongodb+srv://arindamsingh209:arindam@cluster1.29d0mug.mongodb.net/?retryWrites=true&w=majority');

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
    res.status(400).json(e);
  }
});

// Login Page
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (!userDoc) {
    return res.status(400).json('wrong credentials');
  }

  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token).json({
        id: userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json('wrong credentials');
  }
});

// User information header
app.get('/profile', (req, res) => {
  const token = req.cookies.token; // Check token directly
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) {
      console.error('JWT verification error:', err); // Log the error
      return res.status(403).json({ message: 'Token is invalid' });
    }
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '').json('ok');
});

// Create Post Page
app.post('/post', async (req, res) => {
  const { title, summary, content, cover } = req.body; // Get cover image URL from request
  const token = req.cookies.token; // Get token from cookies
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      console.error('JWT verification error:', err); // Log the error
      return res.status(403).json({ message: 'Token is invalid' });
    }
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover, // Use the URL directly
      author: info.id,
    });
    res.json(postDoc);
  });
});

// Edit Post
app.put('/post', async (req, res) => {
  const { id, title, summary, content, cover } = req.body; // Get cover image URL from request
  const token = req.cookies.token; // Get token from cookies
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      console.error('JWT verification error:', err); // Log the error
      return res.status(403).json({ message: 'Token is invalid' });
    }
    const postDoc = await Post.findById(id);
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) {
      return res.status(400).json('you are not the author');
    }
    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: cover ? cover : postDoc.cover, // Update with new URL if provided
    });
    res.json(postDoc);
  });
});

// Show the post at home page
app.get('/post', async (req, res) => {
  res.json(
    await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});

// Post Page
app.get('/post/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);

    if (!postDoc) {
      return res.status(404).json({ message: 'Post not found' });
    }

    res.json(postDoc);
  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
