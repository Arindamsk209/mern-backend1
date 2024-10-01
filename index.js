const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User'); 
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET || 'your-default-secret';
const port = process.env.PORT || 4000;

// MongoDB connection string
const mongoURI = process.env.MONGO_URI || 'mongodb+srv://username:password@cluster1.mongodb.net/myDatabase?retryWrites=true&w=majority';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

const corsOptions = {
  origin: 'https://fascinating-truffle-d8d0b4.netlify.app',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Utility function for error response
const errorResponse = (res, statusCode, message) => {
  return res.status(statusCode).json({ error: message });
};

// Register Page
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.status(201).json({ id: userDoc._id, username: userDoc.username });
  } catch (e) {
    console.log(e);
    return errorResponse(res, 400, e.message || 'Registration failed');
  }
});

// Login Page
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    if (!userDoc) {
      return errorResponse(res, 400, 'User not found');
    }

    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (passOk) {
      const token = jwt.sign({ username, id: userDoc._id }, secret);
      res.cookie('token', token, { httpOnly: true }).json({
        id: userDoc._id,
        username,
      });
    } else {
      return errorResponse(res, 400, 'Wrong credentials');
    }
  } catch (e) {
    return errorResponse(res, 500, 'Internal server error');
  }
});

// User information header
app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (!token) {
    return errorResponse(res, 401, 'Unauthorized');
  }

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) {
      return errorResponse(res, 401, 'Unauthorized');
    }
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '', { httpOnly: true }).json('ok');
});

// Create Post Page
app.post('/post', async (req, res) => {
  const { title, summary, content, cover } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return errorResponse(res, 401, 'Unauthorized');
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return errorResponse(res, 401, 'Unauthorized');
    }
    
    try {
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover,
        author: info.id,
      });
      res.status(201).json(postDoc); // Return the newly created post
    } catch (e) {
      return errorResponse(res, 400, 'Failed to create post');
    }
  });
});

// Edit Post
app.put('/post', async (req, res) => {
  const { id, title, summary, content, cover } = req.body;
  const { token } = req.cookies;

  if (!token) {
    return errorResponse(res, 401, 'Unauthorized');
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return errorResponse(res, 401, 'Unauthorized');
    }

    try {
      const postDoc = await Post.findById(id);
      if (!postDoc) {
        return errorResponse(res, 404, 'Post not found');
      }

      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) {
        return errorResponse(res, 403, 'You are not the author');
      }

      await postDoc.updateOne({
        title,
        summary,
        content,
        cover: cover || postDoc.cover,
      });
      
      res.json(postDoc); // Return the updated post
    } catch (e) {
      return errorResponse(res, 400, 'Failed to update post');
    }
  });
});

// Show the post at home page
app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(posts);
  } catch (error) {
    console.error('Error fetching posts:', error);
    return errorResponse(res, 500, 'Server error');
  }
});

// Post Page
app.get('/post/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);
    if (!postDoc) {
      return errorResponse(res, 404, 'Post not found');
    }
    res.json(postDoc);
  } catch (error) {
    console.error('Error fetching post:', error);
    return errorResponse(res, 500, 'Server error');
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
