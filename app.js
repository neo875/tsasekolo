const express = require('express');
const path = require('path');  // Import the 'path' module
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const cors = require('cors');

app.use(cors());

// MongoDB URI and Database name
const uri = 'mongodb://localhost:27017';
const dbName = 'Userauth';

// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
let db;
MongoClient.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    console.log('Connected to MongoDB');
    db = client.db(dbName);
  })
  .catch(err => {
    console.error('Failed to connect to MongoDB:', err);
  });

// POST: Signup route
app.post('/signup', async (req, res) => {
  const { name, username, age, gender, password } = req.body;
  try {
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).send('Username already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection('users').insertOne({
      name,
      username,
      age,
      gender,
      password: hashedPassword
    });

    res.status(201).send('User signed up successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error signing up user');
  }
});

// POST: Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(401).send('Invalid username or password');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send('Invalid username or password');
    }

    const token = jwt.sign({ username: user.username, userId: user._id }, 'your_secret_key', { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

// GET: Get all users (authenticated)
app.get('/users', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
      return res.status(401).send('Unauthorized');
  }

  try {
      const decoded = jwt.verify(token, 'your_secret_key');
      // Only return users if they are logged in correctly
      const users = await db.collection('users').find().toArray();
      res.json(users);
  } catch (err) {
      res.status(500).send('Error fetching users');
  }
});

// DELETE: Delete a user (authenticated, admin or user)
app.delete('/users/:username', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  const { username } = req.params;

  try {
    const decoded = jwt.verify(token, 'your_secret_key');
    // Check if the logged-in user is trying to delete their own account or an admin is trying to delete another user
    const user = await db.collection('users').findOne({ username: decoded.username });

    if (username !== decoded.username) {
      // If the username doesn't match the logged-in user, check if it's an admin (this can be enhanced if needed)
      // For simplicity, we'll just check if it's not the same user.
      return res.status(403).send('You can only delete your own account or an admin can delete users.');
    }

    // Proceed to delete user
    const result = await db.collection('users').deleteOne({ username });

    if (result.deletedCount === 0) {
      return res.status(404).send('User not found');
    }

    res.send('User deleted successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting user');
  }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
