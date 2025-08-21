// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const SECRET = process.env.JWT_SECRET;

// Simule une base de données en mémoire
const users = [
  {
    username: 'admin',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin'
  },
  {
    username: 'user',
    password: bcrypt.hashSync('user123', 10),
    role: 'user'
  }
];

// 🔐 Middleware JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ✅ Connexion : retourne un token
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username: user.username, role: user.role }, SECRET);
  res.json({ token });
});

const hugeData = Array.from({ length: 100_000 }, (_, i) => ({ id: i + 1, name: `Item-${i + 1}` }));

app.get('/items', authenticateToken, (req, res) => {
  res.json(hugeData); // ❌ renvoie tout d’un coup : CPU/RAM/bande passante
});

app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
