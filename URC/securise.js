// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');

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

const limiter = rateLimit({
  windowMs: 5 * 1000, // 1 min
  max: 5, // max 30 requêtes / min
  message: 'Too many requests, try again later.'
});

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

app.use('/login', limiter); 
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
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100); // 🔒 max 100 éléments

  const start = (page - 1) * limit;
  const end = start + limit;

  const paginated = hugeData.slice(start, end);
  res.json({
    page,
    limit,
    total: hugeData.length,
    data: paginated
  });
});


//app.use('/items', limiter); // Appliqué à cette route
//app.use('/login', limiter); // Appliqué à cette route


app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
