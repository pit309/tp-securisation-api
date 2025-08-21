require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = process.env.JWT_SECRET;

if (!SECRET_KEY) {
  console.error("❌ JWT_SECRET n'est pas défini dans .env");
  process.exit(1);
}

const users = [
  {
    id: 1,
    username: 'admin',
    passwordHash: bcrypt.hashSync('admin123', 10),
    role: 'admin'
  },
  {
    id: 2,
    username: 'user',
    passwordHash: bcrypt.hashSync('user123', 10),
    role: 'user'
  }
];

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).send('Invalid credentials');

  const isValid = bcrypt.compareSync(password, user.passwordHash);
  if (!isValid) return res.status(401).send('Invalid credentials');

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: '1h' }
  );
  res.json({ token });
});

app.get('/admin', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send('No token');

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    if (payload.role !== 'admin') return res.status(403).send('Access denied');
    res.send('Welcome, admin!');
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});

app.listen(3000, () => {
  console.log('Secure API running on http://localhost:3000');
});
