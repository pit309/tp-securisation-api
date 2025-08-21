const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = 'secret123'; // ❌ Clé faible

const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'user123', role: 'user' }
];

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).send('Invalid credentials');

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY);
  res.json({ token });
});

app.get('/admin', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send('No token provided');

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, SECRET_KEY); // ✅ Obligatoire

    if (payload.role !== 'admin') {
      return res.status(403).send('Access denied');
    }

    res.send('Welcome, admin!');
  } catch (err) {
    return res.status(401).send('Invalid token');
  }
});


app.listen(3000, () => {
  console.log('Vulnerable API running on http://localhost:3000');
});
