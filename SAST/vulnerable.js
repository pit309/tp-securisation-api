// app.js

const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// db.js
const users = [
  { id: 1, username: 'admin', password: 'admin123' },
  { id: 2, username: 'user', password: 'user123' },
];

// 🚨 Vulnérabilité : Authentification naïve
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Vulnérabilité : Pas de hash, comparaison en clair
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (user) {
    res.json({ message: 'Login successful', user });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// 🚨 Vulnérabilité : pas d’échappement
app.get('/search', (req, res) => {
  const { q } = req.query;
  const results = users.filter((u) => u.username.includes(q)); // injection possible si q contient des caractères spéciaux
  res.json(results);
});

app.listen(3000, () => console.log('API running on http://localhost:3000'));
