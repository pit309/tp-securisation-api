const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// Clé secrète pour JWT (en dur pour simplifier)
const SECRET = 'monsecret';

// Données "en dur" : comptes utilisateurs
const accounts = [
  { id: '1', ownerId: 'user1', balance: 1000 },
  { id: '2', ownerId: 'user2', balance: 2500 },
];

// Middleware simple d'authentification JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.sendStatus(401);
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // { userId: 'user1' }
    next();
  });
}

// Route pour générer un token (juste pour test)
app.post('/login', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const token = jwt.sign({ userId }, SECRET);
  res.json({ token });
});

app.get('/accounts/:id', authenticateToken, (req, res) => {
  const account = accounts.find(acc => acc.id === req.params.id);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  // Correction BOLA : vérifier que le userId du token est bien owner du compte
  if (account.ownerId !== req.user.userId) {
    return res.status(403).json({ error: 'Forbidden: you do not own this account' });
  }

  res.json(account);
});


const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
