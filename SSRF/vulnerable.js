require('dotenv').config();
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Initialisation des utilisateurs avec mots de passe hachés
let users = [];
const initializeUsers = async () => {
    const hashedPass1 = await bcrypt.hash('user123', SALT_ROUNDS);
    const hashedPass2 = await bcrypt.hash('admin123', SALT_ROUNDS);
    return [
        { id: 1, username: 'user', password: hashedPass1, role: 'user' },
        { id: 2, username: 'admin', password: hashedPass2, role: 'admin' }
    ];
};

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token manquant' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token invalide' });
        }
        req.user = user;
        next();
    });
};

// Route d'authentification
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Identifiants invalides' });
    }

    const token = jwt.sign(
        { userId: user.id, username: user.username, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.json({ token });
});

// VULNÉRABLE : accepte n'importe quelle URL côté serveur
app.post('/fetch-url', authenticateToken, async (req, res) => {
  const { url } = req.body;

  try {
    const response = await axios.get(url);
    res.send(response.data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch URL' });
  }
});

// Vulnérabilité 1: Endpoint de récupération d'image sans validation d'URL
app.post('/fetch-image', authenticateToken, async (req, res) => {
    const { imageUrl } = req.body;

    try {
        const response = await axios.get(imageUrl, { responseType: 'arraybuffer' });
        res.type(response.headers['content-type']);
        res.send(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération de l\'image' });
    }
});

// Vulnérabilité 2: Endpoint de vérification de site sans validation d'URL
app.post('/check-website', async (req, res) => {
    const { url } = req.body;

    try {
        const response = await axios.get(url);
        res.json({ status: response.status, working: true });
    } catch (error) {
        res.json({ status: error.response?.status, working: false });
    }
});

// Vulnérabilité 3: Proxy de service interne sans validation
app.post('/proxy-service', async (req, res) => {
    const { service, path } = req.body;
    const url = `${service}${path}`;

    try {
        const response = await axios.get(url);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de l\'accès au service' });
    }
});

// Vulnérabilité 4: Endpoint de récupération de fichier par chemin sans validation
app.get('/get-file', async (req, res) => {
    const { path } = req.query;

    try {
        const response = await axios.get(path);
        res.send(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération du fichier' });
    }
});

// Serveur interne simulé (vulnérable aux attaques SSRF)
const internalRoutes = {
    '/internal-api/user-data': {
        data: 'Données sensibles des utilisateurs',
        restricted: true
    },
    '/internal-api/system-info': {
        data: 'Informations système sensibles',
        restricted: true
    },
    '/internal-api/metrics': {
        data: 'Métriques système',
        restricted: true
    }
};

// Route interne simulée (accessible uniquement en local normalement)
app.get('/internal-api/', (req, res) => {
    const path = req.path;
    const data = internalRoutes[path];

    if (data) {
        res.json(data);
    } else {
        res.status(404).json({ message: 'Route interne non trouvée' });
    }
});

// Démarrage du serveur avec initialisation des utilisateurs
const startServer = async () => {
    try {
        users = await initializeUsers();
        app.listen(PORT, () => {
            console.log(`Serveur vulnérable démarré sur le port ${PORT}`);
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        process.exit(1);
    }
};

startServer();
