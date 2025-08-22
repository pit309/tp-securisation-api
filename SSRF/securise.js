require('dotenv').config();
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const isUrl = require('is-url');
const dns = require('dns').promises;
const { URL } = require('url');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Liste blanche des domaines autorisés
const WHITELIST_DOMAINS = [
    'api.example.com',
    'cdn.example.com',
    'images.example.com'
];

// Liste blanche des endpoints internes autorisés
const WHITELIST_INTERNAL_PATHS = [
    '/internal-api/metrics',
    '/internal-api/public-info'
];

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

// Middleware de vérification d'URL
const validateUrl = (req, res, next) => {
    const url = req.body.url || req.body.imageUrl || req.query.path || `${req.body.service}${req.body.path}`;
    
    if (!url || !isUrl(url)) {
        return res.status(400).json({ message: 'URL invalide' });
    }

    try {
        const parsedUrl = new URL(url);
        
        // Vérification des adresses IP privées
        if (dns.lookup(parsedUrl.hostname)) {
            return res.status(403).json({ message: 'Les adresses IP privées ne sont pas autorisées' });
        }

        // Vérification de la liste blanche des domaines
        if (!WHITELIST_DOMAINS.includes(parsedUrl.hostname)) {
            return res.status(403).json({ message: 'Domaine non autorisé' });
        }

        // Vérification des schémas autorisés
        if (!['http', 'https'].includes(parsedUrl.protocol.slice(0, -1))) {
            return res.status(403).json({ message: 'Protocole non autorisé' });
        }

        req.validatedUrl = url;
        next();
    } catch (error) {
        res.status(400).json({ message: 'URL malformée' });
    }
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

// Endpoint sécurisé de récupération d'image
app.post('/fetch-image', authenticateToken, validateUrl, async (req, res) => {
    try {
        const response = await axios.get(req.validatedUrl, {
            responseType: 'arraybuffer',
            timeout: 5000,
            maxContentLength: 10 * 1024 * 1024 // 10MB max
        });

        // Vérification du type de contenu
        const contentType = response.headers['content-type'];
        if (!contentType.startsWith('image/')) {
            return res.status(400).json({ message: 'Le contenu n\'est pas une image' });
        }

        res.type(contentType);
        res.send(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération de l\'image' });
    }
});

// Endpoint sécurisé de vérification de site
app.post('/check-website', authenticateToken, validateUrl, async (req, res) => {
    try {
        const response = await axios.get(req.validatedUrl, {
            timeout: 5000,
            maxRedirects: 3
        });
        res.json({ status: response.status, working: true });
    } catch (error) {
        res.json({ status: error.response?.status, working: false });
    }
});

// Middleware de vérification des appels internes
const validateInternalCall = (req, res, next) => {
    const { path } = req.body;

    if (!path || !WHITELIST_INTERNAL_PATHS.includes(path)) {
        return res.status(403).json({ message: 'Chemin interne non autorisé' });
    }

    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Accès restreint aux administrateurs' });
    }

    next();
};

// Proxy de service interne sécurisé
app.post('/proxy-service', authenticateToken, validateInternalCall, async (req, res) => {
    const { path } = req.body;
    const url = `${process.env.INTERNAL_SERVICE}${path}`;

    try {
        const response = await axios.get(url, {
            headers: {
                'X-API-Key': process.env.INTERNAL_API_KEY
            },
            timeout: 5000
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de l\'accès au service interne' });
    }
});

// Endpoint sécurisé de récupération de fichier
app.get('/get-file', authenticateToken, validateUrl, async (req, res) => {
    try {
        const response = await axios.get(req.validatedUrl, {
            timeout: 5000,
            maxContentLength: 50 * 1024 * 1024 // 50MB max
        });

        // Vérification du type de contenu
        const contentType = response.headers['content-type'];
        const allowedTypes = ['text/plain', 'application/json', 'application/xml'];
        
        if (!allowedTypes.includes(contentType)) {
            return res.status(400).json({ message: 'Type de fichier non autorisé' });
        }

        res.type(contentType);
        res.send(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération du fichier' });
    }
});

// Serveur interne simulé (sécurisé)
const internalRoutes = {
    '/internal-api/metrics': {
        data: 'Métriques système publiques',
        restricted: false
    },
    '/internal-api/public-info': {
        data: 'Informations publiques',
        restricted: false
    },
    '/internal-api/user-data': {
        data: 'Données sensibles des utilisateurs',
        restricted: true
    },
    '/internal-api/system-info': {
        data: 'Informations système sensibles',
        restricted: true
    }
};

// Route interne simulée (sécurisée)
app.get('/internal-api/', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.env.INTERNAL_API_KEY) {
        return res.status(401).json({ message: 'Clé API non valide' });
    }

    const path = req.path;
    const data = internalRoutes[path];

    if (!data) {
        return res.status(404).json({ message: 'Route interne non trouvée' });
    }

    if (data.restricted) {
        return res.status(403).json({ message: 'Accès restreint' });
    }

    res.json(data);
});

// Démarrage du serveur avec initialisation des utilisateurs
const startServer = async () => {
    try {
        users = await initializeUsers();
        app.listen(PORT, () => {
            console.log(`Serveur sécurisé démarré sur le port ${PORT}`);
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        process.exit(1);
    }
};

startServer();
