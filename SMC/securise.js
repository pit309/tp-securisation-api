require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Vérification des variables d'environnement requises
const requiredEnvVars = ['JWT_SECRET', 'CORS_ORIGIN', 'NODE_ENV'];
requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
        console.error(`Variable d'environnement manquante: ${varName}`);
        process.exit(1);
    }
});

// Configuration de sécurité avec Helmet
app.use(helmet());

// Configuration CORS sécurisée
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    credentials: true,
    maxAge: 600 // 10 minutes
}));

// Limiter la taille des requêtes JSON
app.use(express.json({ limit: '10kb' }));

// Configuration des logs selon l'environnement
if (process.env.NODE_ENV === 'production') {
    app.use(morgan('combined', {
        skip: (req, res) => res.statusCode < 400,
        stream: require('fs').createWriteStream(
            path.join(__dirname, 'access.log'),
            { flags: 'a' }
        )
    }));
} else {
    app.use(morgan('dev'));
}

// Limiteur de taux global
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes par défaut
    max: parseInt(process.env.RATE_LIMIT) || 100
});
app.use(limiter);

// Limiteur spécifique pour l'authentification
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // 5 tentatives
});

const SALT_ROUNDS = 10;

// Base de données simulée
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

// Middleware de vérification du rôle admin
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Accès non autorisé' });
    }
    next();
};

// Route de debug sécurisée (uniquement en développement)
if (process.env.NODE_ENV === 'development') {
    app.get('/debug', authenticateToken, isAdmin, (req, res) => {
        const safeDebugInfo = {
            environment: process.env.NODE_ENV,
            nodeVersion: process.version,
            userCount: users.length
        };
        res.json(safeDebugInfo);
    });
}

// Route d'authentification sécurisée
app.post('/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = users.find(u => u.username === username);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Identifiants invalides' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Ne renvoie que les informations nécessaires
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de l\'authentification' });
    }
});

// Route API sécurisée
app.get('/api/users', authenticateToken, isAdmin, (req, res) => {
    // Ne renvoie que les informations non sensibles
    const safeUsers = users.map(user => ({
        id: user.id,
        username: user.username,
        role: user.role
    }));
    res.json(safeUsers);
});

// Route de téléchargement sécurisée
app.get('/download/:file', authenticateToken, (req, res) => {
    const file = req.params.file;
    const safePath = path.join(__dirname, 'downloads', file);

    // Vérification du chemin pour éviter la traversée de répertoire
    if (!safePath.startsWith(path.join(__dirname, 'downloads'))) {
        return res.status(403).json({ message: 'Accès non autorisé' });
    }

    res.download(safePath);
});

// Gestionnaire d'erreurs sécurisé
app.use((err, req, res, next) => {
    console.error(err);
    
    // En production, ne pas exposer les détails de l'erreur
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ message: 'Erreur interne du serveur' });
    } else {
        res.status(500).json({
            message: err.message,
            error: err.name
        });
    }
});

// Protection contre les méthodes non supportées
/*
app.all('*', (req, res) => {
    res.status(405).json({ message: 'Méthode non autorisée' });
});
*/

// Démarrage du serveur
const startServer = async () => {
    try {
        users = await initializeUsers();
        const port = process.env.PORT || 3000;
        // N'écoute que sur localhost en développement
        const host = process.env.NODE_ENV === 'production' ? '0.0.0.0' : 'localhost';
        
        app.listen(port, host, () => {
            console.log(`Serveur sécurisé démarré sur ${host}:${port}`);
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        process.exit(1);
    }
};

startServer();
