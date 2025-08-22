require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
// Création des mots de passe hachés de manière asynchrone
const initializeUsers = async () => {
    const hashedUserPass = await bcrypt.hash('user123', SALT_ROUNDS);
    const hashedAdminPass = await bcrypt.hash('admin123', SALT_ROUNDS);
    
    return [
        { id: 1, username: 'user1', password: hashedUserPass, role: 'user' },
        { id: 3, username: 'user2', password: hashedUserPass, role: 'user' },
        { id: 2, username: 'admin', password: hashedAdminPass, role: 'admin' }
    ];
};

let users = [];

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
    const user = users.find(u => u.id === req.user.userId);
    if (user.role !== 'admin') {
        return res.status(403).json({ message: 'Accès non autorisé. Rôle admin requis.' });
    }
    next();
};

// Middleware de vérification de propriété de la ressource
const isResourceOwner = (req, res, next) => {
    const requestedUserId = parseInt(req.params.id);
    if (req.user.userId !== requestedUserId) {
        const user = users.find(u => u.id === req.user.userId);
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Accès non autorisé à cette ressource' });
        }
    }
    next();
};

// Route de connexion
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
    
    if (!user) {
        return res.status(401).json({ message: 'Identifiants invalides' });
    }

    const token = jwt.sign(
        { userId: user.id, username: user.username, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.json({ token });
});

// Route pour obtenir les informations d'un utilisateur (sécurisée)
app.get('/user/:id', authenticateToken, isResourceOwner, (req, res) => {
    const user = users.find(u => u.id === parseInt(req.params.id));
    if (!user) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    res.json(user);
});

// Route administrative (sécurisée)
app.delete('/user/:id', authenticateToken, isAdmin, (req, res) => {
    const userIndex = users.findIndex(u => u.id === parseInt(req.params.id));
    if (userIndex === -1) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    
    users.splice(userIndex, 1);
    res.json({ message: 'Utilisateur supprimé avec succès' });
});

// Initialisation des utilisateurs et démarrage du serveur
const startServer = async () => {
    try {
        users = await initializeUsers();
        app.listen(PORT, () => {
            console.log(`Serveur démarré sur le port ${PORT}`);
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation des utilisateurs:', error);
        process.exit(1);
    }
};

startServer();
