require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');

const app = express();

// Configurations vulnérables
app.use(express.json());
app.use(cors()); // CORS autorisé pour tous les domaines
app.use(morgan('dev')); // Logs détaillés en production

// Information de débogage en production
const debug = true;

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

// En-têtes par défaut non sécurisés
app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Express'); // Divulgue des informations sur la technologie
    next();
});

// Route pour afficher les informations de débogage (vulnérable)
app.get('/debug', (req, res) => {
    if (debug) {
        const debugInfo = {
            environment: process.env.NODE_ENV,
            databaseUrl: process.env.DATABASE_URL,
            jwtSecret: process.env.JWT_SECRET,
            apiKeys: process.env.API_KEY,
            users: users, // Expose les hashs des mots de passe
            nodeVersion: process.version,
            dependencies: process.dependencies,
            envVars: process.env
        };
        res.json(debugInfo);
    } else {
        res.status(404).send('Not found');
    }
});

// Route d'authentification sans limite de tentatives
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Identifiants invalides' });
    }

    const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET || 'default_secret', // Secret par défaut si non configuré
        { expiresIn: '24h' } // Expiration longue
    );

    res.json({ token, user }); // Renvoie les informations utilisateur complètes
});

// Route API non sécurisée
app.get('/api/users', (req, res) => {
    res.json(users); // Expose toutes les données utilisateur
});

// Route de téléchargement de fichier non sécurisée
app.get('/download/:file', (req, res) => {
    const file = req.params.file;
    res.download(file); // Permet l'accès à n'importe quel fichier
});

// Route d'exécution de commande non sécurisée
app.post('/execute', (req, res) => {
    const { command } = req.body;
    require('child_process').exec(command, (error, stdout, stderr) => {
        res.json({ output: stdout, error: stderr });
    });
});

// Gestionnaire d'erreurs qui expose les détails
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        message: err.message,
        stack: err.stack,
        details: err
    });
});

// Démarrage du serveur
const startServer = async () => {
    try {
        users = await initializeUsers();
        const port = process.env.PORT || 3000;
        app.listen(port, '0.0.0.0', () => { // Écoute sur toutes les interfaces
            console.log(`Serveur vulnérable démarré sur le port ${port}`);
            if (debug) {
                console.log('Variables d\'environnement:', process.env);
                console.log('Utilisateurs:', users);
            }
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        process.exit(1);
    }
};

startServer();
