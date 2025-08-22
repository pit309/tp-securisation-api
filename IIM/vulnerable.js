require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SALT_ROUNDS = 10;

// Base de données simulée
let users = [];
let products = [];

const initializeData = async () => {
    // Initialisation des utilisateurs
    const hashedPass1 = await bcrypt.hash('user123', SALT_ROUNDS);
    const hashedPass2 = await bcrypt.hash('admin123', SALT_ROUNDS);
    users = [
        { id: 1, username: 'user', password: hashedPass1, role: 'user' },
        { id: 2, username: 'admin', password: hashedPass2, role: 'admin' }
    ];

    // Initialisation des produits
    products = [
        { id: 1, name: 'Produit A', price: 100 },
        { id: 2, name: 'Produit B', price: 200 }
    ];
};

// Version 1 de l'API (obsolète mais toujours active)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Identifiants invalides' });
    }

    const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.json({ token });
});

// Version 2 de l'API (actuelle mais non documentée)
app.post('/api/v2/auth/login', async (req, res) => {
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

    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// Endpoint test (non documenté et potentiellement dangereux)
app.get('/api/test/users', (req, res) => {
    res.json(users);
});

// Version 1 des produits (avec des bugs connus)
app.get('/api/products', (req, res) => {
    // Bug connu : renvoie tous les détails, y compris les informations internes
    res.json(products);
});

// Version 2 des produits (nouvelle implémentation)
app.get('/api/v2/products', (req, res) => {
    const safeProducts = products.map(p => ({
        id: p.id,
        name: p.name,
        price: p.price
    }));
    res.json(safeProducts);
});

// Endpoint de développement (accidentellement laissé en production)
app.post('/api/dev/reset', (req, res) => {
    users = [];
    products = [];
    res.json({ message: 'Données réinitialisées' });
});

// Endpoint de debug (non supprimé après le développement)
app.get('/api/debug/config', (req, res) => {
    res.json({
        env: process.env,
        nodeVersion: process.version,
        dependencies: process.dependencies
    });
});

// Version bêta non sécurisée (accessible publiquement)
app.post('/api/beta/products', (req, res) => {
    const product = req.body;
    products.push({ ...product, id: products.length + 1 });
    res.json(product);
});

// Ancien endpoint de paiement (devrait être désactivé)
app.post('/api/v1/payment', (req, res) => {
    // Logique de paiement obsolète et non sécurisée
    res.json({ status: 'success' });
});

const startServer = async () => {
    try {
        await initializeData();
        const port = process.env.PORT || 3000;
        app.listen(port, () => {
            console.log(`Serveur vulnérable démarré sur le port ${port}`);
            console.log('ATTENTION: Plusieurs versions d\'API et endpoints de test sont exposés');
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        process.exit(1);
    }
};

startServer();
