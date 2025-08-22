require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT) || 100;

// Base de données simulée
let users = [];
let products = [
    { id: 1, name: 'iPhone', price: 999, stock: 50 },
    { id: 2, name: 'Samsung Galaxy', price: 899, stock: 30 },
    { id: 3, name: 'iPad', price: 799, stock: 20 }
];
let orders = [];
let rateLimiter = new Map(); // Pour le contrôle du taux de requêtes

// Initialisation des utilisateurs
const initializeUsers = async () => {
    const hashedPass1 = await bcrypt.hash('user123', SALT_ROUNDS);
    const hashedPass2 = await bcrypt.hash('admin123', SALT_ROUNDS);
    return [
        { id: 1, username: 'user', password: hashedPass1, role: 'user', credit: 1000 },
        { id: 2, username: 'admin', password: hashedPass2, role: 'admin', credit: 9999 }
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

// Middleware de limitation de taux
const rateLimitMiddleware = (req, res, next) => {
    const userId = req.user.userId;
    const now = Date.now();
    const userRequests = rateLimiter.get(userId) || [];
    
    // Nettoyer les anciennes requêtes (plus de 1 minute)
    const recentRequests = userRequests.filter(time => now - time < 60000);
    
    if (recentRequests.length >= RATE_LIMIT) {
        return res.status(429).json({ message: 'Trop de requêtes. Veuillez réessayer plus tard.' });
    }
    
    recentRequests.push(now);
    rateLimiter.set(userId, recentRequests);
    next();
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

// Liste des produits
app.get('/products', authenticateToken, (req, res) => {
    res.json(products);
});

// Liste des achats
app.get('/orders', authenticateToken, (req, res) => {
    res.json(orders);
});

// Fonction utilitaire pour vérifier la disponibilité du stock
const checkAndReserveStock = (productId, quantity) => {
    const product = products.find(p => p.id === productId);
    if (!product || product.stock < quantity) {
        return false;
    }
    product.stock -= quantity;
    return true;
};

// Fonction utilitaire pour vérifier le crédit utilisateur
const checkAndReserveCredit = (userId, amount) => {
    const user = users.find(u => u.id === userId);
    if (!user || user.credit < amount) {
        return false;
    }
    user.credit -= amount;
    return true;
};

// Création de commande sécurisée
app.post('/order', authenticateToken, rateLimitMiddleware, async (req, res) => {
    const { productId, quantity } = req.body;
    const userId = req.user.userId;

    // Vérifications de base
    if (quantity <= 0 || quantity > 10) {
        return res.status(400).json({ message: 'Quantité invalide' });
    }

    const product = products.find(p => p.id === productId);
    if (!product) {
        return res.status(404).json({ message: 'Produit non trouvé' });
    }

    const totalPrice = product.price * quantity;

    // Vérification synchronisée du stock et du crédit
    const stockAvailable = checkAndReserveStock(productId, quantity);
    if (!stockAvailable) {
        return res.status(400).json({ message: 'Stock insuffisant' });
    }

    const creditAvailable = checkAndReserveCredit(userId, totalPrice);
    if (!creditAvailable) {
        // Rembourser le stock si le crédit est insuffisant
        product.stock += quantity;
        return res.status(400).json({ message: 'Crédit insuffisant' });
    }

    const order = {
        id: orders.length + 1,
        userId,
        productId,
        quantity,
        totalPrice,
        status: 'pending',
        createdAt: new Date(),
        lastModified: new Date()
    };

    orders.push(order);
    res.json(order);
});

// États de commande valides et transitions autorisées
const validOrderTransitions = {
    'pending': ['confirmed', 'cancelled'],
    'confirmed': ['shipped', 'cancelled'],
    'shipped': ['delivered'],
    'delivered': [],
    'cancelled': []
};

// Mise à jour sécurisée de l'état de la commande
app.put('/order/:id/status', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const userId = req.user.userId;
    const order = orders.find(o => o.id === parseInt(id));

    if (!order) {
        return res.status(404).json({ message: 'Commande non trouvée' });
    }

    // Vérification de la propriété ou du rôle admin
    if (order.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Action non autorisée' });
    }

    // Vérification de la transition d'état valide
    const validTransitions = validOrderTransitions[order.status];
    if (!validTransitions || !validTransitions.includes(status)) {
        return res.status(400).json({ 
            message: 'Transition d\'état invalide',
            currentStatus: order.status,
            validTransitions
        });
    }

    order.status = status;
    order.lastModified = new Date();
    res.json(order);
});

// Annulation sécurisée de commande
app.post('/order/:id/cancel', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;
    const order = orders.find(o => o.id === parseInt(id));

    if (!order) {
        return res.status(404).json({ message: 'Commande non trouvée' });
    }

    // Vérification de la propriété ou du rôle admin
    if (order.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Action non autorisée' });
    }

    // Vérification du délai d'annulation (30 minutes)
    const timeSinceOrder = Date.now() - new Date(order.createdAt).getTime();
    if (timeSinceOrder > 30 * 60 * 1000 && req.user.role !== 'admin') {
        return res.status(400).json({ 
            message: 'Délai d\'annulation dépassé (30 minutes)',
            orderAge: Math.round(timeSinceOrder / 1000 / 60) + ' minutes'
        });
    }

    // Vérification de l'état actuel
    if (!validOrderTransitions[order.status].includes('cancelled')) {
        return res.status(400).json({ 
            message: 'Annulation impossible dans l\'état actuel',
            currentStatus: order.status
        });
    }

    // Mise à jour synchronisée
    const product = products.find(p => p.id === order.productId);
    const user = users.find(u => u.id === userId);

    // Remboursement du stock et du crédit
    product.stock += order.quantity;
    user.credit += order.totalPrice;

    order.status = 'cancelled';
    order.lastModified = new Date();
    
    res.json(order);
});

// Démarrage du serveur
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
