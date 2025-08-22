require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const SALT_ROUNDS = 10;
const PORT = process.env.PORT || 3000;

// Base de données simulée
let users = [];
let products = [
    { id: 1, name: 'iPhone', price: 999, stock: 50 },
    { id: 2, name: 'Samsung Galaxy', price: 899, stock: 30 },
    { id: 3, name: 'iPad', price: 799, stock: 20 }
];
let orders = [];

// Initialisation des utilisateurs
const initializeUsers = async () => {
    const hashedPass1 = await bcrypt.hash('user123', SALT_ROUNDS);
    const hashedPass2 = await bcrypt.hash('admin123', SALT_ROUNDS);
    return [
        { id: 1, username: 'user', password: hashedPass1, role: 'user', credit: 1000 },
        { id: 2, username: 'admin', password: hashedPass2, role: 'admin', credit: 9999 }
    ];
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
app.get('/products', (req, res) => {
    res.json(products);
});

// Vulnérabilité 1: Pas de vérification du stock en temps réel
// Vulnérabilité 2: Pas de limitation de commandes multiples
// Vulnérabilité 3: Pas de vérification du crédit disponible
app.post('/order', (req, res) => {
    const { productId, quantity } = req.body;
    const product = products.find(p => p.id === productId);

    if (!product) {
        return res.status(404).json({ message: 'Produit non trouvé' });
    }

    // Création de la commande sans vérifications
    const order = {
        id: orders.length + 1,
        productId,
        quantity,
        totalPrice: product.price * quantity,
        status: 'confirmed'
    };

    // Mise à jour du stock (sans vérification atomique)
    product.stock -= quantity;
    
    orders.push(order);
    res.json(order);
});

// Vulnérabilité 4: État de commande modifiable sans vérification
app.put('/order/:id/status', (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const order = orders.find(o => o.id === parseInt(id));

    if (!order) {
        return res.status(404).json({ message: 'Commande non trouvée' });
    }

    // Modification de l'état sans vérification des transitions valides
    order.status = status;
    res.json(order);
});

// Vulnérabilité 5: Annulation de commande sans vérification de délai
app.post('/order/:id/cancel', (req, res) => {
    const { id } = req.params;
    const order = orders.find(o => o.id === parseInt(id));

    if (!order) {
        return res.status(404).json({ message: 'Commande non trouvée' });
    }

    // Annulation sans vérification du délai ou de l'état actuel
    order.status = 'cancelled';
    
    // Remise en stock sans vérification
    const product = products.find(p => p.id === order.productId);
    product.stock += order.quantity;

    res.json(order);
});

// Démarrage du serveur
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
