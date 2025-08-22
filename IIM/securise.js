require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
app.use(express.json());

const SALT_ROUNDS = 10;
const API_VERSION = '2.0.0';
const DEPRECATED_VERSION = '1.0.0';

// Configuration Swagger
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API E-commerce',
            version: API_VERSION,
            description: 'Documentation complète de l\'API E-commerce avec gestion des versions',
            contact: {
                name: 'Équipe API',
                email: 'api@example.com'
            },
            license: {
                name: 'MIT',
                url: 'https://opensource.org/licenses/MIT'
            }
        },
        servers: [
            {
                url: `http://localhost:${process.env.PORT}`,
                description: 'Serveur de développement'
            }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        },
        tags: [
            {
                name: 'Authentication',
                description: 'Endpoints d\'authentification'
            },
            {
                name: 'Products',
                description: 'Gestion des produits'
            }
        ]
    },
    apis: ['./securise.js']
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
if (process.env.API_DOCS_ENABLED === 'true') {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));
}

// Base de données simulée
let users = [];
let products = [];

// Middleware de vérification de version
const checkAPIVersion = (req, res, next) => {
    const requestedVersion = req.headers['api-version'];
    if (!requestedVersion) {
        return res.status(400).json({
            error: 'Version d\'API manquante',
            message: 'Utilisez l\'en-tête api-version pour spécifier la version'
        });
    }
    if (requestedVersion === DEPRECATED_VERSION) {
        res.set('Deprecation', 'true');
        res.set('Sunset', new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toUTCString());
        res.set('Link', '</api/v2>; rel="successor-version"');
    }
    next();
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

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - id
 *         - username
 *         - role
 *       properties:
 *         id:
 *           type: integer
 *           description: ID unique de l'utilisateur
 *         username:
 *           type: string
 *           description: Nom d'utilisateur
 *         role:
 *           type: string
 *           enum: [user, admin]
 *           description: Rôle de l'utilisateur
 *     LoginRequest:
 *       type: object
 *       required:
 *         - username
 *         - password
 *       properties:
 *         username:
 *           type: string
 *           description: Nom d'utilisateur
 *           example: user1
 *         password:
 *           type: string
 *           description: Mot de passe
 *           example: pass1
 *     LoginResponse:
 *       type: object
 *       properties:
 *         token:
 *           type: string
 *           description: JWT pour l'authentification
 *         user:
 *           $ref: '#/components/schemas/User'
 *
 * /api/v2/auth/login:
 *   post:
 *     tags: [Authentication]
 *     summary: Authentification utilisateur
 *     description: |
 *       Endpoint d'authentification retournant un JWT.
 *       Version actuelle de l'API d'authentification avec support des rôles.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Authentification réussie
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       401:
 *         description: Identifiants invalides
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Identifiants invalides
 *       429:
 *         description: Trop de tentatives de connexion
 *     headers:
 *       api-version:
 *         schema:
 *           type: string
 *           example: "2.0.0"
 *         required: true
 *         description: Version de l'API à utiliser
 */
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

    res.json({
        token,
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        }
    });
});

/**
 * @swagger
 * components:
 *   schemas:
 *     Product:
 *       type: object
 *       required:
 *         - id
 *         - name
 *         - price
 *       properties:
 *         id:
 *           type: integer
 *           description: ID unique du produit
 *           example: 1
 *         name:
 *           type: string
 *           description: Nom du produit
 *           example: Produit A
 *         price:
 *           type: number
 *           description: Prix du produit
 *           example: 100
 *
 * /api/v2/products:
 *   get:
 *     tags: [Products]
 *     summary: Liste des produits
 *     description: |
 *       Récupère la liste des produits disponibles.
 *       Nécessite une authentification et une version d'API valide.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: api-version
 *         schema:
 *           type: string
 *         required: true
 *         description: Version de l'API à utiliser
 *         example: "2.0.0"
 *     responses:
 *       200:
 *         description: Liste des produits récupérée avec succès
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Product'
 *       401:
 *         description: Non authentifié
 *       403:
 *         description: Non autorisé
 *       400:
 *         description: Version d'API manquante
 */
app.get('/api/v2/products', authenticateToken, (req, res) => {
    const safeProducts = products.map(p => ({
        id: p.id,
        name: p.name,
        price: p.price
    }));
    res.json(safeProducts);
});
/*
// Message d'avertissement pour les anciennes versions
app.use('/api/v1/*', (req, res) => {
    res.status(410).json({
        error: 'Version obsolète',
        message: 'Cette version de l\'API est obsolète. Veuillez utiliser la version 2.0',
        documentation: '/api-docs'
    });
});

// Gestionnaire pour les routes inconnues
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Route non trouvée',
        documentation: '/api-docs',
        availableVersions: [API_VERSION]
    });
});
*/
const startServer = async () => {
    try {
        await initializeData();
        const port = process.env.PORT || 3000;
        app.listen(port, () => {
            console.log(`Serveur sécurisé démarré sur le port ${port}`);
            if (process.env.API_DOCS_ENABLED === 'true') {
                console.log(`Documentation Swagger disponible sur http://localhost:${port}/api-docs`);
            }
        });
    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        process.exit(1);
    }
};

startServer();
