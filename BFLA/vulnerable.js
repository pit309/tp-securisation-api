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
        { id: 1, username: 'user', password: hashedUserPass, role: 'user' },
        { id: 2, username: 'admin', password: hashedAdminPass, role: 'admin' }
    ];
};

let users = [];

// Route de connexion
app.post('/login', async (req, res) => {
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

// Route pour obtenir les informations d'un utilisateur (vulnérable)
app.get('/user/:id', (req, res) => {
    // Pas de vérification du rôle ni des permissions
    const user = users.find(u => u.id === parseInt(req.params.id));
    if (!user) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    res.json(user);
});

// Route administrative (vulnérable)
app.delete('/user/:id', (req, res) => {
    // Pas de vérification du rôle ni des permissions
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
