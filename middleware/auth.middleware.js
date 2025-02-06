const jwt = require('jsonwebtoken');
const { Usuario } = require('../models');

// mi token secret
const JWT_SECRET = 'tu_jwt_secret'; 

//verificamos el token y su validez con jtw
const verifyToken = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        
        if (!token) {
            return res.status(403).json({ message: 'No autorizado' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const usuario = await Usuario.findByPk(decoded.id);

        if (!usuario) {
            res.clearCookie('token');
            return res.status(401).json({ message: 'Usuario no encontrado' });
        }

        req.usuario = usuario;
        next();
    } catch (error) {
        res.clearCookie('token');
        return res.status(401).json({ message: 'Sesión inválida' });
    }
};


module.exports = { verifyToken };