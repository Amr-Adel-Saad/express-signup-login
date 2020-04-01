require('dotenv').config({path: __dirname + '/.env'});
const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
    try {
        const bearer = req.headers.authorization;
        const token = bearer.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_KEY);
        req.userData = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Auth failed' });
    }
}