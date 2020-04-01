require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const checkAuth = require('../middleware/check-auth');
const User = require('../models/User');

// User signup
router.post("/signup", (req, res) => {
	const { name, email, password, password2 } = req.body;
	let errors = [];

	if (!name || !email || !password || !password2) {
		errors.push('Enter required fields');
	}

	// Regex to validate email
	if (email && /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(email) === false) {
		errors.push('Enter a valid email');
	}

	if (password !== password2) {
		errors.push('Passwords must match');
	}

	if (password && password.length < 6) {
		errors.push('Password must be at least 6 characters');
	}

	if (errors.length > 0) {
		return res.status(400).json({ message: errors });
	} else {
		User.findOne({ email }).exec()
			.then(user => {
				if (user) {
					return res.status(409).json({ message: 'Email exists' });
				} else {
					bcrypt.hash(password, 10, (err, hash) => {
						if (err) {
							return res.status(500).json({ error: err });
						}
						const newUser = new User({
							name,
							email,
							password: hash
						});
						newUser.save()
							.then(() => res.status(200).json({ message: 'User created' }))
							.catch(err => res.status(500).json({ error: err }));
					});
				}
			})
			.catch(err => res.status(500).json({ error: err }));
	}
});


// User login
router.post('/login', (req, res) => {
	User.findOne({ email: req.body.email }).exec()
		.then(user => {
			if (user) {
				bcrypt.compare(req.body.password, user.password, (err, result) => {
					if (err) {
						return res.status(401).json({ message: 'Auth failed' });
					}
					if (result) {
						const token = jwt.sign({ email: user.email, userId: user._id }
							, process.env.JWT_KEY,
							{ expiresIn: '24h' });

						return res.status(200).json({ message: 'Auth successful', token });
					}
					return res.status(401).json({ message: 'Auth failed' });
				});
			} else {
				return res.status(401).json({ message: 'Auth failed' });
			}
		})
		.catch(err => res.status(500).json({ error: err }));
});

router.get('/profile', checkAuth, (req, res) => {
	res.status(200).json({ userData: req.userData });
});

module.exports = router;