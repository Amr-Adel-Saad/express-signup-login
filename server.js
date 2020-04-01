require('dotenv').config({path: __dirname + '/.env'});

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose').set('useCreateIndex', true);

const app = express();

// CORS middleware
app.use(cors());

// Bodyparser middleware
app.use(express.json());

// Routes
app.use('/user', require('./api/routes/user'));

// DB config
const db = process.env.MONGO_URI;

// Connect to database
mongoose.connect(db, { useNewUrlParser: true , useUnifiedTopology: true})
    .then(() => console.log('MongoDB Connected...'))
    .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => { console.log(`Server started on port ${PORT}`) });
