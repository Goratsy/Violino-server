import * as dotenv from 'dotenv';
dotenv.config()
import express from 'express';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import cors from 'cors';
import pkg from 'pg';
const { Pool } = pkg;
import bcrypt from 'bcrypt'; // in the future: download another library

const app = express();
const PORT = process.env.PORT || 4000;

// CORS

const corsOptions = {
    origin: 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Middleware
app.use(bodyParser.json());

// PostgreSQL connection
const POSTGRE_SQL_POOL = new Pool({
    user: 'gor',
    host: 'localhost',
    database: 'postgres',
    password: process.env.PASSWORD_POSTGRE_SQL,
    port: 5432,
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);
    
    jwt.verify(authHeader, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Routes

// UserPhones: Retrieve all user phones
app.get('/user_phones', authenticateToken, async (req, res) => {
    try {
        const result = await POSTGRE_SQL_POOL.query('SELECT * FROM user_phones');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// UserPhones: Create a new user phone
app.post('/user_phones', async (req, res) => {
    const { name, phone, date_of_send, information_about_user } = req.body;
    try {
        const existingPhone = await POSTGRE_SQL_POOL.query('SELECT * FROM user_phones WHERE phone = $1', [phone]);
        if (existingPhone.rows.length > 0) {
            return res.status(400).json({ error: 'Phone number already exists' });
        }

        await POSTGRE_SQL_POOL.query(
            'INSERT INTO user_phones (name, phone, date_of_send, information_about_user) VALUES ($1, $2, $3, $4)',
            [name, phone, date_of_send, information_about_user]
        );
        res.status(201).json({ message: 'User phone created successfully' });
    } catch (err) {
        res.status(500).json({ error: `Internal Server Error. ${err}` });
    }
});

// UserPhones: Update multiple user phones
app.put('/user_phones', authenticateToken, async (req, res) => {
    const updates = req.body;
    try {
        for (const update of updates) {
            const { id, name, phone, date_of_send, information_about_user } = update;
            await POSTGRE_SQL_POOL.query(
                'UPDATE user_phones SET name = $1, phone = $2, date_of_send = $3, information_about_user = $4 WHERE id = $5',
                [name, phone, date_of_send, information_about_user, id]
            );
        }
        res.status(200).json({ message: 'User phones updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// UserPhones: Delete a specific user phone by ID
app.delete('/user_phones/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await POSTGRE_SQL_POOL.query('DELETE FROM user_phones WHERE id = $1', [id]);
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Managers: Log a manager login
app.post('/managers/logins', async (req, res) => {
    const { login, password, date_of_login, device, ip_address } = req.body;
    try {
        const manager = await POSTGRE_SQL_POOL.query('SELECT * FROM manager WHERE login = $1', [login]);
        if (manager.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid login credentials' });
        }

        const validPassword = await bcrypt.compare(password, manager.rows[0].password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid login credentials' });
        }
        
        const token = jwt.sign({ id: manager.rows[0].manager_id }, JWT_SECRET, { expiresIn: '1h' });

        await POSTGRE_SQL_POOL.query(
            'INSERT INTO login_history (manager_id, date_of_login, device, ip_address, active_tokens) VALUES ($1, $2, $3, $4, $5)',
            [manager.rows[0].manager_id, date_of_login, device, ip_address, token]
        );
 
        res.status(201).json({ token });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Protected example route
app.get('/managers', authenticateToken, async (req, res) => {
    try {
        const result = await POSTGRE_SQL_POOL.query('SELECT * FROM manager');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/test', async (req, res) => {
    res.json('test connection');
});


app.get('/test_db', async (req, res) => {
    try {
        let db_data = await POSTGRE_SQL_POOL.query('SELECT * FROM user_phones');
        res.json(db_data['rows']);
    } catch (error) {
        res.json('error db');
    }
});

