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
    origin: 'http://localhost:5173, http://81.177.220.20:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Middleware
app.use(bodyParser.json());

// PostgreSQL connection
const POSTGRE_SQL_POOL = new Pool({
    user: process.env.DB_USER_NAME, // gor
    host: process.env.DB_HOST_URL, // localhost
    database:  process.env.DB_NAME, // postgres
    password: process.env.PASSWORD_POSTGRE_SQL_PROD,
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

app.get('/authentification_manager', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Authentification successful' });
})

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
            const { user_phone_id, name, phone, date_of_send, information_about_user } = update;
            await POSTGRE_SQL_POOL.query(
                'UPDATE user_phones SET name = $1, phone = $2, date_of_send = $3, information_about_user = $4 WHERE user_phone_id = $5',
                [name, phone, date_of_send, information_about_user, user_phone_id]
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
        await POSTGRE_SQL_POOL.query('DELETE FROM user_phones WHERE user_phone_id = $1', [id]);
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Managers: Log a manager login
app.post('/managers/logins', async (req, res) => {
    const { login, password, date_of_login, device, ip_address } = req.body;
    try {
        const is_in_black_list_ip = await POSTGRE_SQL_POOL.query('SELECT ip FROM black_list_ip WHERE ip = $1', [ip_address]);
        if (is_in_black_list_ip.rows[0]) {
            return res.status(400).json({ error: 'All attempts were wasted' });
        }

        const manager = await POSTGRE_SQL_POOL.query('SELECT * FROM manager WHERE login = $1', [login]);

        if (manager.rows.length === 0) {
            await POSTGRE_SQL_POOL.query('INSERT INTO black_list_ip (ip) VALUES ($1)', [ip_address]);
            return res.status(400).json({ error: 'Invalid login credentials' });
        }


        const login_history = await POSTGRE_SQL_POOL.query('SELECT * FROM login_history WHERE ip_address = $1 AND device = $2', [ip_address, device]);

        if (!login_history.rows[0]) {
            await POSTGRE_SQL_POOL.query(
                'INSERT INTO login_history (manager_id, date_of_login, device, ip_address) VALUES ($1, $2, $3, $4)',
                [manager.rows[0].manager_id, date_of_login, device, ip_address]
            );
        } else {
            await POSTGRE_SQL_POOL.query(
                'UPDATE login_history SET date_of_login = $1 WHERE ip_address = $2 AND device = $3',
                [date_of_login, ip_address, device]
            );
        }


        const validPassword = await bcrypt.compare(password, manager.rows[0].password);
        if (!validPassword) {
            const failed_attempts = await POSTGRE_SQL_POOL.query('SELECT failed_login_attempts FROM login_history WHERE ip_address = $1 AND device = $2', [ip_address, device]);
            await POSTGRE_SQL_POOL.query(
                'UPDATE login_history SET failed_login_attempts = $1 WHERE ip_address = $2 AND device = $3',
                [failed_attempts.rows[0].failed_login_attempts + 1, ip_address, device]
            );

            if (failed_attempts.rows[0].failed_login_attempts + 1 >= 3) {
                await POSTGRE_SQL_POOL.query('INSERT INTO black_list_ip (ip) VALUES ($1)', [ip_address]);
            }

            return res.status(400).json({ error: 'Invalid login credentials' });

        }

        await POSTGRE_SQL_POOL.query(
            'UPDATE login_history SET failed_login_attempts = $1 WHERE manager_id = $2 AND device = $3',
            [0, manager.rows[0].manager_id, device]
        );

        const token = jwt.sign({ id: manager.rows[0].manager_id }, JWT_SECRET, { expiresIn: '1h' });

        
        res.status(201).json({ token });
    } catch (err) {

        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Protected example route
app.get('/managers', authenticateToken, async (req, res) => {
    try {
        // const result = await POSTGRE_SQL_POOL.query('SELECT manager_id, manager_name, login FROM manager');
        const result = await POSTGRE_SQL_POOL.query('SELECT login_history.*, manager.manager_name, manager.login FROM login_history JOIN manager ON manager.manager_id = login_history.manager_id');
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

