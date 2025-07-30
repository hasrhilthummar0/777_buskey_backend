require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const db = require('./database/db');
const bcrypt = require('bcrypt');
const twilio = require('twilio');
const util = require('util');
const query = util.promisify(db.query).bind(db);
const app = express();
const PORT = process.env.PORT || 5000;
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const session = require('express-session');

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());


app.use(session({
  secret: process.env.secret__Key, 
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

app.get('/api/games', async (req, res) => {
    const { provider, limitCount, type } = req.query;

    if (!provider || !limitCount) {
        return res.status(400).json({ message: 'Provider and limitCount are required.' });
    }

    try {
        const apiEndpoint = `${process.env.GAME_API_BASE_URL}/providerGame`;

        const response = await axios.get(apiEndpoint, {
            headers: {
                'Authorization': `Bearer ${process.env.GAME_API_TOKEN}`,
            },
            params: {
                provider: provider,
                limitCount: Number(limitCount),
                type: type || undefined
            }
        });
        res.status(200).json(response.data);

    } catch (error) {
        console.error('Game List', error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'Failed to retrieve game list.' });
    }
});

app.post('/api/callback', (req, res) => {
    const callbackData = req.body;
    console.log('Callback Received:', callbackData);

    res.status(200).json({
        credit_amount: 105.00,
        timestamp: Date.now()
    });
});

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// app.post('/api/auth/send-otp', async (req, res) => {
//     const { phone, email } = req.body;

//     if (!phone || !email) {
//         return res.status(400).json({ message: 'Phone number and email are required.' });
//     }

//     try {
//         const existingUsers = await query(
//             'SELECT * FROM users WHERE (phone = ? OR email = ?) AND is_verified = TRUE',
//             [phone, email]
//         );

//         if (existingUsers.length > 0) {
//             return res.status(400).json({ message: 'This phone number or email is already registered.' });
//         }

//         const otp = Math.floor(100000 + Math.random() * 900000).toString();
//         const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

//         const sql = `
//             INSERT INTO users (phone, email, name, otp, otp_expiry, password) 
//             VALUES (?, ?, ?, ?, ?, '') 
//             ON DUPLICATE KEY UPDATE 
//                 email = VALUES(email), 
//                 name = VALUES(name),
//                 otp = VALUES(otp), 
//                 otp_expiry = VALUES(otp_expiry)`;

//         await query(sql, [phone, email, req.body.name || ' ', otp, otpExpiry]);

//         await client.messages.create({
//             body: `Your verification code is: ${otp}`,
//             from: process.env.TWILIO_PHONE_NUMBER,
//             to: `+91${phone}`
//         });

//         res.status(200).json({ message: 'OTP sent successfully!' });

//     } catch (error) {
//         console.error('Send OTP Error:', error);
//         res.status(500).json({ message: 'Failed to send OTP. Please try again.' });
//     }
// });

app.post('/api/auth/send-otp', async (req, res) => {
    const { phone, email, name } = req.body;
    if (!phone || !email || !name) {
        return res.status(400).json({ message: 'Name, Email and Phone number are required.' });
    }

    try {
        // --- અહીં સુધારો કરેલ છે ---
        // ક્વેરીનું પરિણામ સીધું જ 'existingUsers' માં એરે તરીકે મેળવો
        const existingUsers = await db.query(
            'SELECT * FROM users WHERE (phone = ? OR email = ?) AND is_verified = TRUE',
            [phone, email]
        );

        // હવે આ શરત બરાબર કામ કરશે
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'This phone number or email is already registered.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

        const sql = `
            INSERT INTO users (phone, email, name, otp, otp_expiry, password) 
            VALUES (?, ?, ?, ?, ?, '') 
            ON DUPLICATE KEY UPDATE 
                email = VALUES(email), 
                name = VALUES(name),
                otp = VALUES(otp), 
                otp_expiry = VALUES(otp_expiry)`;

        await db.query(sql, [phone, email, name, otp, otpExpiry]);

        await client.messages.create({
            body: `Your verification code is: ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: `+91${phone}`
        });

        res.status(200).json({ message: 'OTP sent successfully!' });

    } catch (error) {
        console.error('Send OTP Error:', error);
        res.status(500).json({ message: 'Failed to send OTP. Please try again.' });
    }
});

// app.post('/api/auth/register', async (req, res) => {
//     const { name, phone, email, password, otp } = req.body;

//     if (!name || !phone || !email || !password || !otp) {
//         return res.status(400).json({ message: 'All fields are required.' });
//     }

//     try {
//         const users = await query('SELECT * FROM users WHERE phone = ?', [phone]);

//         if (users.length === 0) {
//             return res.status(400).json({ message: 'Phone number not found. Please send OTP again.' });
//         }

//         const user = users[0];

//         if (user.otp !== otp || new Date() > new Date(user.otp_expiry)) {
//             return res.status(400).json({ message: 'Invalid or expired OTP.' });
//         }

//         const hashedPassword = await bcrypt.hash(password, 10);

//         const updateSql = `
//             UPDATE users 
//             SET name = ?, email = ?, password = ?, is_verified = TRUE, otp = NULL, otp_expiry = NULL, bonus_balance = 50.00
//             WHERE phone = ?`;
//         await query(updateSql, [name, email, hashedPassword, phone]);

//         res.status(201).json({ message: 'User registered successfully!' });

//     } catch (error) {
//         if (error.code === 'ER_DUP_ENTRY') {
//             return res.status(400).json({ message: 'This email address is already registered.' });
//         }
//         console.error('Registration Error:', error);
//         res.status(500).json({ message: 'An internal error occurred.' });
//     }
// });

app.post('/api/auth/register', async (req, res) => {
    const { name, phone, email, password, otp } = req.body;
    if (!name || !phone || !email || !password || !otp) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        // --- અહીં સુધારો કરેલ છે ---
        const users = await db.query('SELECT * FROM users WHERE phone = ?', [phone]);

        if (users.length === 0) {
            return res.status(400).json({ message: 'Phone number not found. Please send OTP again.' });
        }

        const user = users[0];

        if (user.otp !== otp || new Date() > new Date(user.otp_expiry)) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const updateSql = `
            UPDATE users SET name = ?, email = ?, password = ?, is_verified = TRUE, 
            otp = NULL, otp_expiry = NULL, bonus_balance = 50.00 
            WHERE phone = ?`;
        await db.query(updateSql, [name, email, hashedPassword, phone]);

        res.status(201).json({ message: 'User registered successfully!' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'This email is already registered.' });
        }
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'An internal error occurred.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        // --- અહીં સુધારો કરેલ છે ---
        const users = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = users[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const payload = { id: user.id, name: user.name, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.status(200).json({
            message: 'Login successful!',
            user: payload
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'An internal error occurred.' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.cookie('auth_token', '', {
        httpOnly: true,
        expires: new Date(0),
        path: '/',
        sameSite: 'lax'
    });

    res.status(200).json({ message: 'Logged out successfully.' });
});

app.get('/api/user/me', async (req, res) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) {
            return res.status(401).json({ message: 'Not authenticated' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const users = await query(
            'SELECT id, name, email, main_balance, bonus_balance, bank_details FROM users WHERE id = ?',
            [decoded.id]
        );

        if (!users || users.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(users[0]);

    } catch (error) {
        console.error('Get User Error:', error);
        res.status(401).json({ message: 'Invalid token or server error.' });
    }
});

app.post('/api/deposit/add', async (req, res) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) {
            return res.status(401).json({ message: 'Not authenticated. Please login again.' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const { amount } = req.body;
        if (!amount || amount <= 0) {
            return res.status(400).json({ message: 'Invalid deposit amount.' });
        }

        const depositAmount = parseFloat(amount);
        const bonusAmount = depositAmount * 0.05;

        const updateUserWalletSql = `
            UPDATE users 
            SET main_balance = main_balance + ?, 
                bonus_balance = bonus_balance + ? 
            WHERE id = ?`;
        await query(updateUserWalletSql, [depositAmount, bonusAmount, userId]);

        res.status(200).json({
            message: `₹${depositAmount.toFixed(2)} deposited and ₹${bonusAmount.toFixed(2)} bonus credited successfully!`
        });

    } catch (error) {
        console.error('Deposit Error:', error);
        res.status(500).json({ message: 'An error occurred during the deposit process.' });
    }
});

app.post('/api/user/bank-details', async (req, res) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) return res.status(401).json({ message: 'Not authenticated' });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const { accountHolderName, accountNumber, ifscCode, upiId } = req.body;

        if (!accountHolderName || (!accountNumber && !upiId)) {
            return res.status(400).json({ message: 'Please provide required bank details.' });
        }

        const bankDetails = JSON.stringify({ accountHolderName, accountNumber, ifscCode, upiId });

        await query('UPDATE users SET bank_details = ? WHERE id = ?', [bankDetails, userId]);

        res.status(200).json({ message: 'Bank details updated successfully.' });
    } catch (error) {
        console.error("Update Bank Details Error:", error);
        res.status(500).json({ message: 'Failed to update bank details.' });
    }
});

app.post('/api/withdrawal/request', async (req, res) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) return res.status(401).json({ message: 'Not authenticated' });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const { amount } = req.body;
        const withdrawalAmount = parseFloat(amount);

        if (!amount || withdrawalAmount < 110) {
            return res.status(400).json({ message: 'Invalid withdrawal amount. Minimum is ₹110.' });
        }

        const users = await query(
            'SELECT main_balance, bank_details FROM users WHERE id = ?',
            [userId]
        );
        const user = users[0];

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (!user.bank_details) {
            return res.status(400).json({ message: 'Please add your withdrawal account first.' });
        }
        if (user.main_balance < withdrawalAmount) {
            return res.status(400).json({ message: 'Insufficient withdrawable balance.' });
        }

        await query('UPDATE users SET main_balance = main_balance - ? WHERE id = ?', [withdrawalAmount, userId]);

        await query(
            'INSERT INTO withdrawals (user_id, amount, status, bank_details) VALUES (?, ?, ?, ?)',
            [userId, withdrawalAmount, 'pending', user.bank_details]
        );

        res.status(200).json({ message: `Withdrawal request submitted successfully.` });

    } catch (error) {
        console.error("WITHDRAWAL API ERROR", error);
        res.status(400).json({ message: error.message || 'Failed to submit withdrawal request.' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({ message: 'Phone number is required.' });
    }

    try {
        
        const users = await db.query('SELECT id, is_verified FROM users WHERE phone = ?', [phone.trim()]);

        // Check if user exists and is verified
        // If no user exists or the user is not verified, we still send an OTP
        if (users.length === 0 || !users[0].is_verified) {
            console.log(`Password reset attempt for non-existent or unverified phone: ${phone}`);
            return res.status(200).json({ message: 'If a user with this phone number exists, an OTP has been sent.' });
        }
        
        const user = users[0];
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); 

        await db.query('UPDATE users SET otp = ?, otp_expiry = ? WHERE id = ?', [otp, otpExpiry, user.id]);

        await client.messages.create({
           body: `Your password reset code is: ${otp}`,
           from: process.env.TWILIO_PHONE_NUMBER,
           to: `+91${phone}`
        });
        
        res.status(200).json({ message: 'If a user with this phone number exists, an OTP has been sent.' });

    } catch (error) {
        console.error('Forgot Password Error:', error);
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { newPassword } = req.body;
   
    const phone = req.session.otp_verified_phone;

    if (!newPassword || !phone) {
        return res.status(400).json({ message: 'Invalid request. Please verify OTP first.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const updateSql = 'UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE phone = ?';
        await db.query(updateSql, [hashedPassword, phone]);

        
        delete req.session.otp_verified_phone;

        res.status(200).json({ message: 'Password has been reset successfully.' });

    } catch (error) {
        console.error('Reset Password Error:', error);
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});


app.post('/api/auth/verify-otp', async (req, res) => {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
        return res.status(400).json({ message: 'Phone number and OTP are required.' });
    }

    try {
        
        const users = await db.query('SELECT * FROM users WHERE phone = ?', [phone]);

        
        if (users.length === 0) {
            return res.status(400).json({ message: 'Invalid phone number.' });
        }

       
        const user = users[0];

        
        if (user.otp !== otp || new Date() > new Date(user.otp_expiry)) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        req.session.otp_verified_phone = phone;

        res.status(200).json({ message: 'OTP verified successfully.' });

    } catch (error) {
        console.error('Verify OTP Error:', error);
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
