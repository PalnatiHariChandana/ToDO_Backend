// File: backend/server.js
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Security dependencies
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

const app = express();

// Security configurations
const SALT_ROUNDS = 12;
const JWT_OPTIONS = {
    expiresIn: '1h',
    algorithm: 'HS512'
};

// Middleware
// Update this part in your server.jsF
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));


app.use(express.json({ limit: '10kb' }));
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", "https://your-api-url.com"],
        },
    }
})); //secuirty headers


// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    tls: true,
    tlsAllowInvalidCertificates: false,
    tlsAllowInvalidHostnames: false,
})
    .then(() => console.log('Connected to MongoDB Successfully!'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
    });
// Add this temporarily to debug

// Rate limiting - Prevent brute force attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Specific limiter for authentication routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 1 hour
    max: 100, // 100 attempts per hour
    message: 'Too many login attempts, please try again later'
});
app.use('/api/auth/', authLimiter);

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(hpp());

// User Model (models/User.js)
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [5, 'Username must be at least 5 characters'],
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters']
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});
const User = mongoose.model('User', userSchema);

// Todo Model (models/Todo.js)
const todoSchema = new mongoose.Schema({
    text: {
        type: String,
        required: [true, 'Todo text is required'],
        trim: true,
        maxlength: [500, 'Todo text cannot exceed 500 characters']
    },
    completed: {
        type: Boolean,
        default: false
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    shareableLink: {
        type: String,
        unique: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Todo = mongoose.model('Todo', todoSchema);

// Auth Middleware
// const jwt = require('jsonwebtoken');
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization');

        if (!token || !token.startsWith('Bearer ')) {
            throw new Error('Invalid token format');
        }

        const tokenString = token.replace('Bearer ', '');

        const decoded = jwt.verify(tokenString, process.env.JWT_SECRET, {
            algorithms: ['HS512']
        });

        // Check token expiration
        const now = Math.floor(Date.now() / 1000);
        if (decoded.exp <= now) {
            throw new Error('Token has expired');
        }

        // Check if user still exists
        const user = await User.findById(decoded.userId);
        if (!user) {
            throw new Error('User not found');
        }

        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({
            error: 'Authentication failed',
            message: 'Please login again.'
        });
    }
};

// Auth Routes
// const bcrypt = require('bcryptjs');

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Register attempt:', { username });

        // Add username validation check before attempting to create user
        if (username.length < 5) {
            return res.status(400).json({
                error: 'Username must be at least 5 characters long'
            });
        }

        // Password strength validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                error: 'Password too weak',
                requirements: 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number and one special character'
            });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const user = new User({
            username,
            password: hashedPassword
        });

        await user.save();
        console.log('User created successfully');

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            JWT_OPTIONS
        );

        res.status(201).json({ token });
    } catch (error) {
        console.error('Registration error:', error);
        // Send more specific error message
        res.status(400).json({
            error: error.message || 'Error creating user',
            details: error.errors ? Object.values(error.errors).map(err => err.message) : []
        });
    }
});


// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Please provide both username and password' });
        }

        const user = await User.findOne({ username });

        // Check if account is locked
        if (user && user.lockUntil && user.lockUntil > Date.now()) {
            return res.status(403).json({
                error: 'Account is temporarily locked',
                unlockTime: user.lockUntil
            });
        }

        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            // Increment login attempts
            user.loginAttempts += 1;

            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + (15 * 60 * 1000); // Lock for 15 minutes
            }

            await user.save();

            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Reset login attempts on successful login
        user.loginAttempts = 0;
        user.lockUntil = null;
        await user.save();

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            JWT_OPTIONS
        );

        // Set secure cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 3600000 // 1 hour
        });

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Add this near your other routes in server.js
app.get('/', (req, res) => {
    res.json({ message: 'Backend API is running!' });
});

// Todo Routes
// Create todo
app.post('/api/todos', auth, async (req, res) => {
    try {
        const { text } = req.body;

        // Enhanced shareable link with unique identifier
        const shareableLink = `https://todo-app-bga2.vercel.app/todo/${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        // Input validation
        if (!text || text.trim().length === 0) {
            return res.status(400).json({ error: 'Todo text is required' });
        }

        const todo = new Todo({
            text,
            user: req.user.userId,
            shareableLink
        });

        await todo.save();
        res.status(201).json(todo);
    } catch (error) {
        res.status(500).json({ error: 'Error creating todo' });
    }
});

// Get todos
app.get('/api/todos', auth, async (req, res) => {
    try {
        const todos = await Todo.find({ user: req.user.userId });
        res.json(todos);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching todos' });
    }
});

// Update todo
app.put('/api/todos/:id', auth, async (req, res) => {
    try {
        const todo = await Todo.findOneAndUpdate(
            { _id: req.params.id, user: req.user.userId },
            req.body,
            { new: true }
        );
        if (!todo) {
            return res.status(404).json({ error: 'Todo not found' });
        }
        res.json(todo);
    } catch (error) {
        res.status(500).json({ error: 'Error updating todo' });
    }
});

// Delete todo
app.delete('/api/todos/:id', auth, async (req, res) => {
    try {
        const todo = await Todo.findOneAndDelete({
            _id: req.params.id,
            user: req.user.userId
        });
        if (!todo) {
            return res.status(404).json({ error: 'Todo not found' });
        }
        res.json({ message: 'Todo deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Error deleting todo' });
    }
});

// Get shared todo
app.get('/api/todos/shared/:link', async (req, res) => {
    try {
        const todo = await Todo.findOne({ shareableLink: req.params.link });
        if (!todo) {
            return res.status(404).json({ error: 'Todo not found' });
        }
        res.json(todo);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching shared todo' });
    }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});