require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const path = require('path');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3002;

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-here',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true
    }
}));

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '12345',
    database: process.env.DB_NAME || 'online_voting_system',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Initialize database tables with error handling for existing tables
async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        
        // Drop existing tables if they exist (for development only)
        await connection.execute('DROP TABLE IF EXISTS votes');
        await connection.execute('DROP TABLE IF EXISTS candidates');
        await connection.execute('DROP TABLE IF EXISTS elections');
        await connection.execute('DROP TABLE IF EXISTS students');
        await connection.execute('DROP TABLE IF EXISTS admins');
        
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS admins (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await connection.execute(`
            CREATE TABLE IF NOT EXISTS students (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(50) NOT NULL UNIQUE,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS elections (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                start_date DATETIME NOT NULL,
                end_date DATETIME NOT NULL,
                results_published BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await connection.execute(`
            CREATE TABLE IF NOT EXISTS candidates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                election_id INT NOT NULL,
                name VARCHAR(255) NOT NULL,
                student_id VARCHAR(50) NOT NULL,
                photo_url VARCHAR(255),
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE
            )
        `);

        await connection.execute(`
            CREATE TABLE IF NOT EXISTS votes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                election_id INT NOT NULL,
                candidate_id INT NOT NULL,
                student_id VARCHAR(50) NOT NULL,
                voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE,
                FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE,
                FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
                UNIQUE KEY unique_vote (election_id, student_id)
            )
        `);

        // Insert a default admin if none exists
        const [adminRows] = await connection.execute('SELECT id FROM admins LIMIT 1');
        if (adminRows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await connection.execute(
                'INSERT INTO admins (email, password) VALUES (?, ?)',
                ['admin@example.com', hashedPassword]
            );
            console.log('Default admin created: admin@example.com / admin123');
        }

        connection.release();
        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
        process.exit(1);
    }
}

// Auth Service
const authService = {
    // Admin Authentication
    async registerAdmin(email, password) {
        const connection = await pool.getConnection();
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            const [result] = await connection.execute(
                'INSERT INTO admins (email, password) VALUES (?, ?)',
                [email, hashedPassword]
            );
            return result.affectedRows > 0;
        } catch (error) {
            console.error('Admin registration error:', error);
            throw error;
        } finally {
            connection.release();
        }
    },

    async loginAdmin(email, password) {
        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute(
                'SELECT id, password FROM admins WHERE email = ?',
                [email]
            );
            if (rows.length === 0) return false;
            
            const match = await bcrypt.compare(password, rows[0].password);
            return match ? { id: rows[0].id, email } : false;
        } catch (error) {
            console.error('Admin login error:', error);
            throw error;
        } finally {
            connection.release();
        }
    },

    // Student Authentication
    async studentExists(email, studentId) {
        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute(
                'SELECT id FROM students WHERE email = ? OR student_id = ?',
                [email, studentId]
            );
            return rows.length > 0;
        } catch (error) {
            console.error('Student exists check error:', error);
            throw error;
        } finally {
            connection.release();
        }
    },

    async registerStudent(studentId, fullName, email, password) {
        const connection = await pool.getConnection();
        try {
            if (await this.studentExists(email, studentId)) {
                throw new Error('Email or Student ID already in use');
            }
            
            const hashedPassword = await bcrypt.hash(password, 10);
            const [result] = await connection.execute(
                'INSERT INTO students (student_id, full_name, email, password) VALUES (?, ?, ?, ?)',
                [studentId, fullName, email, hashedPassword]
            );
            return result.affectedRows > 0;
        } catch (error) {
            console.error('Student registration error:', error);
            throw error;
        } finally {
            connection.release();
        }
    },

    async loginStudent(email, password) {
        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute(
                'SELECT id, password, full_name, student_id FROM students WHERE email = ?',
                [email]
            );
            if (rows.length === 0) return false;
            
            const match = await bcrypt.compare(password, rows[0].password);
            if (!match) return false;
            
            return {
                id: rows[0].id,
                studentId: rows[0].student_id,
                fullName: rows[0].full_name,
                email
            };
        } catch (error) {
            console.error('Student login error:', error);
            throw error;
        } finally {
            connection.release();
        }
    }
};

// Routes

// Admin Routes
app.post('/api/registerAdmin', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password are required" 
            });
        }
        
        const success = await authService.registerAdmin(email, password);
        
        if (success) {
            res.json({ 
                success: true, 
                message: "Admin registered successfully" 
            });
        } else {
            res.status(400).json({ 
                success: false, 
                message: "Registration failed" 
            });
        }
    } catch (error) {
        console.error('Admin registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message || "Internal server error" 
        });
    }
});

app.post('/api/loginAdmin', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password are required" 
            });
        }

        const admin = await authService.loginAdmin(email, password);
        
        if (admin) {
            req.session.user = admin;
            req.session.role = 'admin';
            res.json({ 
                success: true, 
                message: "Login successful",
                data: {
                    id: admin.id,
                    email: admin.email
                }
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: "Invalid credentials" 
            });
        }
    } catch (error) {
        console.error('Login admin error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message || "Internal server error" 
        });
    }
});

// Student Routes
app.post('/api/registerStudent', async (req, res) => {
    try {
        const { student_id, full_name, email, password } = req.body;
        
        if (!student_id || !full_name || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "All fields are required" 
            });
        }
        
        const success = await authService.registerStudent(student_id, full_name, email, password);
        
        if (success) {
            res.json({ 
                success: true, 
                message: "Student registered successfully" 
            });
        } else {
            res.status(400).json({ 
                success: false, 
                message: "Registration failed" 
            });
        }
    } catch (error) {
        console.error('Register student error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message || "Internal server error" 
        });
    }
});

app.post('/api/loginStudent', async (req, res) => {
    try {
        const { email, password } = req.body;
        const student = await authService.loginStudent(email, password);
        
        if (student) {
            req.session.user = student;
            req.session.role = 'student';
            res.json({ 
                success: true, 
                message: "Login successful",
                data: {
                    id: student.id,
                    studentId: student.studentId,
                    fullName: student.fullName,
                    email: student.email
                }
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: "Invalid credentials" 
            });
        }
    } catch (error) {
        console.error('Login student error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message || "Internal server error" 
        });
    }
});

// Logout Route
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ 
                success: false, 
                message: "Logout failed" 
            });
        }
        res.clearCookie('connect.sid');
        res.json({ 
            success: true, 
            message: "Logged out successfully" 
        });
    });
});

// Election Management
app.post('/api/elections', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const { title, description, start_date, end_date } = req.body;
        const [result] = await pool.execute(
            'INSERT INTO elections (title, description, start_date, end_date) VALUES (?, ?, ?, ?)',
            [title, description, start_date, end_date]
        );
        res.json({ 
            success: true, 
            id: result.insertId,
            message: "Election created successfully"
        });
    } catch (error) {
        console.error('Create election error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/elections', async (req, res) => {
    try {
        const [elections] = await pool.execute('SELECT * FROM elections');
        res.json({ success: true, data: elections });
    } catch (error) {
        console.error('Get elections error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/elections/active', async (req, res) => {
    try {
        const [elections] = await pool.execute(
            'SELECT * FROM elections WHERE start_date <= NOW() AND end_date >= NOW()'
        );
        res.json({ success: true, data: elections });
    } catch (error) {
        console.error('Get active elections error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/elections/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM elections WHERE id = ?',
            [req.params.id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Election not found" });
        }
        res.json({ success: true, data: rows[0] });
    } catch (error) {
        console.error('Get election error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/elections/:id', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const { title, description, start_date, end_date, results_published } = req.body;
        const [result] = await pool.execute(
            'UPDATE elections SET title = ?, description = ?, start_date = ?, end_date = ?, results_published = ? WHERE id = ?',
            [title, description, start_date, end_date, results_published, req.params.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Election not found" });
        }
        
        res.json({ 
            success: true,
            message: "Election updated successfully"
        });
    } catch (error) {
        console.error('Update election error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/elections/:id', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        await pool.execute('DELETE FROM elections WHERE id = ?', [req.params.id]);
        res.json({ 
            success: true,
            message: "Election deleted successfully"
        });
    } catch (error) {
        console.error('Delete election error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Candidate Management
app.post('/api/candidates', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const { election_id, name, student_id, photo_url, details } = req.body;
        
        // Validate required fields
        if (!election_id || !name || !student_id) {
            return res.status(400).json({ 
                success: false, 
                message: "Election ID, Name, and Student ID are required" 
            });
        }

        // Check if election exists
        const [election] = await pool.execute(
            'SELECT id FROM elections WHERE id = ?',
            [election_id]
        );
        
        if (election.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: "Election does not exist" 
            });
        }

        // Check if student exists
        const [student] = await pool.execute(
            'SELECT id FROM students WHERE student_id = ?',
            [student_id]
        );
        
        if (student.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: "Student with this ID does not exist" 
            });
        }

        const [result] = await pool.execute(
            'INSERT INTO candidates (election_id, name, student_id, photo_url, details) VALUES (?, ?, ?, ?, ?)',
            [election_id, name, student_id, photo_url || null, details || null]
        );
        
        res.json({ 
            success: true, 
            id: result.insertId,
            message: "Candidate created successfully"
        });
    } catch (error) {
        console.error('Create candidate error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.sqlMessage || "Failed to create candidate" 
        });
    }
});

app.get('/api/candidates', async (req, res) => {
    try {
        const [candidates] = await pool.execute('SELECT * FROM candidates');
        res.json({ success: true, data: candidates });
    } catch (error) {
        console.error('Get candidates error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/candidates/:id', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM candidates WHERE id = ?',
            [req.params.id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Candidate not found" });
        }
        res.json({ success: true, data: rows[0] });
    } catch (error) {
        console.error('Get candidate error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/candidates/election/:election_id', async (req, res) => {
    try {
        const [candidates] = await pool.execute(
            'SELECT * FROM candidates WHERE election_id = ?',
            [req.params.election_id]
        );
        res.json({ success: true, data: candidates });
    } catch (error) {
        console.error('Get candidates by election error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/candidates/:id', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const { election_id, name, student_id, photo_url, details } = req.body;
        const [result] = await pool.execute(
            'UPDATE candidates SET election_id = ?, name = ?, student_id = ?, photo_url = ?, details = ? WHERE id = ?',
            [election_id, name, student_id, photo_url, details, req.params.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Candidate not found" });
        }
        
        res.json({ 
            success: true,
            message: "Candidate updated successfully"
        });
    } catch (error) {
        console.error('Update candidate error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/candidates/:id', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        await pool.execute('DELETE FROM candidates WHERE id = ?', [req.params.id]);
        res.json({ 
            success: true,
            message: "Candidate deleted successfully"
        });
    } catch (error) {
        console.error('Delete candidate error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// In server.js, update the candidate creation endpoint
app.post('/api/candidates', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const { election_id, name, student_id, photo_url, details } = req.body;
        
        // Validate required fields
        if (!election_id || !name || !student_id) {
            return res.status(400).json({ 
                success: false, 
                message: "Election ID, Name, and Student ID are required" 
            });
        }

        // Check if election exists
        const [election] = await pool.execute(
            'SELECT id FROM elections WHERE id = ?',
            [election_id]
        );
        
        if (election.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: "Election does not exist" 
            });
        }

        // Check if student exists - provide more detailed error
        const [student] = await pool.execute(
            'SELECT student_id, full_name FROM students WHERE student_id = ?',
            [student_id]
        );
        
        if (student.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Student with ID ${student_id} does not exist. Please register the student first.`,
                student_id: student_id
            });
        }

        // Check if this student is already a candidate in this election
        const [existingCandidate] = await pool.execute(
            'SELECT id FROM candidates WHERE election_id = ? AND student_id = ?',
            [election_id, student_id]
        );
        
        if (existingCandidate.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: `This student is already a candidate in this election`
            });
        }

        const [result] = await pool.execute(
            'INSERT INTO candidates (election_id, name, student_id, photo_url, details) VALUES (?, ?, ?, ?, ?)',
            [election_id, name, student_id, photo_url || null, details || null]
        );
        
        res.json({ 
            success: true, 
            id: result.insertId,
            message: "Candidate created successfully",
            student_name: student[0].full_name
        });
    } catch (error) {
        console.error('Create candidate error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.sqlMessage || "Failed to create candidate" 
        });
    }
});

// Voting
app.post('/api/votes', async (req, res) => {
    if (req.session.role !== 'student') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const { election_id, candidate_id } = req.body;
        const student_id = req.session.user.studentId;

        // Check if student has already voted in this election
        const [existingVote] = await pool.execute(
            'SELECT id FROM votes WHERE election_id = ? AND student_id = ?',
            [election_id, student_id]
        );

        if (existingVote.length > 0) {
            return res.status(400).json({ success: false, message: "You have already voted in this election" });
        }

        // Check if election is active
        const [election] = await pool.execute(
            'SELECT id FROM elections WHERE id = ? AND start_date <= NOW() AND end_date >= NOW()',
            [election_id]
        );

        if (election.length === 0) {
            return res.status(400).json({ success: false, message: "Election is not active" });
        }

        // Check if candidate exists in this election
        const [candidate] = await pool.execute(
            'SELECT id FROM candidates WHERE id = ? AND election_id = ?',
            [candidate_id, election_id]
        );

        if (candidate.length === 0) {
            return res.status(400).json({ success: false, message: "Candidate not found in this election" });
        }

        const [result] = await pool.execute(
            'INSERT INTO votes (election_id, candidate_id, student_id) VALUES (?, ?, ?)',
            [election_id, candidate_id, student_id]
        );

        res.json({ 
            success: true, 
            id: result.insertId,
            message: "Vote submitted successfully"
        });
    } catch (error) {
        console.error('Vote error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Results
app.get('/api/results/:election_id', async (req, res) => {
    try {
        // First check if results are published
        const [election] = await pool.execute(
            'SELECT results_published FROM elections WHERE id = ?',
            [req.params.election_id]
        );
        
        if (election.length === 0) {
            return res.status(404).json({ success: false, message: "Election not found" });
        }
        
        if (!election[0].results_published) {
            return res.status(403).json({ 
                success: false, 
                message: "Results for this election have not been published yet" 
            });
        }

        const [results] = await pool.execute(
            `SELECT c.id, c.name, c.photo_url, c.details, COUNT(v.id) as vote_count 
             FROM candidates c 
             LEFT JOIN votes v ON c.id = v.candidate_id 
             WHERE c.election_id = ? 
             GROUP BY c.id 
             ORDER BY vote_count DESC`,
            [req.params.election_id]
        );
        res.json({ success: true, data: results });
    } catch (error) {
        console.error('Get results error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Publish Results
app.post('/api/elections/:id/publish-results', async (req, res) => {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        const [result] = await pool.execute(
            'UPDATE elections SET results_published = TRUE WHERE id = ?',
            [req.params.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Election not found" });
        }
        
        res.json({ 
            success: true,
            message: "Results published successfully"
        });
    } catch (error) {
        console.error('Publish results error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        success: false, 
        message: 'Internal server error' 
    });
});

// Start server
async function startServer() {
    try {
        await initializeDatabase();
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
            console.log(`Available endpoints:`);
            console.log(`- POST http://localhost:${PORT}/api/registerAdmin`);
            console.log(`- POST http://localhost:${PORT}/api/loginAdmin`);
            console.log(`- POST http://localhost:${PORT}/api/registerStudent`);
            console.log(`- POST http://localhost:${PORT}/api/loginStudent`);
            console.log(`- POST http://localhost:${PORT}/api/logout`);
            console.log(`- GET  http://localhost:${PORT}/api/elections`);
            console.log(`- GET  http://localhost:${PORT}/api/candidates`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();