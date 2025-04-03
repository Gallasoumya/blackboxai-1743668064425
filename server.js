const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const PORT = 8000;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Database files
const USERS_DB = 'users.json';
const PASSWORDS_DB = 'passwords.json';

// Initialize database files if they don't exist
if (!fs.existsSync(USERS_DB)) {
    fs.writeFileSync(USERS_DB, '[]');
}
if (!fs.existsSync(PASSWORDS_DB)) {
    fs.writeFileSync(PASSWORDS_DB, '[]');
}

// Helper functions
const readUsers = () => JSON.parse(fs.readFileSync(USERS_DB));
const writeUsers = (users) => fs.writeFileSync(USERS_DB, JSON.stringify(users, null, 2));
const readPasswords = () => JSON.parse(fs.readFileSync(PASSWORDS_DB));
const writePasswords = (passwords) => fs.writeFileSync(PASSWORDS_DB, JSON.stringify(passwords, null, 2));

// Authentication routes
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    const users = readUsers();

    if (users.some(user => user.email === email)) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now(), name, email, password: hashedPassword };
    
    users.push(newUser);
    writeUsers(users);

    res.json({ success: true, user: { id: newUser.id, name: newUser.name, email: newUser.email } });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users.find(user => user.email === email);

    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ 
        success: true, 
        user: { id: user.id, name: user.name, email: user.email } 
    });
});

// Password manager routes
app.get('/api/passwords', (req, res) => {
    const { userId } = req.query;
    const passwords = readPasswords();
    const userPasswords = passwords.filter(p => p.userId === userId);
    
    // In a real app, we would decrypt the passwords here
    res.json(userPasswords.map(p => ({
        ...p,
        password: '••••••••' // Return masked passwords to client
    })));
});

app.post('/api/passwords', (req, res) => {
    const { userId, website, username, password, notes } = req.body;
    const passwords = readPasswords();
    
    // In a real app, we would encrypt the password here
    const newPassword = { 
        id: Date.now(), 
        userId, 
        website, 
        username, 
        password, // This should be encrypted in production
        notes,
        createdAt: new Date().toISOString()
    };
    
    passwords.push(newPassword);
    writePasswords(passwords);

    res.json({ 
        ...newPassword,
        password: '••••••••' // Return masked password to client
    });
});

// Phishing detection route (simplified)
app.post('/api/check-url', (req, res) => {
    const { url } = req.body;
    
    // In a real app, this would check against phishing databases
    // This is a simplified simulation
    const isSafe = !url.includes('phishing') && !url.includes('scam');
    const isSuspicious = url.includes('login') || url.includes('verify');
    
    let result;
    if (!isSafe) {
        result = {
            status: 'dangerous',
            message: 'This is a known phishing site',
            details: [
                'Reported in multiple phishing databases',
                'Hosts fake login pages',
                'Associated with malware distribution'
            ]
        };
    } else if (isSuspicious) {
        result = {
            status: 'suspicious',
            message: 'This site looks suspicious',
            details: [
                'Domain was registered recently',
                'Similar to known legitimate domains',
                'Limited online presence'
            ]
        };
    } else {
        result = {
            status: 'safe',
            message: 'No known phishing threats detected',
            details: [
                'Domain is registered to a legitimate company',
                'No reports of phishing from this domain',
                'SSL certificate is valid and properly configured'
            ]
        };
    }

    // Add random delay to simulate real API call
    setTimeout(() => res.json(result), 1000);
});

// Network scan route (simplified simulation)
app.post('/api/scan-network', (req, res) => {
    // In a real app, this would perform actual network scanning
    // This is a simplified simulation
    const checks = [
        {
            name: 'Open Ports',
            status: Math.random() > 0.7 ? 'danger' : (Math.random() > 0.5 ? 'warning' : 'safe'),
            details: Math.random() > 0.7 ? 'Multiple open ports detected' : 
                    (Math.random() > 0.5 ? 'Some ports may be vulnerable' : 'No vulnerable ports found')
        },
        {
            name: 'DNS Security',
            status: Math.random() > 0.8 ? 'danger' : (Math.random() > 0.4 ? 'warning' : 'safe'),
            details: Math.random() > 0.8 ? 'Using unsecured DNS servers' : 
                    (Math.random() > 0.4 ? 'DNS could be more secure' : 'DNS properly secured')
        },
        {
            name: 'Encryption',
            status: Math.random() > 0.6 ? 'safe' : 'warning',
            details: Math.random() > 0.6 ? 'Strong encryption detected' : 'Encryption could be stronger'
        },
        {
            name: 'Router Security',
            status: Math.random() > 0.7 ? 'danger' : (Math.random() > 0.3 ? 'warning' : 'safe'),
            details: Math.random() > 0.7 ? 'Default credentials detected' : 
                    (Math.random() > 0.3 ? 'Some security settings could be improved' : 'Router properly secured')
        }
    ];

    // Calculate overall status
    const hasDanger = checks.some(check => check.status === 'danger');
    const hasWarning = checks.some(check => check.status === 'warning');
    const overallStatus = hasDanger ? 'dangerous' : hasWarning ? 'suspicious' : 'safe';

    // Simulate network info
    const networkInfo = {
        ipAddress: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        connectionType: Math.random() > 0.5 ? 'Wi-Fi' : 'Ethernet',
        isp: ['Comcast', 'Verizon', 'AT&T', 'Spectrum'][Math.floor(Math.random() * 4)],
        location: ['New York, NY', 'Chicago, IL', 'Los Angeles, CA', 'Houston, TX'][Math.floor(Math.random() * 4)]
    };

    setTimeout(() => res.json({
        status: overallStatus,
        checks,
        networkInfo
    }), 2000);
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});