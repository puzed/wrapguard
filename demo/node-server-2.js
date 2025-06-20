const http = require('http');
const os = require('os');

console.log('Node.js version:', process.version);
console.log('Process PID:', process.pid);

const PORT = 8002;
const SERVER_NAME = 'Node Server 2';
const MY_IP = '10.150.0.3';
const OTHER_SERVER = 'http://10.150.0.2:8001';

// Create HTTP server
const server = http.createServer(async (req, res) => {
    res.end('i am 2')
});


// Start server
console.log('About to call server.listen...');
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ${SERVER_NAME} listening on port ${PORT}`);
    console.log(`📍 WireGuard IP: ${MY_IP}`);
    console.log(`🔗 Other server: ${OTHER_SERVER}`);
    
    console.log('🎯 Server is listening and ready to accept connections');

    setInterval(() => {
        console.log('server2: attemping connection')
        
        const req = http.request(OTHER_SERVER, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                console.log('Response:', data);
                console.log('✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅');
            });
        });
        
        req.on('error', (error) => {
            console.log('Error:', error.message);
        });
        
        req.end();
    }, 10000)
});


console.log('Server setup complete, waiting for listen callback...');