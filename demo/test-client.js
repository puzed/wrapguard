const net = require('net');

console.log('Test client starting...');

const client = new net.Socket();

client.on('connect', () => {
    console.log('Connected!');
    client.write('GET / HTTP/1.1\r\nHost: 10.150.0.3:8002\r\n\r\n');
});

client.on('data', (data) => {
    console.log('Received:', data.toString());
    client.destroy();
});

client.on('error', (err) => {
    console.log('Error:', err);
});

client.on('close', () => {
    console.log('Connection closed');
});

console.log('Connecting to 10.150.0.3:8002...');
client.connect(8002, '10.150.0.3');