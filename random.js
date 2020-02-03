const net = require('net')
const crypto = require('crypto');

const port = 3000;

const server = net.createServer((client) => {
    client.write(new Uint8Array(crypto.randomBytes(1024 / 8)));
    client.end();
});

server.listen(port, function() {
    console.log('Server listening: ' + JSON.stringify(server.address()));
    server.on('close', function(){
        console.log('Server Terminated');
    });
    server.on('error', function(err){
        console.log('Server Error: ', JSON.stringify(err));
    });
});