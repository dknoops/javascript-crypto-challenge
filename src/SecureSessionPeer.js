const nacl = require('libsodium-wrappers');
const Decryptor = require('./Decryptor');
const Encryptor = require('./Encryptor');

module.exports = async (peer) => {
    await nacl.ready;
    const keypair = nacl.crypto_kx_keypair();
    let other_peer, rx, tx, decryptor, encryptor, msg = undefined;

    let obj = Object.freeze({
       publicKey: keypair.publicKey,
       generateSharedKeys: async (p_other_peer) => {
            other_peer = p_other_peer;      
            const server_keys = nacl.crypto_kx_server_session_keys(keypair.publicKey, keypair.privateKey, other_peer.publicKey);
            rx = server_keys.sharedRx;
            tx = server_keys.sharedTx;
            decryptor = await Decryptor(rx);
            encryptor = await Encryptor(tx);
       },
       encrypt: (msg) => {
            return encryptor.encrypt(msg);
       },
       decrypt: (ciphertext, nonce) => {
            return decryptor.decrypt(ciphertext, nonce);
       },
       send: (msg) => {
            other_peer.setMessage(obj.encrypt(msg));
       },
       receive: () => {
            return obj.decrypt(msg.ciphertext, msg.nonce);
       },
       setMessage: (msg_in) => {
           msg = msg_in;
       }
    });

    if (peer) {
        other_peer = peer;
        const client_keys = nacl.crypto_kx_client_session_keys(keypair.publicKey, keypair.privateKey, other_peer.publicKey);
        rx = client_keys.sharedRx;
        tx = client_keys.sharedTx;
        other_peer.generateSharedKeys(obj);
        decryptor = await Decryptor(rx);
        encryptor = await Encryptor(tx);
    }

    return obj;
}