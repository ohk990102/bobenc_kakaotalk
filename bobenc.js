import sjcl from './sjcl';
import base64 from 'base-64';


const BOBENC_HEADER = "BOBENC";
const BOBENC_VERSION = "01"
const BOBENC_CMD = {
    START: 'HELLOBOB',
    KEY_BROADCAST: 'KEYEXCHG',
    MSG_BROADCAST: 'MSGEXCHG',
    END: 'BYEWORLD',
};
const BOBENC_CMD_LENGTH = 8;

let bobencRoom = new Map();
let random_ready = false;

Socket.connect({port:3000}).then((client) => {
    let buf = client.input.read(1024 / 8);
    buf = new Uint32Array(new Uint8Array(buf).buffer);
    sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");
    console.log('random ready');
});

/**
 * Checks if given message is BobEnc protocol message.
 * @param {string} msg - Message to check. 
 */
function checkCompatibleBobEncMsg(msg) {
    if (typeof msg !== "string")
        return false;
    if (msg.slice(0, BOBENC_HEADER.length) !== BOBENC_HEADER)
        return false;
    let left = msg.slice(BOBENC_HEADER.length);
    let version = parseInt(left.slice(0, BOBENC_VERSION.length), 10);
    if (version === NaN)
        return false;
    if (version >= 90 || version > parseInt(BOBENC_VERSION))
        return false;
    return true;
}

/**
 * Get BobEncRoom instance by roomId.
 * @param {string} roomId - Room id to identify. (Kakao defines it as chatId -> hash it please)
 */
function getBobEncRoom(roomId) {
    if (typeof roomId === 'string') {
        if (bobencRoom.has(roomId)) {
            return bobencRoom.get(roomId);
        }
        return null;
    }
    // Throw if not string. 
    throw new Error('roomId should be string');
}

/**
 * Check BobEncRoom instance by roomId.
 * @param {string} roomId - Room id to identify. (Kakao defines it as chatId -> hash it please)
 */
function isBobEncRoom(roomId) {
    if (typeof roomId === 'string') {
        if (bobencRoom.has(roomId))
            return true;
        return false;
    }
    // Throw if not string. 
    throw new Error('roomId should be string');
}

/**
 * Set BobEncRoom instance by roomId.
 * @param {string} roomId - Room id to identify. (Kakao defines it as chatId -> hash it please)
 * @param {BobEncRoom} roomInstance - Instance of BobEncRoom. 
 */
function setBobEncRoom(roomId, roomInstance) {
    // console.log(roomId);
    if (typeof roomId === 'string') {
        bobencRoom.set(roomId, roomInstance);
        return;
    }
    // Throw if not string. 
    throw new Error('roomId should be string');
}

function getCmd(msg) {
    if (!checkCompatibleBobEncMsg(msg))
        return null;
    let left = msg.slice(BOBENC_HEADER.length + BOBENC_VERSION.length);
    if (left.length < BOBENC_CMD_LENGTH)
        return null;
    return left.slice(0, BOBENC_CMD_LENGTH);
}

function getMsg(msg) {
    if (!checkCompatibleBobEncMsg(msg))
        return null;
    let ret = msg.slice(BOBENC_HEADER.length + BOBENC_VERSION.length + BOBENC_CMD_LENGTH);
    // console.log(ret);
    return ret;
}

class BobEncRoom {
    constructor(roomIdHash, myuuid) {
        this.roomIdHash = roomIdHash;
        this.myuuid = myuuid;
        this.keys = sjcl.ecc.elGamal.generateKeys(sjcl.ecc.curves.c256);
        this.pub = this.keys.pub.get();
        this.sec = this.keys.sec.get();
        this.clients = new Map();
    }
    has_client(uuid) {
        return this.clients.has(uuid);
    }
    get_client(uuid) {
        return this.clients.get(uuid);
    }
    add_client(uuid, pubkey) {
        let pub = new sjcl.ecc.elGamal.publicKey(sjcl.ecc.curves.c256, sjcl.codec.base64.toBits(pubkey));
        let shkey = this.keys.sec.dh(pub);
        let new_client = new BobEncClient(uuid, shkey);
        this.clients.set(uuid, new_client);
        // console.log('client', uuid, 'added');
    }
    get_encrypted_msg(msg) {
        let new_msg = {
            uuid: this.myuuid,
            msgs : {}
        };
        for (let [uuid, client] of this.clients) {
            new_msg.msgs[uuid] = client.encrypt_msg(msg);
        }
        return JSON.stringify(new_msg);
    }
    get_decrypted_msg(msg) {
        if (!this.has_client(msg.uuid))
            return null;
        if (!msg.msgs.hasOwnProperty(this.myuuid))
            return null;
        return this.get_client(msg.uuid).decrypt_msg(msg.msgs[this.myuuid]);
    }
    get_myinfo() {
        return JSON.stringify({
            uuid: this.myuuid,
            key: sjcl.codec.base64.fromBits(this.pub.x.concat(this.pub.y))
        });
    }
    get_myuuid() {
        return this.myuuid;
    }
}

class BobEncClient {
    constructor(uuid, key) {
        this.uuid = uuid;
        this.key = key;
    }
    encrypt_msg(msg) {
        return base64.encode(sjcl.encrypt(this.key, msg));
    }
    decrypt_msg(msg) {
        return sjcl.decrypt(this.key, base64.decode(msg));
    }
}

export {BOBENC_HEADER, BOBENC_VERSION, BOBENC_CMD, checkCompatibleBobEncMsg, getCmd, getMsg, getBobEncRoom, isBobEncRoom, setBobEncRoom, BobEncRoom, random_ready};