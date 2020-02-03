// require
import * as bobenc from './bobenc.js';
import BSON from 'bson';
import hash from 'object-hash';
import uuidv4 from 'uuid/v4';

// header const


// pointers
const KAKAO_SEND = 0xD1FE20;    // TODO: dynamic assign
const KAKAO_RECV = 0xD3AF70;    // TODO: dynamic assign
const sendptr = Module.findExportByName("ws2_32.dll", "WSASend");

let sendHandler = undefined;
let mem = Memory.alloc(1024);

// status
let is_hooked_real = false;
let saved_ecx = undefined;

/**
 * Hash chatId Object
 * @param {object} chatId - chatId to hash
 */
function hashChatId(chatId) {
    return hash(hash(chatId.low)+hash(chatId.high)+hash(chatId.unsigned));
}

/**
 * Deep-clone an object.
 * @param {object} obj - Object to deep-clone.  
 */
function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

function hook_real() {
    Interceptor.attach(ptr(KAKAO_SEND), {
        onEnter: function(args) {
            let cmd = Memory.readCString(ptr(parseInt(args[0])+6));
            // console.log(cmd);
            // console.log(hexdump(args[0], parseInt(args[1])));
            if (cmd == 'WRITE') {
                let bson_data = Memory.readByteArray(ptr(parseInt(args[0]) + 0x16), parseInt(args[1]) - 0x16);
                let bson_data_de = BSON.deserialize(new Buffer(bson_data), {promoteLongs: false});
                let hashed_chatId = hashChatId(bson_data_de.chatId);
                if (bobenc.isBobEncRoom(hashed_chatId)) {
                    let bobencroom = bobenc.getBobEncRoom(hashed_chatId);
                    if (bobenc.checkCompatibleBobEncMsg(bson_data_de.msg)) {
                        // Do something
                        if (bobenc.getCmd(bson_data_de.msg) === bobenc.BOBENC_CMD.KEY_BROADCAST) {
                            bson_data_de.msg = bson_data_de.msg.concat(bobencroom.get_myinfo());
                            let new_bson_data = BSON.serialize(bson_data_de, {promoteLongs: false});
                            let new_bytearray = Array.prototype.slice.call(new_bson_data, 0);
                            Memory.writeInt(ptr(parseInt(args[0]) + 0x12), new_bytearray.length);
                            Memory.writeByteArray(ptr(parseInt(args[0]) + 0x16), new_bytearray);
                            args[1] = ptr(new_bytearray.length + 0x16);
                        }
                    }
                    else {
                        let newmsg = bobencroom.get_encrypted_msg(bson_data_de.msg);
                        newmsg = bobenc.BOBENC_HEADER + bobenc.BOBENC_VERSION + bobenc.BOBENC_CMD.MSG_BROADCAST + newmsg;
                        bson_data_de.msg = newmsg;
                        let new_bson_data = BSON.serialize(bson_data_de, {promoteLongs: false});
                        let new_bytearray = Array.prototype.slice.call(new_bson_data, 0);
                        Memory.writeInt(ptr(parseInt(args[0]) + 0x12), new_bytearray.length);
                        Memory.writeByteArray(ptr(parseInt(args[0]) + 0x16), new_bytearray);
                        args[1] = ptr(new_bytearray.length + 0x16);
                    }
                }
                else if (bobenc.checkCompatibleBobEncMsg(bson_data_de.msg)) {
                    if (bobenc.getCmd(bson_data_de.msg) === bobenc.BOBENC_CMD.START) {
                        // Start session.
                        let new_bobencroom = new bobenc.BobEncRoom(hashed_chatId, uuidv4());
                        bobenc.setBobEncRoom(hashed_chatId, new_bobencroom);
                    }
                }
            }
        }
    });
    Interceptor.attach(ptr(KAKAO_RECV), {
        onEnter: function(args) {
            var buffer = Memory.readByteArray(ptr(args[0]), args[1].toInt32());
            var bson_data_de = BSON.deserialize(new Buffer(buffer), {promoteLongs: false});
            // console.log(JSON.stringify(bson_data_de));
            if (bson_data_de.hasOwnProperty('chatLog')) {
                let hashed_chatId = hashChatId(bson_data_de.chatLog.chatId);
               //  console.log(hashed_chatId)
                if (bobenc.isBobEncRoom(hashed_chatId)) {
                    let bobencroom = bobenc.getBobEncRoom(hashed_chatId);
                    if (bobenc.getCmd(bson_data_de.chatLog.message) === bobenc.BOBENC_CMD.KEY_BROADCAST) {
                        let msg;
                        // console.log(1);
                        try {
                            msg = JSON.parse(bobenc.getMsg(bson_data_de.chatLog.message));
                        }
                        catch (e) { 
                            return; 
                        }
                        if (!msg.hasOwnProperty('uuid') || !msg.hasOwnProperty('key'))
                            return;
                        if (!bobencroom.has_client(msg.uuid)) {
                            bobencroom.add_client(msg.uuid, msg.key);
                        }
                    }
                    else if (bobenc.getCmd(bson_data_de.chatLog.message) === bobenc.BOBENC_CMD.MSG_BROADCAST) {
                        let msg;
                        try {
                            msg = JSON.parse(bobenc.getMsg(bson_data_de.chatLog.message));
                        }
                        catch (e) { 
                            return; 
                        }
                        if (!msg.hasOwnProperty('uuid') || !msg.hasOwnProperty('msgs'))
                            return;
                        let decrypt_msg = bobencroom.get_decrypted_msg(msg);
                        if (decrypt_msg !== null) {
                            bson_data_de.chatLog.message = decrypt_msg;
                            let new_bson_data = BSON.serialize(bson_data_de, {promoteLongs: false});
                            let new_bytearray = Array.prototype.slice.call(new_bson_data, 0);
                            Memory.writeByteArray(ptr(parseInt(args[0])), new_bytearray);
                            args[1] = ptr(new_bson_data.length);
                        }
                    }
                }
            }
        }
    });
}

function init() {
    Interceptor.attach(sendptr, {
        onEnter: function(args) {
            if (!is_hooked_real) {
                console.log('[*] seems like kakaotalk is properly loaded');
                console.log('[*] invoking hook_real()');
                hook_real();
                is_hooked_real = true;
            }
            
        }
    });
}

init();
