var BSON = require('BSON');
var base64 = require('base-64');
var utf8 = require('utf8');

var sendptr = Module.findExportByName("ws2_32.dll", "WSASend");
var mysend = new NativeFunction(ptr(0xD1FE20), 'int', ['pointer', 'int', 'int']);
var alloc = Memory.alloc(1024);
alloc.writeByteArray([0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x52, 0x49, 0x54, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x12, 0x63, 0x68, 0x61, 0x74, 0x49, 0x64, 0x00, 0x5d, 0x84, 0xfb, 0xeb, 0x43, 0x95, 0x00, 0x00, 0x02, 0x6d, 0x73, 0x67, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00, 0x12, 0x6d, 0x73, 0x67, 0x49, 0x64, 0x00, 0xc2, 0x9f, 0x13, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x10, 0x74, 0x12, 0x6d, 0x61, 0x78, 0x00, 0x00, 0x50, 0x8c, 0x5d, 0xaa, 0xf0, 0x1c, 0x1e, 0x00])
console.log(alloc);

Interceptor.attach(ptr(0xD1FE20), {
   onEnter: function(args) {
      console.log(args[0], args[1], args[2]);
      var cmd = Memory.readCString(ptr(parseInt(args[0]) +6));

      if (cmd == "WRITE") {
         var bson_data = Memory.readByteArray(ptr(parseInt(args[0]) + 0x16), parseInt(args[1]) - 0x16);
         var bson_data_de = BSON.deserialize(new Buffer(bson_data), {promoteLongs: false});
         console.log(JSON.stringify(bson_data_de));
         bson_data_de.msg = '[B64] ' + base64.encode(utf8.encode(bson_data_de.msg));
         var new_bson_data = BSON.serialize(bson_data_de);
         var newbyte = [];
         for(var i = 0; i < new_bson_data.length; i++) {
            newbyte.push(new_bson_data[i]);
         }
         console.log(newbyte);
         Memory.writeInt(ptr(parseInt(args[0])+0x12), new_bson_data.length);
         Memory.writeByteArray(ptr(parseInt(args[0])+0x16), newbyte);
         args[1] = ptr(new_bson_data.length + 0x16);
      }
   }
});

Interceptor.attach(ptr(0xD3AF70), {
   onEnter: function(args) {
      console.log("RECV");
      // console.log(Memory.readByteArray(ptr(args[0]), parseInt(args[1])));
      var buffer = Memory.readByteArray(ptr(args[0]), args[1].toInt32());
      var bson_data_de = BSON.deserialize(new Buffer(buffer), {promoteLongs: false});
      console.log(JSON.stringify(bson_data_de));
      if (bson_data_de.chatLog != undefined) {
         bson_data_de.chatLog.message = '[BLIND]';
         var new_bson_data = BSON.serialize(bson_data_de);
         var newbyte = [];
         for(var i = 0; i < new_bson_data.length; i++) {
            newbyte.push(new_bson_data[i]);
         }
         Memory.writeByteArray(ptr(parseInt(args[0])), newbyte);
         args[1] = ptr(new_bson_data.length);
      }
   }
})


/**
Thread.backtrace를 통해 적절한 encrypt전 메s시지 확인
Interceptor.attach(ptr({address}) , {
   onEnter: function(args) {
      console.log("WSA send! ", args[0], args[1], args[2]);
   }
});

**/