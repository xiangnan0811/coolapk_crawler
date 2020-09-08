var getAuthString_absulate_addr = Module.getExportByName("libnative-lib.so", "getAuthString");
var native_lib_base_addr = parseInt(getAuthString_absulate_addr) - parseInt('0x66500');
send('native_lib_base_addr: ' + ptr(native_lib_base_addr));

// 用libnative-lib.so基地址加上MD5:MD5()的偏移量 就是MD5:MD5()在内存中的地址
// md5_init_address 是int型
var md5_init_address = ptr(native_lib_base_addr + parseInt('0x32168'));
send('md5_init_address: ' + md5_init_address);

// hook MD5::MD5()
try{
    Interceptor.attach(md5_init_address,
    {
        onEnter: function (args) {
            send("md5_init--open(" + args[0] + "," + args[1] + ")");
            send("md5_init--open(" + Memory.readUtf8String(args[0]) + "," + args[1] + ")");
        },
        onLeave: function (retval) {
            send("md5_init retval: " + retval);
        }
    });
}
catch (error) {
    console.log(error);
}

// hook b64_encode()
var b64_encode_addr = ptr(native_lib_base_addr + parseInt('0x31DB8'));
send("b64_encode_addr: " + b64_encode_addr);
Interceptor.attach(b64_encode_addr,
    {
        onEnter: function (args) {
            send("b64_encode ori: " + Memory.readUtf8String(args[0]));
        },
        onLeave: function (retval) {
            send("b64_encode retval: " + Memory.readUtf8String(retval));
        }
    }
);
