import sys
import frida

oncreate_script = """
// 打印调用堆栈
function printstack() {
    send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

// array 转成 string
function array2string(array) {
    var buffer = Java.array('byte', array);
    // console.log(buffer.length);
    var result = "";
    for (var i = 0; i < buffer.length; i++) {
        result += (String.fromCharCode(buffer[i]));
    }
    return result;
}

Java.perform(function (){
    var appConfig = Java.use('com.coolapk.market.AppConfig');

    appConfig.getAndroidId.implementation = function () {
        send('I am in getAndroidId:');
        var androidId = Java.use('java.lang.String');
        
        androidId = this.getAndroidId();
        send("getAndroidId:" + androidId);
        // printstack();
        return androidId;
    };

    appConfig.getImeiOrMeid.implementation = function () {
        send('I am in getImeiOrMeid:');
        var imeiOrMeid = Java.use('java.lang.String');
        
        imeiOrMeid = this.getImeiOrMeid();
        send("getImeiOrMeid:" + imeiOrMeid);
        // printstack();
        return imeiOrMeid;
    };

    appConfig.getImsi.implementation = function () {
        send('I am in getImsi:');
        var imsi = Java.use('java.lang.String');
        
        imsi = this.getImsi();
        send("getImsi:" + imsi);
        // printstack();
        return imsi;
    };

    appConfig.getMacAddress.implementation = function () {
        send('I am in getMacAddress:');
        var macAddress = Java.use('java.lang.String');
        
        macAddress = this.getMacAddress();
        send("getMacAddress:" + macAddress);
        // printstack();
        return macAddress;
    };

    var Base64 = Java.use("android.util.Base64")
    Base64.encodeToString.overload('[B', 'int').implementation = function (args1, args2) {
        send('I am in encodeToString:');
        
        send("encodeToString ori:" + array2string(args1));
        // printstack();
        return Base64.encodeToString(args1, args2);
    };
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


# APP启动后hook
device = frida.get_usb_device()
process = device.attach('com.coolapk.market')
script = process.create_script(oncreate_script)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
