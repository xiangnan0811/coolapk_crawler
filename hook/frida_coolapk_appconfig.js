function printstack() {
    send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

setTimeout(function (){
    Java.perform(function (){
        var appConfig = Java.use('com.coolapk.market.AppConfig');

        appConfig.getAndroidId.implementation = function () {
            console.log('[*] I am in getAndroidId:');
            var androidId = Java.use('java.lang.String').$new();
            
            androidId = this.getAndroidId();
            console.log("[->] getAndroidId:" + androidId);
            printstack();
            return androidId;
        };
    });
});