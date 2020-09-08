import sys
import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

jscode = open("frida_hook_lib_native.js", "r", encoding='utf-8').read()
process = frida.get_usb_device().attach('com.coolapk.market')
script = process.create_script(jscode)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()