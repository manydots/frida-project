import HookEvent from './hook/HookEvent';
const gm = new HookEvent();

// 加载主功能
function start(): void {
    gm.logger('=== Frida Start ===');

    gm.hook('userLogout');

    gm.logger('=== Frida End ===');
}

/**
 * ===============以下是dp集成frida============
 * frida 官网地址: https://frida.re/
 * frida提供的js api接口文档地址: https://frida.re/docs/javascript-api/
 * 关于dp2支持frida的说明, 请参阅: /dp2/lua/df/frida.lua
 */

// 准备工作
function setup(): void {
    if (process.env.is_dp) {
        handler_communication(); // 注册dp通讯
    }
    start(); // frida自己的配置
}

// 入口点
// int frida_main(lua_State* ls, var char* args);
function frida_main(ls: any, _args: any): number {
    // args是lua调用时传过来的字符串
    // 建议约定lua和js通讯采用json格式
    const args = _args.readUtf8String();
    // 在这里做你需要的事情
    gm.logger(`frida main, args = ${args}`);
    return 0;
}

// 当lua调用js时触发
// int frida_handler(lua_State* ls, int arg1, float arg2, var char* arg3);
function frida_handler(ls: any, arg1: any, arg2: any, _arg3: any): number {
    const arg3 = _arg3.readUtf8String();
    // 如果需要通讯, 在这里编写逻辑
    // 比如: arg1是功能号, arg3是数据内容 (建议json格式)
    // just for test
    dp2_lua_call(arg1, arg2, arg3);
    return 0;
}

// 获取dp2的符号
// void* dp2_frida_resolver(var char* fname);
let __dp2_resolver: any = null;
function dp2_resolver(fname: any): any {
    return __dp2_resolver(Memory.allocUtf8String(fname));
}

// 通讯 (调用lua)
// int lua_call(int arg1, float arg2, var char* arg3);
let __dp2_lua_call: any = null;
function dp2_lua_call(arg1: any, arg2: any, _arg3: any): any {
    let arg3 = null;
    if (_arg3 != null) {
        arg3 = Memory.allocUtf8String(_arg3);
    }
    return __dp2_lua_call(arg1, arg2, arg3);
}

// 注册dp通讯
function handler_communication(): void {
    let addr = Module.getExportByName('libdp2.so', 'dp2_frida_resolver');
    __dp2_resolver = new NativeFunction(addr, 'pointer', ['pointer']);

    addr = dp2_resolver('lua.call');
    __dp2_lua_call = new NativeFunction(addr, 'int', ['int', 'float', 'pointer']);

    addr = dp2_resolver('frida.main');
    Interceptor.replace(addr, new NativeCallback(frida_main, 'int', ['pointer', 'pointer']));

    addr = dp2_resolver('frida.handler');
    Interceptor.replace(addr, new NativeCallback(frida_handler, 'int', ['pointer', 'int', 'float', 'pointer']));

    Interceptor.flush();
    gm.logger('frida setup ok');
}

// 延迟加载
function awake(): void {
    Interceptor.attach(ptr(0x829ea5a), {
        onEnter: function (args) {},
        onLeave: function (retval) {
            gm.logger('=== frida awake load ===');
            setup();
        }
    });
}

rpc.exports = {
    init: function (stage, parameters) {
        gm.logger('frida init ' + stage);
        // 延迟加载
        if (stage == 'early') {
            // 配合dp2.8+使用
            if (process.env.is_dp) {
                setup();
            }
            // frida.js单独使用时
            if (process.env.is_frida) {
                awake();
            }
        } else {
            // 热重载
            gm.logger('=== frida reload ===');
            setup();
        }
    },
    dispose: function () {
        gm.logger('=== frida dispose ===');
    }
};
