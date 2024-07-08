var path = require('path');
var fs = require('fs');
var records = require('./records');

var obj = {};
// var str1 = ['Party', 'Battle', 'Dungeon', 'User'];
var arr = [];
// '0x08130fa8': '_ZN12advancealtar7Manager10giveUpGameEP5CUser',
var str1 = ['dungeon_clear']; //  DUNGEON_CLEAR EnterDungeon leave_game_world
// 加入队伍 join_user
/**
 * 离开队伍 leave_user
 * ["0x081c4256"] = "_ZN21DisPatcher_LeaveParty7processEP5CUserR8MSG_BASER9ParamBase",
 * ["0x0859c114"] = "_ZN6CParty10leave_userEP5CUser20ENUM_PARTY_INFO_TYPE",
 *
 * 副本通关 DUNGEON_CLEAR PlayResult
 * ["0x08636398"] = "_ZN18TimerSetPlayResult12dispatch_sigEiij",
 * ["0x085b2412"] = "_ZN6CParty13SetPlayResultEP5CUser",
 * ["0x085ab736"] = "_ZN6CParty13dungeon_clearEv",
 * 
 * 副本房间清理完成 (开门) CLEAR_MAP
 */

Object.entries(records).forEach(([key, value]) => {
    if (arrayIncludes(value)) {
        obj[key] = value || 'None';
        arr.push(key);
    }
});

fs.writeFile(path.join(__dirname, 'filter.address.js'), `var address = ${JSON.stringify(obj)}; module.exports = address;`, (err) => {
    if (err) throw err;
    console.log('address文件已被保存');
});

var fstr = [];
arr.forEach((addr) => {
    fstr.push(
        `
    // ptr(${addr})
    Interceptor.attach(ptr(${addr}), {
        onEnter: function (args) {
            // this.user = args[1];
            console.log("${addr}");
        },
        onLeave: function (retval) {}
    });
    `
    );
});

// 模糊搜索基址并Interceptor.attach
fs.writeFile(
    path.join(__dirname, 'filter.attach.js'),
    `// 模糊搜索基址并Interceptor.attach
    function debugCode() {
        ${fstr.join('')}
    };`,
    (err) => {
        if (err) throw err;
        console.log('attach文件已被保存');
    }
);

function arrayIncludes(value) {
    let _value = value?.toLocaleLowerCase();
    let result = false;
    str1.forEach((str) => {
        if (_value.includes(str?.toLocaleLowerCase())) {
            result = true;
        }
    });
    return result;
}
