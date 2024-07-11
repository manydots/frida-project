/**
 * 游戏Game NativeFunction
 *
 * Party 队伍相关
 * - CParty_GetManager 获取队长
 * - CParty_GetUser 获取队伍中玩家
 * - CParty_ReturnToVillage 返回城镇
 *
 * User 角色相关
 * - CUser_GetParty 获取角色所在队伍
 * - CUser_GetAccId 获取角色账号id
 * - CUser_GetCharacNo 获取当前角色id
 * - CUser_GetCharacName 获取角色名字
 *
 */
const GameNative = {
    // Party
    // 获得队长
    CParty_GetManager: new NativeFunction(ptr(0x08145780), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取队伍中玩家
    CParty_GetUser: new NativeFunction(ptr(0x08145764), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    // 返回城镇
    CParty_ReturnToVillage: new NativeFunction(ptr(0x085aca60), 'int', ['pointer'], { abi: 'sysv' }),

    // User
    // 获取角色所在队伍
    CUser_GetParty: new NativeFunction(ptr(0x0865514c), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取角色账号id
    CUser_GetAccId: new NativeFunction(ptr(0x080da36e), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取当前角色id
    CUser_GetCharacNo: new NativeFunction(ptr(0x080cbc4e), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色名字
    CUser_GetCharacName: new NativeFunction(ptr(0x08101028), 'pointer', ['pointer'], { abi: 'sysv' })
};

export default GameNative;
