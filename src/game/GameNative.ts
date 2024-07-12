/**
 * 游戏Game NativeFunction
 *
 * Party 队伍相关
 * - CParty_GetManager 获取队长
 * - CParty_GetUser 获取队伍中玩家
 * - CParty_GetDungeon 获取副本对象
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
    // 从客户端封包中读取数据
    PacketBuf_get_byte: new NativeFunction(ptr(0x858cf22), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    PacketBuf_get_short: new NativeFunction(ptr(0x858cfc0), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    PacketBuf_get_int: new NativeFunction(ptr(0x858d27e), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    PacketBuf_get_binary: new NativeFunction(ptr(0x858d3b2), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),

    // 服务器组包
    PacketGuard_PacketGuard: new NativeFunction(ptr(0x858dd4c), 'int', ['pointer'], { abi: 'sysv' }),
    InterfacePacketBuf_put_header: new NativeFunction(ptr(0x80cb8fc), 'int', ['pointer', 'int', 'int'], { abi: 'sysv' }),
    InterfacePacketBuf_put_byte: new NativeFunction(ptr(0x80cb920), 'int', ['pointer', 'uint8'], { abi: 'sysv' }),
    InterfacePacketBuf_put_short: new NativeFunction(ptr(0x80d9ea4), 'int', ['pointer', 'uint16'], { abi: 'sysv' }),
    InterfacePacketBuf_put_int: new NativeFunction(ptr(0x80cb93c), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    InterfacePacketBuf_put_binary: new NativeFunction(ptr(0x811df08), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),
    InterfacePacketBuf_finalize: new NativeFunction(ptr(0x80cb958), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    Destroy_PacketGuard_PacketGuard: new NativeFunction(ptr(0x858de80), 'int', ['pointer'], { abi: 'sysv' }),
    InterfacePacketBuf_clear: new NativeFunction(ptr(0x080cb8e6), 'int', ['pointer'], { abi: 'sysv' }),
    InterfacePacketBuf_put_packet: new NativeFunction(ptr(0x0815098e), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    // 线程安全锁
    Guard_Mutex_Guard: new NativeFunction(ptr(0x810544c), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    Destroy_Guard_Mutex_Guard: new NativeFunction(ptr(0x8105468), 'int', ['pointer'], { abi: 'sysv' }),

    // 服务器内置定时器队列
    G_TimerQueue: new NativeFunction(ptr(0x80f647c), 'pointer', [], { abi: 'sysv' }),

    // 获取DataManager实例
    G_CDataManager: new NativeFunction(ptr(0x80cc19b), 'pointer', [], { abi: 'sysv' }),
    // 获取GameWorld实例
    G_GameWorld: new NativeFunction(ptr(0x80da3a7), 'pointer', [], { abi: 'sysv' }),

    // 执行debug命令
    DoUserDefineCommand: new NativeFunction(ptr(0x0820ba90), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    // 设置角色等级(最高70级) 需要临时开GM权限
    DisPatcher_DebugCommandSetLevel: new NativeFunction(ptr(0x0858efde), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),

    // Party
    // 获得队长
    CParty_GetManager: new NativeFunction(ptr(0x08145780), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取队伍中玩家
    CParty_GetUser: new NativeFunction(ptr(0x08145764), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),

    // 返回城镇
    CParty_ReturnToVillage: new NativeFunction(ptr(0x085aca60), 'int', ['pointer'], { abi: 'sysv' }),

    CDataManager_find_dungeon: new NativeFunction(ptr(0x0835f9f8), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    // 获取当前玩家所在副本
    getDungeonIdxAfterClear: new NativeFunction(ptr(0x0867cb90), 'int', ['pointer'], { abi: 'sysv' }),

    // 获取副本名称
    CDungeon_GetName: new NativeFunction(ptr(0x081455a6), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取副本等级
    // CDungeon_GetMinLevel: new NativeFunction(ptr(0x0814559a), 'int', ['pointer'], { abi: 'sysv' }),
    CDungeon_GetMinLevel: new NativeFunction(ptr(0x086c9076), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    // 副本标准等级
    // CDungeon_GetStandardLevel: new NativeFunction(ptr(0x080f9810), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取副本id
    CDungeon_get_index: new NativeFunction(ptr(0x080fdcf0), 'int', ['pointer'], { abi: 'sysv' }),

    // User
    // 获取角色所在队伍
    CUser_GetParty: new NativeFunction(ptr(0x0865514c), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取角色账号id
    CUser_GetAccId: new NativeFunction(ptr(0x080da36e), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取当前角色id
    CUser_GetCharacNo: new NativeFunction(ptr(0x080cbc4e), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色名字
    CUser_GetCharacName: new NativeFunction(ptr(0x08101028), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 设置角色最大等级 int为等级
    CUser_SetUserMaxLevel: new NativeFunction(ptr(0x0868fec8), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    CUser_CalcurateUserMaxLevel: new NativeFunction(ptr(0x0868ff04), 'pointer', ['pointer'], { abi: 'sysv' }),

    // 返回选择角色界面
    CUser_ReturnToSelectCharacList: new NativeFunction(ptr(0x8686fee), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    CUser_SendCmdErrorPacket: new NativeFunction(ptr(0x0867bf42), 'int', ['pointer', 'int', 'uint8'], { abi: 'sysv' })
};

export default GameNative;
