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
    // 线程安全锁
    Guard_Mutex_Guard: new NativeFunction(ptr(0x810544c), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    Destroy_Guard_Mutex_Guard: new NativeFunction(ptr(0x8105468), 'int', ['pointer'], { abi: 'sysv' }),
    // 执行debug命令
    DoUserDefineCommand: new NativeFunction(ptr(0x0820ba90), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    // 设置角色等级(最高70级) 需要临时开GM权限
    DisPatcher_DebugCommandSetLevel: new NativeFunction(ptr(0x0858efde), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),

    // 获取字符串长度
    strlen: new NativeFunction(Module.getExportByName(null, 'strlen'), 'int', ['pointer'], { abi: 'sysv' }),
    // linux读本地文件
    fopen: new NativeFunction(Module.getExportByName(null, 'fopen'), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    fread: new NativeFunction(Module.getExportByName(null, 'fread'), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    fclose: new NativeFunction(Module.getExportByName(null, 'fclose'), 'int', ['int'], { abi: 'sysv' }),
    // 服务器内置定时器队列
    G_TimerQueue: new NativeFunction(ptr(0x80f647c), 'pointer', [], { abi: 'sysv' }),

    // MYSQL操作
    // 游戏中已打开的数据库索引(游戏数据库非线程安全 谨慎操作)
    DBMgr_GetDBHandle: new NativeFunction(ptr(0x83f523e), 'pointer', ['pointer', 'int', 'int'], { abi: 'sysv' }),
    MySQL_MySQL: new NativeFunction(ptr(0x83f3ac8), 'pointer', ['pointer'], { abi: 'sysv' }),
    MySQL_init: new NativeFunction(ptr(0x83f3ce4), 'int', ['pointer'], { abi: 'sysv' }),
    MySQL_open: new NativeFunction(ptr(0x83f4024), 'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer'], { abi: 'sysv' }),
    MySQL_close: new NativeFunction(ptr(0x83f3e74), 'int', ['pointer'], { abi: 'sysv' }),
    MySQL_set_query_2: new NativeFunction(ptr(0x83f41c0), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    MySQL_set_query_3: new NativeFunction(ptr(0x83f41c0), 'int', ['pointer', 'pointer', 'pointer'], { abi: 'sysv' }),
    MySQL_set_query_4: new NativeFunction(ptr(0x83f41c0), 'int', ['pointer', 'pointer', 'int', 'int'], { abi: 'sysv' }),
    MySQL_set_query_5: new NativeFunction(ptr(0x83f41c0), 'int', ['pointer', 'pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    MySQL_set_query_6: new NativeFunction(ptr(0x83f41c0), 'int', ['pointer', 'pointer', 'int', 'int', 'int', 'int'], { abi: 'sysv' }),
    MySQL_exec: new NativeFunction(ptr(0x83f4326), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    MySQL_exec_query: new NativeFunction(ptr(0x083f5348), 'int', ['pointer'], { abi: 'sysv' }),
    MySQL_get_n_rows: new NativeFunction(ptr(0x80e236c), 'int', ['pointer'], { abi: 'sysv' }),
    MySQL_fetch: new NativeFunction(ptr(0x83f44bc), 'int', ['pointer'], { abi: 'sysv' }),
    MySQL_get_int: new NativeFunction(ptr(0x811692c), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    MySQL_get_short: new NativeFunction(ptr(0x0814201c), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    MySQL_get_uint: new NativeFunction(ptr(0x80e22f2), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    MySQL_get_ulonglong: new NativeFunction(ptr(0x81754c8), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    MySQL_get_ushort: new NativeFunction(ptr(0x8116990), 'int', ['pointer'], { abi: 'sysv' }),
    MySQL_get_float: new NativeFunction(ptr(0x844d6d0), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    MySQL_get_binary: new NativeFunction(ptr(0x812531a), 'int', ['pointer', 'int', 'pointer', 'int'], { abi: 'sysv' }),
    MySQL_get_binary_length: new NativeFunction(ptr(0x81253de), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    MySQL_get_str: new NativeFunction(ptr(0x80ecdea), 'int', ['pointer', 'int', 'pointer', 'int'], { abi: 'sysv' }),
    MySQL_blob_to_str: new NativeFunction(ptr(0x83f452a), 'pointer', ['pointer', 'int', 'pointer', 'int'], { abi: 'sysv' }),

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

    // 获取DataManager实例
    G_CDataManager: new NativeFunction(ptr(0x80cc19b), 'pointer', [], { abi: 'sysv' }),
    // 获取GameWorld实例
    G_GameWorld: new NativeFunction(ptr(0x80da3a7), 'pointer', [], { abi: 'sysv' }),

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
    // 获取角色等级
    CUser_GetCharacLevel: new NativeFunction(ptr(0x80da2b8), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色职业
    CUser_GetCharacJob: new NativeFunction(ptr(0x080fdf20), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色转职职业
    CUser_GetCharacGrowType: new NativeFunction(ptr(0x0815741c), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色觉醒职业
    CUser_GetCharacSecondGrowType: new NativeFunction(ptr(0x0822f23c), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色已用疲劳值
    CUser_GetFatigue: new NativeFunction(ptr(0x08657766), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色最大疲劳值
    CUser_GetMaxFatigue: new NativeFunction(ptr(0x08657804), 'int', ['pointer'], { abi: 'sysv' }),
    // 设置角色最大等级 int为等级
    CUser_SetUserMaxLevel: new NativeFunction(ptr(0x0868fec8), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    CUser_CalcurateUserMaxLevel: new NativeFunction(ptr(0x0868ff04), 'pointer', ['pointer'], { abi: 'sysv' }),

    // 设置角色虚弱值
    CUser_SetCurCharacStamina: new NativeFunction(ptr(0x082f0914), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    // 获取角色当前城镇
    CUser_GetCurCharacVill: new NativeFunction(ptr(0x08645564), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色当前区域
    CUser_GetArea: new NativeFunction(ptr(0x086813be), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    // 获取角色X轴坐标
    CUser_GetPosX: new NativeFunction(ptr(0x0813492c), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色Y轴坐标
    CUser_GetPosY: new NativeFunction(ptr(0x0813493c), 'int', ['pointer'], { abi: 'sysv' }),

    // 通知客户端道具更新(客户端指针, 通知方式[仅客户端=1, 世界广播=0, 小队=2, war room=3], itemSpace[装备=0, 时装=1], 道具所在的背包槽)
    CUser_SendUpdateItemList: new NativeFunction(ptr(0x867c65a), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 通知客户端更新背包栏
    CUser_SendItemSpace: new NativeFunction(ptr(0x865db6c), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    // 给角色发消息
    CUser_SendNotiPacketMessage: new NativeFunction(ptr(0x86886ce), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),

    // 获取角色状态
    CUser_GetState: new NativeFunction(ptr(0x80da38c), 'int', ['pointer'], { abi: 'sysv' }),
    // 通知客户端角色属性更新
    CUser_SendNotiPacket: new NativeFunction(ptr(0x867ba5c), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 获取账号金库
    CUser_GetAccountCargo: new NativeFunction(ptr(0x0822fc22), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 重置异界/极限祭坛次数
    CUser_DimensionInoutUpdate: new NativeFunction(ptr(0x8656c12), 'int', ['pointer', 'int', 'int'], { abi: 'sysv' }),
    // 道具是否被锁
    CUser_CheckItemLock: new NativeFunction(ptr(0x8646942), 'int', ['pointer', 'int', 'int'], { abi: 'sysv' }),

    // 返回选择角色界面
    CUser_ReturnToSelectCharacList: new NativeFunction(ptr(0x8686fee), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    CUser_SendCmdErrorPacket: new NativeFunction(ptr(0x0867bf42), 'int', ['pointer', 'int', 'uint8'], { abi: 'sysv' }),
    // 发包给客户端
    CUser_Send: new NativeFunction(ptr(0x86485ba), 'int', ['pointer', 'pointer'], { abi: 'sysv' })
};

export default GameNative;
