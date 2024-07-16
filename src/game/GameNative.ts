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

    // 获取包名
    Get_PacketName: new NativeFunction(ptr(0x082a2112), 'pointer', ['int', 'int'], { abi: 'sysv' }),
    // 获取系统时间
    CSystemTime_getCurSec: new NativeFunction(ptr(0x80cbc9e), 'int', ['pointer'], { abi: 'sysv' }),
    GlobalData_systemTime: ptr(0x941f714),

    // 获取DataManager实例
    G_CDataManager: new NativeFunction(ptr(0x80cc19b), 'pointer', [], { abi: 'sysv' }),
    // 获取装备pvf数据
    CDataManager_find_item: new NativeFunction(ptr(0x835fa32), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    // 获取GameWorld实例
    G_GameWorld: new NativeFunction(ptr(0x80da3a7), 'pointer', [], { abi: 'sysv' }),
    GameWorld_IsEnchantRevisionChannel: new NativeFunction(ptr(0x082343fc), 'int', ['pointer'], { abi: 'sysv' }),
    // 服务器环境
    G_CEnvironment: new NativeFunction(ptr(0x080cc181), 'pointer', [], { abi: 'sysv' }),
    get_server_group: new NativeFunction(ptr(0x08106ce0), 'pointer', [], { abi: 'sysv' }),
    // 获取当前服务器配置文件名
    CEnvironment_get_file_name: new NativeFunction(ptr(0x80da39a), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 城镇瞬移
    GameWorld_Move_Area: new NativeFunction(ptr(0x86c5a84), 'pointer', ['pointer', 'pointer', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int'], { abi: 'sysv' }),

    // 将协议发给所有在线玩家(慎用! 广播类接口必须限制调用频率, 防止CC攻击)
    // 除非必须使用, 否则改用对象更加明确的CParty::send_to_party/GameWorld::send_to_area
    GameWorld_send_all: new NativeFunction(ptr(0x86c8c14), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    GameWorld_send_all_with_state: new NativeFunction(ptr(0x86c9184), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),

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
    // 发送道具
    CUser_AddItem: new NativeFunction(ptr(0x867b6d4), 'int', ['pointer', 'int', 'int', 'int', 'pointer', 'int'], { abi: 'sysv' }),
    // 角色增加经验
    CUser_gain_exp_sp: new NativeFunction(ptr(0x866a3fe), 'int', ['pointer', 'int', 'pointer', 'pointer', 'int', 'int', 'int'], { abi: 'sysv' }),

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
    CUser_Send: new NativeFunction(ptr(0x86485ba), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),

    // 获取角色背包
    CUser_getCurCharacInvenW: new NativeFunction(ptr(0x80da28e), 'pointer', ['pointer'], { abi: 'sysv' }),
    CUser_getCurCharacInvenR: new NativeFunction(ptr(0x80da27e), 'pointer', ['pointer'], { abi: 'sysv' }),

    // 获取装备耐久
    CEquipItem_get_endurance: new NativeFunction(ptr(0x0811ed98), 'int', ['pointer'], { abi: 'sysv' }),
    CInventory_GetInvenData: new NativeFunction(ptr(0x084fbf2c), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    CInventory_get_empty_slot: new NativeFunction(ptr(0x84fb824), 'int', ['pointer', 'int', 'int'], { abi: 'sysv' }),

    // 背包道具
    Inven_Item: new NativeFunction(ptr(0x80cb854), 'pointer', ['pointer'], { abi: 'sysv' }),
    std_pair_vector: new NativeFunction(ptr(0x81349d6), 'pointer', ['pointer'], { abi: 'sysv' }),
    std_pair_clear: new NativeFunction(ptr(0x817a342), 'pointer', ['pointer'], { abi: 'sysv' }),
    std_pair_make: new NativeFunction(ptr(0x81b8d41), 'pointer', ['pointer', 'pointer', 'pointer'], { abi: 'sysv' }),
    std_pair_push_back: new NativeFunction(ptr(0x80dd606), 'pointer', ['pointer', 'pointer'], { abi: 'sysv' }),

    WongWork_CMailBoxHelper_MakeSystemMultiMailPostal: new NativeFunction(ptr(0x8556a14), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),
    WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail: new NativeFunction(
        ptr(0x8556b68),
        'int',
        ['pointer', 'pointer', 'int', 'int', 'int', 'pointer', 'int', 'int', 'int', 'int'],
        { abi: 'sysv' }
    ),
    // 点券充值
    WongWork_IPG_CIPGHelper_IPGInput: new NativeFunction(
        ptr(0x80ffca4),
        'int',
        ['pointer', 'pointer', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        { abi: 'sysv' }
    ),
    // 同步点券数据库
    WongWork_IPG_CIPGHelper_IPGQuery: new NativeFunction(ptr(0x8100790), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    // 代币充值
    WongWork_IPG_CIPGHelper_IPGInputPoint: new NativeFunction(ptr(0x80fffc0), 'int', ['pointer', 'pointer', 'int', 'int', 'pointer', 'pointer'], { abi: 'sysv' }),

    // 分解机参数:角色 位置 背包类型  239  角色（谁的） 0xFFFF
    DisPatcher_DisJointItem_disjoint: new NativeFunction(ptr(0x81f92ca), 'int', ['pointer', 'int', 'int', 'int', 'pointer', 'int'], { abi: 'sysv' }),
    // 分解机用户的状态 参数 用户 239 背包类型 位置
    CUser_GetCurCharacExpertJob: new NativeFunction(ptr(0x0822f8d4), 'int', ['pointer'], { abi: 'sysv' }),
    // 副职业类型
    CUser_GetCurCharacExpertJobType: new NativeFunction(ptr(0x0822f894), 'int', ['pointer'], { abi: 'sysv' }),
    // 副职业经验
    CUser_GetCurCharacExpertJobExp: new NativeFunction(ptr(0x08375026), 'int', ['pointer'], { abi: 'sysv' }),

    // 检查背包中道具是否为空
    Inven_Item_isEmpty: new NativeFunction(ptr(0x811ed66), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取背包中道具item_id
    Inven_Item_getKey: new NativeFunction(ptr(0x850d14e), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取背包槽中的道具 INVENTORY_TYPE
    CInventory_GetInvenRef: new NativeFunction(ptr(0x84fc1de), 'pointer', ['pointer', 'int', 'int'], { abi: 'sysv' }),
    // 背包中删除道具(背包指针, 背包类型, 槽, 数量, 删除原因, 记录删除日志)
    CInventory_delete_item: new NativeFunction(ptr(0x850400c), 'int', ['pointer', 'int', 'int', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 道具是否是装备
    Inven_Item_isEquipableItemType: new NativeFunction(ptr(0x08150812), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取道具附加信息
    Inven_Item_get_add_info: new NativeFunction(ptr(0x80f783a), 'int', ['pointer'], { abi: 'sysv' }),
    // 装备强化/增幅
    Inven_Item_IncUpgrade: new NativeFunction(ptr(0x0854b4be), 'int', ['pointer'], { abi: 'sysv' }),

    // 获取装备魔法封印等级
    CEquipItem_GetRandomOptionGrade: new NativeFunction(ptr(0x8514e6e), 'int', ['pointer'], { abi: 'sysv' }),
    CEquipItem_GetUsableEquipmentType: new NativeFunction(ptr(0x0832e036), 'int', ['pointer'], { abi: 'sysv' }),
    CEquipItem_GetSubType: new NativeFunction(ptr(0x833eecc), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取道具名
    CItem_getItemName: new NativeFunction(ptr(0x811ed82), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取装备品级
    CItem_getRarity: new NativeFunction(ptr(0x080f12d6), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取装备可穿戴等级
    CItem_GetUsableLevel: new NativeFunction(ptr(0x80f12ee), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetAttachType: new NativeFunction(ptr(0x80f12e2), 'int', ['pointer'], { abi: 'sysv' }),

    CItem_GetIndex: new NativeFunction(ptr(0x8110c48), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetGrade: new NativeFunction(ptr(0x8110c54), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetPrice: new NativeFunction(ptr(0x822c84a), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetGenRate: new NativeFunction(ptr(0x822c84a), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetNeedLevel: new NativeFunction(ptr(0x8545fda), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetItemGroupName: new NativeFunction(ptr(0x80f1312), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetUpSkillType: new NativeFunction(ptr(0x8545fcc), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetGetExpertJobCompoundMaterialVariation: new NativeFunction(ptr(0x850d292), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetExpertJobCompoundRateVariation: new NativeFunction(ptr(0x850d2aa), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetExpertJobCompoundResultVariation: new NativeFunction(ptr(0x850d2c2), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetExpertJobSelfDisjointBigWinRate: new NativeFunction(ptr(0x850d2de), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetExpertJobSelfDisjointResultVariation: new NativeFunction(ptr(0x850d2f6), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_GetExpertJobAdditionalExp: new NativeFunction(ptr(0x850d30e), 'int', ['pointer'], { abi: 'sysv' })
};

export default GameNative;
