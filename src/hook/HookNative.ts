// NativeFunction
const _HookNative = {
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
    CAccountCargo_GetItemCount: new NativeFunction(ptr(0x0828a794), 'int', ['pointer'], { abi: 'sysv' }),
    GetIntegratedPvPItemAttr: new NativeFunction(ptr(0x084fc5ff), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取GameWorld实例
    G_GameWorld: new NativeFunction(ptr(0x80da3a7), 'pointer', [], { abi: 'sysv' }),
    GameWorld_IsEnchantRevisionChannel: new NativeFunction(ptr(0x082343fc), 'int', ['pointer'], { abi: 'sysv' }),
    // 服务器环境
    G_CEnvironment: new NativeFunction(ptr(0x080cc181), 'pointer', [], { abi: 'sysv' }),
    // 获取当前服务器配置文件名
    CEnvironment_get_file_name: new NativeFunction(ptr(0x80da39a), 'pointer', ['pointer'], { abi: 'sysv' }),

    // 背包道具
    Inven_Item: new NativeFunction(ptr(0x80cb854), 'pointer', ['pointer'], { abi: 'sysv' }),
    std_pair_vector: new NativeFunction(ptr(0x81349d6), 'pointer', ['pointer'], { abi: 'sysv' }),
    std_pair_clear: new NativeFunction(ptr(0x817a342), 'pointer', ['pointer'], { abi: 'sysv' }),
    std_pair_make: new NativeFunction(ptr(0x81b8d41), 'pointer', ['pointer', 'pointer', 'pointer'], { abi: 'sysv' }),
    std_pair_push_back: new NativeFunction(ptr(0x80dd606), 'pointer', ['pointer', 'pointer'], { abi: 'sysv' }),

    WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail: new NativeFunction(
        ptr(0x8556b68),
        'int',
        ['pointer', 'pointer', 'int', 'int', 'int', 'pointer', 'int', 'int', 'int', 'int'],
        { abi: 'sysv' }
    ),
    WongWork_CMailBoxHelper_MakeSystemMultiMailPostal: new NativeFunction(ptr(0x8556a14), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),
    // 城镇瞬移
    GameWorld_move_area: new NativeFunction(ptr(0x86c5a84), 'pointer', ['pointer', 'pointer', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int'], { abi: 'sysv' }),

    // 将协议发给所有在线玩家(慎用! 广播类接口必须限制调用频率, 防止CC攻击)
    // 除非必须使用, 否则改用对象更加明确的CParty::send_to_party/GameWorld::send_to_area
    GameWorld_send_all: new NativeFunction(ptr(0x86c8c14), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    GameWorld_send_all_with_state: new NativeFunction(ptr(0x86c9184), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),
    stAmplifyOption_t_getAbilityType: new NativeFunction(ptr(0x08150732), 'uint8', ['pointer'], { abi: 'sysv' }),
    stAmplifyOption_t_getAbilityValue: new NativeFunction(ptr(0x08150772), 'uint16', ['pointer'], { abi: 'sysv' }),

    // 获取DataManager实例
    G_CDataManager: new NativeFunction(ptr(0x80cc19b), 'pointer', [], { abi: 'sysv' }),
    // 获取装备pvf数据
    CDataManager_find_item: new NativeFunction(ptr(0x835fa32), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),

    // 获取时装管理器
    CInventory_GetAvatarItemMgrR: new NativeFunction(ptr(0x80dd576), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取时装插槽数据
    WongWork_CAvatarItemMgr_getJewelSocketData: new NativeFunction(ptr(0x82f98f8), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),

    // 获取角色状态
    CUser_get_state: new NativeFunction(ptr(0x80da38c), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色账号id
    CUser_get_acc_id: new NativeFunction(ptr(0x80da36e), 'int', ['pointer'], { abi: 'sysv' }),
    // 给角色发消息
    CUser_SendNotiPacketMessage: new NativeFunction(ptr(0x86886ce), 'int', ['pointer', 'pointer', 'int'], { abi: 'sysv' }),
    // 获取角色名字
    CUserCharacInfo_getCurCharacName: new NativeFunction(ptr(0x8101028), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取当前角色id
    CUserCharacInfo_getCurCharacNo: new NativeFunction(ptr(0x80cbc4e), 'int', ['pointer'], { abi: 'sysv' }),
    // 根据账号查找已登录角色
    GameWorld_find_user_from_world_byaccid: new NativeFunction(ptr(0x86c4d40), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    // 本次登录时间
    CUserCharacInfo_GetLoginTick: new NativeFunction(ptr(0x822f692), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色背包
    CUserCharacInfo_getCurCharacInvenW: new NativeFunction(ptr(0x80da28e), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 设置角色虚弱值
    CUserCharacInfo_setCurCharacStamia: new NativeFunction(ptr(0x082f0914), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    // 获取当前玩家所在副本
    getDungeonIdxAfterClear: new NativeFunction(ptr(0x0867cb90), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色所在队伍
    CUser_GetParty: new NativeFunction(ptr(0x0865514c), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取角色上次退出游戏时间
    CUserCharacInfo_getCurCharacLastPlayTick: new NativeFunction(ptr(0x82a66aa), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色等级
    CUserCharacInfo_get_charac_level: new NativeFunction(ptr(0x80da2b8), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取角色当前等级升级所需经验
    CUserCharacInfo_get_level_up_exp: new NativeFunction(ptr(0x0864e3ba), 'int', ['pointer', 'int'], { abi: 'sysv' }),
    // 角色增加经验
    CUser_gain_exp_sp: new NativeFunction(ptr(0x866a3fe), 'int', ['pointer', 'int', 'pointer', 'pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 发送道具
    CUser_AddItem: new NativeFunction(ptr(0x867b6d4), 'int', ['pointer', 'int', 'int', 'int', 'pointer', 'int'], { abi: 'sysv' }),
    // 减少金币
    CInventory_use_money: new NativeFunction(ptr(0x84ff54c), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 增加金币
    CInventory_gain_money: new NativeFunction(ptr(0x84ff29c), 'int', ['pointer', 'int', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 获取角色当前持有金币数量
    CInventory_get_money: new NativeFunction(ptr(0x81347d6), 'int', ['pointer'], { abi: 'sysv' }),

    // 获取背包槽中的道具 INVENTORY_TYPE
    CInventory_GetInvenRef: new NativeFunction(ptr(0x84fc1de), 'pointer', ['pointer', 'int', 'int'], { abi: 'sysv' }),
    // 背包中删除道具(背包指针, 背包类型, 槽, 数量, 删除原因, 记录删除日志)
    CInventory_delete_item: new NativeFunction(ptr(0x850400c), 'int', ['pointer', 'int', 'int', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 道具是否是装备
    Inven_Item_isEquipableItemType: new NativeFunction(ptr(0x08150812), 'int', ['pointer'], { abi: 'sysv' }),

    // 获取道具附加信息
    Inven_Item_get_add_info: new NativeFunction(ptr(0x80f783a), 'int', ['pointer'], { abi: 'sysv' }),

    // 获取道具名
    CItem_getItemName: new NativeFunction(ptr(0x811ed82), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取装备品级
    CItem_getRarity: new NativeFunction(ptr(0x080f12d6), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取装备可穿戴等级
    CItem_getUsableLevel: new NativeFunction(ptr(0x80f12ee), 'int', ['pointer'], { abi: 'sysv' }),
    CItem_getAttachType: new NativeFunction(ptr(0x80f12e2), 'int', ['pointer'], { abi: 'sysv' }),

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
    CItem_GetExpertJobAdditionalExp: new NativeFunction(ptr(0x850d30e), 'int', ['pointer'], { abi: 'sysv' }),

    // 检查背包中道具是否为空
    Inven_Item_isEmpty: new NativeFunction(ptr(0x811ed66), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取背包中道具item_id
    Inven_Item_getKey: new NativeFunction(ptr(0x850d14e), 'int', ['pointer'], { abi: 'sysv' }),
    // 道具是否被锁
    CUser_CheckItemLock: new NativeFunction(ptr(0x8646942), 'int', ['pointer', 'int', 'int'], { abi: 'sysv' }),
    // 道具是否为消耗品
    CItem_is_stackable: new NativeFunction(ptr(0x80f12fa), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取消耗品类型
    CStackableItem_GetItemType: new NativeFunction(ptr(0x8514a84), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取徽章支持的镶嵌槽类型
    CStackableItem_getJewelTargetSocket: new NativeFunction(ptr(0x0822ca28), 'int', ['pointer'], { abi: 'sysv' }),

    CDataManager_find_dungeon: new NativeFunction(ptr(0x0835f9f8), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    // 获取副本名称
    CDungeon_getDungeonName: new NativeFunction(ptr(0x081455a6), 'pointer', ['pointer'], { abi: 'sysv' }),
    // 获取副本id
    CDungeon_get_index: new NativeFunction(ptr(0x080fdcf0), 'int', ['pointer'], { abi: 'sysv' }),

    // 通知客户端道具更新(客户端指针, 通知方式[仅客户端=1, 世界广播=0, 小队=2, war room=3], itemSpace[装备=0, 时装=1], 道具所在的背包槽)
    CUser_SendUpdateItemList: new NativeFunction(ptr(0x867c65a), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    // 通知客户端更新角色身上装备
    CUser_SendNotiPacket: new NativeFunction(ptr(0x0867ba5c), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),

    // 获取队伍中玩家
    CParty_GetUser: new NativeFunction(ptr(0x08145764), 'pointer', ['pointer', 'int'], { abi: 'sysv' }),
    CParty_send_to_party: new NativeFunction(ptr(0x0859d14e), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    // 修复金币异常
    CParty_UseAncientDungeonItems: new NativeFunction(ptr(0x859eac2), 'int', ['pointer', 'pointer', 'pointer', 'pointer'], { abi: 'sysv' }),

    // 获取装备耐久
    CEquipItem_get_endurance: new NativeFunction(ptr(0x0811ed98), 'int', ['pointer'], { abi: 'sysv' }),
    CInventory_GetInvenData: new NativeFunction(ptr(0x084fbf2c), 'int', ['pointer', 'int', 'pointer'], { abi: 'sysv' }),
    CUserCharacInfo_getCurCharacInvenR: new NativeFunction(ptr(0x80da27e), 'pointer', ['pointer'], { abi: 'sysv' }),
    CInventory_get_empty_slot: new NativeFunction(ptr(0x84fb824), 'int', ['pointer', 'int', 'int'], { abi: 'sysv' }),

    // 时装镶嵌数据存盘
    DB_UpdateAvatarJewelSlot_makeRequest: new NativeFunction(ptr(0x843081c), 'pointer', ['int', 'int', 'pointer'], { abi: 'sysv' }),
    // 发包给客户端
    CUser_Send: new NativeFunction(ptr(0x86485ba), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),

    // 测试系统API
    strlen1: new NativeFunction(ptr(0x0807e3b0), 'int', ['pointer'], { abi: 'sysv' }),
    // 获取字符串长度
    strlen: new NativeFunction(Module.getExportByName(null, 'strlen'), 'int', ['pointer'], { abi: 'sysv' }),
    // linux读本地文件
    fopen: new NativeFunction(Module.getExportByName(null, 'fopen'), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    fread: new NativeFunction(Module.getExportByName(null, 'fread'), 'int', ['pointer', 'int', 'int', 'int'], { abi: 'sysv' }),
    fclose: new NativeFunction(Module.getExportByName(null, 'fclose'), 'int', ['int'], { abi: 'sysv' }),

    // 获取系统时间
    CSystemTime_getCurSec: new NativeFunction(ptr(0x80cbc9e), 'int', ['pointer'], { abi: 'sysv' }),
    GlobalData_systemTime: ptr(0x941f714),

    // 线程安全锁
    Guard_Mutex_Guard: new NativeFunction(ptr(0x810544c), 'int', ['pointer', 'pointer'], { abi: 'sysv' }),
    Destroy_Guard_Mutex_Guard: new NativeFunction(ptr(0x8105468), 'int', ['pointer'], { abi: 'sysv' }),

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
    MySQL_blob_to_str: new NativeFunction(ptr(0x83f452a), 'pointer', ['pointer', 'int', 'pointer', 'int'], { abi: 'sysv' })
};

export default _HookNative;
