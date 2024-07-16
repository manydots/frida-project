// 装备品级
enum ItemRarity {
    common = 0,
    uncommon = 1,
    rare = 2,
    unique = 3,
    epic = 4,
    chronicle = 5
}
// 副本难度
const Difficult = {
    0: '普通级',
    1: '冒险级',
    2: '王者级',
    3: '地狱级',
    4: '英雄级'
};

enum GlobMask {
    FLAG_EQUIP = 0x01, // 装备位
    FLAG_INVEN = 0x02, // 背包
    FLAG_CARGO = 0x04, // 角色仓库
    FLAG_ACC_CARGO = 0x08 // 账号金库
}

// 副职业
enum ExpertJobType {
    None = 0, // 无
    Enchanter = 1, // 附魔师
    Alchemist = 2, // 炼金师
    Disjointer = 3, // 分解师
    DollController = 4 // 控偶师
}

// 获取背包槽中的道具
enum INVENTORY_TYPE {
    BODY = 0, // 身上穿的装备(0-26) 0-9装扮 10-21装备 22宠物 23-25宠物装备
    ITEM = 1, // 物品栏(0-311) 3-8快捷栏 9-56装备栏 57-104消耗品  105-152材料 153-200任务栏 201-248副职业栏 249-311徽章栏
    AVARTAR = 2, // 时装栏(0-104) 0-9已穿戴 10-104背包
    CREATURE = 3 // 宠物装备(0-241) 0-139宠物 140-188宠物装备 189-237宠物消耗
}

// 通知客户端更新背包栏
enum ENUM_ITEMSPACE {
    INVENTORY = 0, // 物品栏
    AVATAR = 1, // 时装栏
    CARGO = 2, // 仓库
    QUIPPED = 3,
    TRADE = 4,
    PRIVATE_STORE = 5,
    MAIL = 6,
    CREATURE = 7, // 宠物栏
    COMPOUND_AVATAR = 8,
    USE_EMBLEM = 9,
    AVATAR_CONVERT = 10,
    ACCOUNT_CARGO = 12 // 账号仓库
}

// 完成角色当前可接的所有任务(仅发送金币/经验/QP等基础奖励 无道具奖励)
enum QUEST_gRADE {
    COMMON_UNIQUE = 5, //任务脚本中[grade]字段对应的常量定义 可以在importQuestScript函数中找到
    NORMALY_REPEAT = 4, //可重复提交的重复任务
    DAILY = 3, //每日任务
    EPIC = 0, //史诗任务
    ACHIEVEMENT = 2 //史诗任务
}

// 怪物攻城活动当前状态
enum VILLAGEATTACK_STATE {
    P1 = 0, // 一阶段
    P2 = 1, // 二阶段
    P3 = 2, // 三阶段
    END = 3 // 活动已结束
}

export { ItemRarity, Difficult, GlobMask, ExpertJobType, INVENTORY_TYPE, ENUM_ITEMSPACE, QUEST_gRADE, VILLAGEATTACK_STATE };
