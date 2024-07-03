// 装备品级
const ItemRarity = {
    common: 0,
    uncommon: 1,
    rare: 2,
    unique: 3,
    epic: 4,
    chronicle: 5
};

const GlobMask = {
    FLAG_EQUIP: 0x01, // 装备位
    FLAG_INVEN: 0x02, // 背包
    FLAG_CARGO: 0x04, // 角色仓库
    FLAG_ACC_CARGO: 0x08 // 账号金库
};

// 副职业
const ExpertJobType = {
    None: 0, // 无
    Enchanter: 1, // 附魔师
    Alchemist: 2, // 炼金师
    Disjointer: 3, // 分解师
    DollController: 4 // 控偶师
};

export { ItemRarity, GlobMask, ExpertJobType };
