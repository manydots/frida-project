import _HookNative from './HookNative'; // hook NativeFunction

/**
 *  hook地址枚举(游戏事件)
 *  @param History_Log 捕获玩家游戏日志
 *  @param Reach_GameWorld 玩家上线
 *  @param Leave_GameWorld 玩家下线
 *  @param Rarity_Extension 稀有度重写
 *  @param Dungeon_Start 进入副本
 *  @param Dungeon_GiveUp 放弃副本
 *  @param Dungeon_Difficult 获取副本难度
 *  @param Dungeon_Mob_Die 副本房间怪物死亡
 *  @param Dungeon_Clear 副本通关
 *  @param Dungeon_Finish 副本完成(翻牌通关经验奖励)
 *  @param CParty_Get_Item 捡取道具
 *
 */
enum _HookType {
    History_Log = 0x854f990, // 捕获玩家游戏日志
    Reach_GameWorld = 0x86c4e50, // 玩家上线
    Leave_GameWorld = 0x86c5288, // 玩家下线
    Rarity_Extension = 0x080f12d6, // 服务端把稀有度超过5 retval.replace(3) 解决需要2个PVF问题

    Dungeon_Start = 0x081c8102, // 进入副本
    Dungeon_GiveUp = 0x081c40b4, // 放弃副本
    Dungeon_Difficult = 0x085a0954, // 获取副本难度
    Dungeon_Mob_Die = 0x085b5a4c, // 副本房间怪物死亡
    Dungeon_Clear = 0x085b2412, // 副本通关(会触发2次???)
    Dungeon_Finish = 0x085ad278, // 副本完成(翻牌通关经验奖励)
    CParty_Get_Item = 0x085b949c // 捡取道具
}

export const HookNative = _HookNative;
export const HookType = _HookType;
export default _HookType;
