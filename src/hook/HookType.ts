import _HookNative from './HookNative'; // hook NativeFunction

/**
 *  hook地址枚举(游戏事件)
 *  @param History_Log 捕获玩家游戏日志
 *  @param Reach_GameWorld 玩家上线
 *  @param Leave_GameWorld 玩家下线
 *
 */
enum _HookType {
    History_Log = 0x854f990, // 捕获玩家游戏日志
    Reach_GameWorld = 0x86c4e50, // 玩家上线
    Leave_GameWorld = 0x86c5288 // 玩家下线
}

export const HookNative = _HookNative;
export const HookType = _HookType;
export default _HookType;
