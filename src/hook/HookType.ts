import _HookNative from './HookNative'; // hook NativeFunction

// hook地址枚举
const _HookType = {
    // 游戏事件
    Reach_GameWord: 0x86c4e50, // 玩家上线
    Leave_GameWord: 0x86c5288 // 玩家下线
};

export const HookNative = _HookNative;
export const HookType = _HookType;
export default _HookType;
