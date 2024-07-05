import hookType from './HookType';

const _HookGameEvent = {
    /**
     *  角色登入登出处理
     *  @param gm HookEvent实例
     */
    userLogout(gm: any): void {
        // 选择角色处理函数
        Interceptor.attach(ptr(hookType.Reach_GameWorld), {
            // 函数入口, 拿到函数参数args
            onEnter: function (args) {
                // 保存函数参数
                this.user = args[1];
                gm.logger(`[Reach_GameWorld][user]${this.user}`);
            },
            // 原函数执行完毕, 这里可以得到并修改返回值retval
            onLeave: function (retval) {
                // 发送频道消息
                gm.api_GameWorld_SendNotiPacketMessage(`玩家【${gm.api_CUserCharacInfo_getCurCharacName(this.user)}】上线了`, 14);
                // 给角色发问候消息
                // gm.api_CUser_SendNotiPacketMessage(this.user, `Hello ${gm.api_CUserCharacInfo_getCurCharacName(this.user)}`, 2);
            }
        });
        // 角色退出处理函数
        Interceptor.attach(ptr(hookType.Leave_GameWorld), {
            onEnter: function (args) {
                const user = args[0];
                gm.logger(`[Leave_GameWorld][user]${user}`);
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * hook捕获玩家游戏日志
     * @param gm HookEvent实例
     */
    historyLog(gm: any): void {
        // cHistoryTrace::operator()
        Interceptor.attach(ptr(hookType.History_Log), {
            onEnter: function (args) {
                const history_log = args[1].readUtf8String(-1);
                const group = history_log?.split(',');
                const game_event = group ? group[13].slice(1) : null; // 玩家游戏事件 删除多余空格
                gm.logger(`[HistoryLog]${game_event}`);
            },
            onLeave: function (retval) {}
        });
    }
};

export default _HookGameEvent;
