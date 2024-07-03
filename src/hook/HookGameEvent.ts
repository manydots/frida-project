import hookType from './HookType';

const _HookGameEvent = {
    // 角色登入登出处理
    userLogout(gm: any): void {
        // 选择角色处理函数 Hook GameWorld::reach_game_world
        Interceptor.attach(ptr(hookType.Reach_GameWord), {
            // 函数入口, 拿到函数参数args
            onEnter: function (args) {
                // 保存函数参数
                this.user = args[1];
                gm.logger(`[Reach_GameWord][user]${this.user}`);
            },
            // 原函数执行完毕, 这里可以得到并修改返回值retval
            onLeave: function (retval) {
                // 消息类型 1绿(私聊)/14管理员(喇叭)/16系统消息
                // 发送频道消息
                gm.api_GameWorld_SendNotiPacketMessage(`[${process.env.loggername}]玩家【${gm.api_CUserCharacInfo_getCurCharacName(this.user)}】上线了`, 14);
                // 给角色发消息问候
                // gm.api_CUser_SendNotiPacketMessage(this.user, `[${process.env.loggername}]玩家【${gm.api_CUserCharacInfo_getCurCharacName(this.user)}】上线了`, 2);
                // 测试弹窗消息（客户端会崩溃，木青1031插件中修复，未测试）
                // gm.SendPacketMessage(this.user, `[弹窗消息]你好啊${gm.api_CUserCharacInfo_getCurCharacName(this.user)}`);
            }
        });
        Interceptor.attach(ptr(hookType.Leave_GameWord), {
            onEnter: function (args) {
                const user = args[0];
                gm.logger(`[Leave_GameWord][user]${user}`);
            },
            onLeave: function (retval) {}
        });
    }
};

export default _HookGameEvent;
