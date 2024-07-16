// import { HookNative } from './HookType';
// import { VILLAGEATTACK_STATE } from '../enum/enum';
import { logger } from '../utils/tool';
import hookGameEvent from './HookGameEvent';

// 定义HookEvent类
class _HookEvent {
    static instance: any = null; // 私有静态属性
    private eventHandlers: any = hookGameEvent; // 挂载游戏事件hook

    // 怪物攻城活动数据
    // public villageAttackEventInfo: any = {
    //     state: VILLAGEATTACK_STATE.END, // 活动当前状态
    //     score: 0, //当前阶段频道内总PT
    //     start_time: 0, //活动开始时间(UTC)
    //     difficult: 0, //活动难度(0-4)
    //     next_village_monster_id: 0, //下次刷新的攻城怪物id
    //     last_killed_monster_id: 0, //上次击杀的攻城怪物id
    //     p2_last_killed_monster_time: 0, //P2阶段上次击杀攻城怪物时间
    //     p2_kill_combo: 0, //P2阶段连续击杀相同攻城怪物数量
    //     gbl_cnt: 0, //城镇中存活的GBL主教数量
    //     defend_success: 0, //怪物攻城活动防守成功
    //     user_pt_info: {} //角色个人pt数据
    // };

    // 私有构造函数，防止外部通过new关键字创建实例
    private constructor() {}

    /**
     * 获取HookEvent实例(单例模式)
     */
    static getInstance(): any {
        if (!_HookEvent.instance) {
            _HookEvent.instance = new _HookEvent();
        }
        return _HookEvent.instance;
    }

    /**
     * 延迟delay执行函数
     * @param func Function
     * @param args 参数列表
     * @param delay 延迟时间
     */
    api_runScript_delay(func: Function, delay: number, ...args: any[]): void {
        let _self = this;
        setTimeout(() => {
            func.call(_self, args);
        }, delay);
    }

    // // 从数据库载入怪物攻城活动数据
    // event_villageattack_load_from_db(): void {
    //     if (this.api_MySQL_exec(this.mysql_frida, "select event_info from game_event where event_id = 'villageattack';")) {
    //         if (HookNative.MySQL_get_n_rows(this.mysql_frida) == 1) {
    //             HookNative.MySQL_fetch(this.mysql_frida);
    //             const info = this.api_MySQL_get_str(this.mysql_frida, 0);
    //             this.villageAttackEventInfo = JSON.parse(info);
    //         }
    //     }
    // }

    // // 怪物攻城活动数据存档
    // event_villageattack_save_to_db(): void {
    //     this.api_MySQL_exec(this.mysql_frida, `replace into game_event (event_id, event_info) values ('villageattack', '${JSON.stringify(this.villageAttackEventInfo)}');`);
    // }

    /**
     * hook函数 Interceptor.attach
     * @param gameEvent hook函数名称
     * @param params 拓展参数
     */
    hook(gameEvent: string, params?: object): void {
        const _self = this;
        if (typeof this.eventHandlers[gameEvent] === 'function') {
            this.eventHandlers[gameEvent](params ?? {}, _self);
            logger(`[hook][${gameEvent}]`);
        } else {
            console.error(`No handler found for event: ${gameEvent}`);
        }
    }
}

export default _HookEvent;
