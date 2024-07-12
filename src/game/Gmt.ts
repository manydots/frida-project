/**
 * 系统工具类
 */
import GameNative from './GameNative';

export default class Gmt {
    static instance: any = null; // 私有静态属性

    public global_config: any = {};
    public timer_dispatcher_list: any = []; // 需要在dispatcher线程执行的任务队列(热加载后会被清空)

    // 私有构造函数，防止外部通过new关键字创建实例
    private constructor() {}

    /**
     * 获取HookEvent实例(单例模式)
     */
    static getInstance(): any {
        if (!Gmt.instance) {
            Gmt.instance = new Gmt();
        }
        return Gmt.instance;
    }

    /**
     * 申请锁(申请后务必手动释放!!!)
     */
    Guard_Mutex_Guard(): any {
        const a1 = Memory.alloc(100);
        GameNative.Guard_Mutex_Guard(a1, GameNative.G_TimerQueue().add(16));
        return a1;
    }

    /**
     * 在dispatcher线程执行(args为函数f的参数组成的数组, 若f无参数args可为null)
     * @param func Function
     * @param args 参数列表
     */
    scheduleOnMainThread(func: Function, args: any): void {
        let _self = this;
        // 线程安全
        const guard = this.Guard_Mutex_Guard();
        this.timer_dispatcher_list.push([func.bind(_self), args]); // 改变this指向
        GameNative.Destroy_Guard_Mutex_Guard(guard);
        return;
    }
}
