import { logger } from '../utils/tool';
import hookGameEvent from './HookGameEvent';

// 定义HookEvent类
class _HookEvent {
    static instance: any = null; // 私有静态属性
    private eventHandlers: any = hookGameEvent; // 挂载游戏事件hook

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
