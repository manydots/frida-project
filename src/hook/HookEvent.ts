import { HookNative } from './HookType';
import hookGameEvent from './HookGameEvent';

// 定义HookEvent类
class _HookEvent {
    static readonly INVENTORY_TYPE_ITEM: number = 1; // 物品栏
    static readonly INVENTORY_TYPE_AVARTAR: number = 2; // 时装栏
    private eventHandlers: any = hookGameEvent;
    global_config: any = {};
    timer_dispatcher_list: any = []; // 需要在dispatcher线程执行的任务队列(热加载后会被清空)

    // 构造函数，用于初始化对象
    constructor() {}

    /**
     * 服务器组包
     * @returns packet_guard
     */
    api_PacketGuard_PacketGuard(): any {
        const packet_guard = Memory.alloc(0x20000);
        HookNative.PacketGuard_PacketGuard(packet_guard);
        return packet_guard;
    }

    /**
     * 发送字符串给客户端
     * @param packet_guard packet_guard
     * @param s
     */
    api_InterfacePacketBuf_put_string(packet_guard: any, s: any): void {
        const p = Memory.allocUtf8String(s);
        const len = HookNative.strlen(p);
        HookNative.InterfacePacketBuf_put_int(packet_guard, len);
        HookNative.InterfacePacketBuf_put_binary(packet_guard, p, len);
        return;
    }

    /**
     * 从客户端封包中读取数据(失败会抛异常, 调用方必须做异常处理)
     * @param packet_buf
     * @returns data.readU8
     */
    api_PacketBuf_get_byte(packet_buf: any): any {
        const data = Memory.alloc(1);
        if (HookNative.PacketBuf_get_byte(packet_buf, data)) {
            return data.readU8();
        }
        throw new Error('PacketBuf_get_byte Fail!');
    }

    /**
     * @param packet_buf
     * @returns data.readShort
     */
    api_PacketBuf_get_short(packet_buf: any): any {
        const data = Memory.alloc(2);
        if (HookNative.PacketBuf_get_short(packet_buf, data)) {
            return data.readShort();
        }
        throw new Error('PacketBuf_get_short Fail!');
    }

    /**
     * @param packet_buf
     * @returns data.readInt
     */
    api_PacketBuf_get_int(packet_buf: any): any {
        const data = Memory.alloc(4);
        if (HookNative.PacketBuf_get_int(packet_buf, data)) {
            return data.readInt();
        }
        throw new Error('PacketBuf_get_int Fail!');
    }

    /**
     * 世界广播(频道内公告)
     * @param msg 发送文本
     * @param msg_type 消息类型 1绿(私聊)/14管理员(喇叭)/16系统消息
     */
    api_GameWorld_SendNotiPacketMessage(msg: string, msg_type: number): void {
        const packet_guard = this.api_PacketGuard_PacketGuard();
        HookNative.InterfacePacketBuf_put_header(packet_guard, 0, 12);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, msg_type);
        HookNative.InterfacePacketBuf_put_short(packet_guard, 0);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, 0);
        this.api_InterfacePacketBuf_put_string(packet_guard, msg);
        HookNative.InterfacePacketBuf_finalize(packet_guard, 1);
        HookNative.GameWorld_send_all_with_state(HookNative.G_GameWorld(), packet_guard, 3); // 只给state >= 3 的玩家发公告
        HookNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * 给角色发消息
     * @param user User指针
     * @param msg 发送文本
     * @param msg_type 消息类型
     */
    api_CUser_SendNotiPacketMessage(user: any, msg: string, msg_type: number): void {
        const p = Memory.allocUtf8String(msg);
        HookNative.CUser_SendNotiPacketMessage(user, p, msg_type);
        return;
    }

    /**
     * 测试弹窗消息（客户端会崩溃，木青1031插件中修复，未测试）
     * @param user User指针
     * @param msg 发送文本
     */
    SendPacketMessage(user: any, msg: string): void {
        const packet_guard = this.api_PacketGuard_PacketGuard();
        HookNative.InterfacePacketBuf_put_header(packet_guard, 0, 233);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, 1);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, msg.length);
        this.api_InterfacePacketBuf_put_string(packet_guard, msg);

        HookNative.InterfacePacketBuf_finalize(packet_guard, 1);
        HookNative.CUser_Send(user, packet_guard);
        HookNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * 获取角色名字
     * @param user User指针
     * @returns 角色名字
     */
    api_CUserCharacInfo_getCurCharacName(user: any): any {
        const p = HookNative.CUserCharacInfo_getCurCharacName(user);
        if (p.isNull()) {
            return '';
        }
        return p.readUtf8String(-1);
    }

    /**
     * 获取道具名字
     * @param item_id 道具id
     * @returns 道具名字
     */
    api_CItem_GetItemName(item_id: any): any {
        const citem = HookNative.CDataManager_find_item(HookNative.G_CDataManager(), item_id);
        if (!citem.isNull()) {
            return HookNative.CItem_GetItemName(citem).readUtf8String(-1);
        }
        return item_id.toString();
    }

    /**
     * 点券充值 (禁止直接修改billing库所有表字段, 点券相关操作务必调用数据库存储过程!)
     * @param user User指针
     * @param amount 点券数量
     */
    api_recharge_cash_cera(user: any, amount: number): void {
        // 充值
        HookNative.WongWork_IPG_CIPGHelper_IPGInput(
            ptr(0x941f734).readPointer(),
            user,
            5,
            amount,
            ptr(0x8c7fa20),
            ptr(0x8c7fa20),
            Memory.allocUtf8String('GM'),
            ptr(0),
            ptr(0),
            ptr(0)
        );
        // 通知客户端充值结果
        HookNative.WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941f734).readPointer(), user);
    }

    /**
     * 代币充值
     * @param user User指针
     * @param amount 代币数量
     */
    api_recharge_cash_cera_point(user: any, amount: number): void {
        // 充值
        HookNative.WongWork_IPG_CIPGHelper_IPGInputPoint(ptr(0x941f734).readPointer(), user, amount, 4, ptr(0), ptr(0));
        // 通知客户端充值结果
        HookNative.WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941f734).readPointer(), user);
    }

    // rarityExtension(): void {
    //     // CItem::get_rarity(CItem *this)
    //     Interceptor.attach(ptr(0x080f12d6), {
    //         onLeave: function (retval) {
    //             if (retval > 5) retval.replace(3);
    //         }
    //     });
    // }

    /**
     * 在dispatcher线程执行(args为函数f的参数组成的数组, 若f无参数args可为null)
     */
    api_scheduleOnMainThread(f: any, args: any): void {
        // 线程安全
        const guard = this.api_Guard_Mutex_Guard();
        this.timer_dispatcher_list.push([f, args]);
        HookNative.Destroy_Guard_Mutex_Guard(guard);
        return;
    }

    // 挂接消息分发线程 确保代码线程安全
    hook_TimerDispatcher_dispatch() {
        let _self = this;
        //hook TimerDispatcher::dispatch
        //服务器内置定时器 每秒至少执行一次
        Interceptor.attach(ptr(0x8632a18), {
            onEnter: function (args) {},
            onLeave: function (retval) {
                //清空等待执行的任务队列
                _self.do_timer_dispatch();
            }
        });
    }

    // 处理到期的自定义定时器
    do_timer_dispatch() {
        // 当前待处理的定时器任务列表
        let task_list = [];
        // 线程安全
        let guard = this.api_Guard_Mutex_Guard();
        // 依次取出队列中的任务
        while (this.timer_dispatcher_list.length > 0) {
            // 先入先出
            let task = this.timer_dispatcher_list.shift();
            task_list.push(task);
        }
        HookNative.Destroy_Guard_Mutex_Guard(guard);
        // 执行任务
        for (var i = 0; i < task_list.length; ++i) {
            let task = task_list[i];
            let f = task[0];
            let args = task[1];
            f.apply(null, args);
        }
    }

    /**
     * 申请锁(申请后务必手动释放!!!)
     */
    api_Guard_Mutex_Guard(): any {
        const a1 = Memory.alloc(100);
        HookNative.Guard_Mutex_Guard(a1, HookNative.G_TimerQueue().add(16));
        return a1;
    }

    /**
     * 设置定时器 到期后在dispatcher线程执行
     */
    api_scheduleOnMainThread_delay(f: any, args: any, delay: number): void {
        setTimeout(this.api_scheduleOnMainThread, delay, f, args);
    }

    //mysql查询(返回mysql句柄)(注意线程安全)
    api_MySQL_exec(mysql: any, sql: string): any {
        const sql_ptr = Memory.allocUtf8String(sql);
        HookNative.MySQL_set_query_2(mysql, sql_ptr);
        return HookNative.MySQL_exec(mysql, 1);
    }

    // 查询sql结果
    // 使用前务必保证api_MySQL_exec返回0
    // 并且MySQL_get_n_rows与预期一致
    api_MySQL_get_int(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == HookNative.MySQL_get_int(mysql, field_index, v)) return v.readInt();
        // log('api_MySQL_get_int Fail!!!');
        return null;
    }

    api_MySQL_get_uint(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == HookNative.MySQL_get_uint(mysql, field_index, v)) return v.readUInt();
        //log('api_MySQL_get_uint Fail!!!');
        return null;
    }

    api_MySQL_get_short(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == HookNative.MySQL_get_short(mysql, field_index, v)) return v.readShort();
        //log('MySQL_get_short Fail!!!');
        return null;
    }

    api_MySQL_get_float(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == HookNative.MySQL_get_float(mysql, field_index, v)) return v.readFloat();
        //log('MySQL_get_float Fail!!!');
        return null;
    }

    api_MySQL_get_str(mysql: any, field_index: any): any {
        const binary_length = HookNative.MySQL_get_binary_length(mysql, field_index);
        if (binary_length > 0) {
            var v = Memory.alloc(binary_length);
            if (1 == HookNative.MySQL_get_binary(mysql, field_index, v, binary_length)) return v.readUtf8String(binary_length);
        }
        //log('MySQL_get_str Fail!!!');
        return null;
    }

    api_MySQL_get_binary(mysql: any, field_index: any): any {
        const binary_length = HookNative.MySQL_get_binary_length(mysql, field_index);
        if (binary_length > 0) {
            var v = Memory.alloc(binary_length);
            if (1 == HookNative.MySQL_get_binary(mysql, field_index, v, binary_length)) return v.readByteArray(binary_length);
        }
        //log('api_MySQL_get_binary Fail!!!');
        return null;
    }

    // 从数据库载入怪物攻城活动数据
    // event_villageattack_load_from_db() {
    //     let mysql_frida = {a：1}
    //     if (this.api_MySQL_exec(mysql_frida, "select event_info from game_event where event_id = 'villageattack';")) {
    //         if (HookNative.MySQL_get_n_rows(mysql_frida) == 1) {
    //             HookNative.MySQL_fetch(mysql_frida);
    //             var info = api_MySQL_get_str(mysql_frida, 0);
    //             villageAttackEventInfo = JSON.parse(info);
    //         }
    //     }
    // }

    /**
     * hook函数 Interceptor.attach
     * @param gameEvent hook函数名称
     */
    hook(gameEvent: string): void {
        const _self = this;
        if (typeof this.eventHandlers[gameEvent] === 'function') {
            this.eventHandlers[gameEvent](_self);
            this.logger(`[hook][${gameEvent}]`);
        } else {
            console.error(`No handler found for event: ${gameEvent}`);
        }
    }

    /***********************以下为系统工具函数*******************************/
    /**
     * 打印日志
     * @param args 打印参数
     */
    logger(...args: any[]): void {
        try {
            console.log(`[${new Date()}][${process.env.loggername}]${args.join('')}`);
        } catch (e: any) {
            console.error(e);
        }
    }

    // 本地时间戳
    get_timestamp(): string {
        let date = new Date();
        date = new Date(date.setHours(date.getHours())); // 转换到本地时间
        const year = date.getFullYear().toString();
        const month = (date.getMonth() + 1).toString();
        const day = date.getDate().toString();
        const hour = date.getHours().toString();
        const minute = date.getMinutes().toString();
        const second = date.getSeconds().toString();
        // const ms = date.getMilliseconds().toString();
        return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    }

    /**
     * 获取随机数
     * @param min 最小值
     * @param max 最大值
     * @returns 返回min与max之间的随机数
     */
    get_random_int(min: number, max: number): number {
        return Math.floor(Math.random() * (max - min)) + min;
    }

    /**
     * 读取文件
     * @param path 文件路径
     * @param mode 文件读取模式
     * @param len 读取数据长度
     */
    local_read_file(path: string, mode: string, len: number): any {
        const path_ptr = Memory.allocUtf8String(path);
        const mode_ptr = Memory.allocUtf8String(mode);
        const f = HookNative.fopen(path_ptr, mode_ptr);
        if (f == 0) return null;
        const data = Memory.alloc(len);
        const fread_ret = HookNative.fread(data, 1, len, f);
        HookNative.fclose(f);
        // 返回字符串
        if (mode == 'r') return data.readUtf8String(fread_ret);
        // 返回二进制buff指针
        return data;
    }

    /**
     * 加载本地配置文件(json格式)
     * @param path 文件路径
     */
    local_load_config(path: string): void {
        const data = this.local_read_file(path, 'r', 10 * 1024 * 1024);
        this.global_config = JSON.parse(data);
    }

    /**
     * 获取系统UTC时间(秒)
     * @param path 文件路径
     */
    local_getSysUTCSec() {
        return HookNative.GlobalData_systemTime.readInt();
    }
}

export default _HookEvent;
