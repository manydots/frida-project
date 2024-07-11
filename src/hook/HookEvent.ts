import { HookNative } from './HookType';
import { VILLAGEATTACK_STATE } from '../enum/enum';
import { logger } from '../utils/tool';
import hookGameEvent from './HookGameEvent';

// 定义HookEvent类
class _HookEvent {
    static instance: any = null; // 私有静态属性
    private eventHandlers: any = hookGameEvent; // 挂载游戏事件hook

    // 已打开的数据库句柄
    public mysql_taiwan_cain: any = null;
    public mysql_taiwan_cain_2nd: any = null;
    public mysql_taiwan_billing: any = null;
    public mysql_frida: any = null;

    public global_config: any = {};
    public timer_dispatcher_list: any = []; // 需要在dispatcher线程执行的任务队列(热加载后会被清空)

    // 怪物攻城活动数据
    public villageAttackEventInfo: any = {
        state: VILLAGEATTACK_STATE.END, // 活动当前状态
        score: 0, //当前阶段频道内总PT
        start_time: 0, //活动开始时间(UTC)
        difficult: 0, //活动难度(0-4)
        next_village_monster_id: 0, //下次刷新的攻城怪物id
        last_killed_monster_id: 0, //上次击杀的攻城怪物id
        p2_last_killed_monster_time: 0, //P2阶段上次击杀攻城怪物时间
        p2_kill_combo: 0, //P2阶段连续击杀相同攻城怪物数量
        gbl_cnt: 0, //城镇中存活的GBL主教数量
        defend_success: 0, //怪物攻城活动防守成功
        user_pt_info: {} //角色个人pt数据
    };

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
     * @param packet_buf
     * @returns data.readByteArray
     */
    api_PacketBuf_get_binary(packet_buf: any, len: number): any {
        const data = Memory.alloc(len);
        if (HookNative.PacketBuf_get_binary(packet_buf, data, len)) {
            return data.readByteArray(len);
        }
        throw new Error('PacketBuf_get_binary Fail!');
    }

    /**
     * 获取原始封包数据
     * @param packet_buf
     */
    api_PacketBuf_get_buf(packet_buf: any): any {
        return packet_buf.add(20).readPointer().add(13);
    }

    // 当玩家设置屏蔽或聊天窗口中不显示指定消息类型时，就收不到对应的消息，尽量使用1/14/16这种不会被关闭的类型
    /**
     * 世界广播(频道内公告)
     * @param msg 发送文本
     * @param msg_type 消息类型 1绿(私聊) 2/9蓝(组队) 3/5白(普通)  6粉(公会) 8橙(师徒) 14管理员(喇叭) 16系统消息
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
     * 频道喇叭
     * @param msg 发送文本
     * @param name 发送人名称
     * @param msg_type 消息类型 类型33, ch=11必须为存在的频道
     * @param ch 频道名称
     */
    api_GameWorld_SendGMMessage(msg: string, name: string = '系统公告', msg_type: number = 15, ch: number = 11): void {
        const packet_guard = this.api_PacketGuard_PacketGuard();
        HookNative.InterfacePacketBuf_put_header(packet_guard, 0, 118);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, msg_type); // 13频道喇叭 15服务器喇叭 33 1:1私聊
        HookNative.InterfacePacketBuf_put_byte(packet_guard, ch);
        HookNative.InterfacePacketBuf_put_short(packet_guard, 0);
        this.api_InterfacePacketBuf_put_string(packet_guard, name);
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
    api_SendPacketMessage(user: any, msg: string): void {
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
     * 物品信息弹窗包
     * @param itemId 物品id
     */
    api_SendItemMessage(user: any, itemId: number): void {
        const packet_guard = this.api_PacketGuard_PacketGuard();
        HookNative.InterfacePacketBuf_clear(packet_guard);
        HookNative.InterfacePacketBuf_put_header(packet_guard, 1, 339);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, 1);

        HookNative.InterfacePacketBuf_put_int(packet_guard, itemId); // 物品id
        HookNative.InterfacePacketBuf_put_short(packet_guard, 0);

        HookNative.InterfacePacketBuf_finalize(packet_guard, 1);
        HookNative.CUser_Send(user, packet_guard);
        HookNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * @returns 获取当前频道文件名
     */
    api_CEnvironment_get_file_name(): any {
        var filename = HookNative.CEnvironment_get_file_name(HookNative.G_CEnvironment());
        return filename?.readUtf8String(-1);
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
     * 设置角色虚弱值
     * @param user User指针
     * @param stamia 虚弱值0-100
     */
    api_setCurCharacStamia(user: any, stamia: any): void {
        HookNative.CUserCharacInfo_setCurCharacStamia(user, stamia);
        const packet_guard = this.api_PacketGuard_PacketGuard();
        HookNative.InterfacePacketBuf_put_header(packet_guard, 0, 33);
        HookNative.InterfacePacketBuf_put_byte(packet_guard, stamia);
        HookNative.InterfacePacketBuf_finalize(packet_guard, 1);
        HookNative.CUser_Send(user, packet_guard);
        HookNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * 给角色发送邮件
     * @param charac_no 角色id
     * @param title 邮件标题(发件人名称)
     * @param text 邮件正文
     * @param gold 金钱
     * @param item_list 物品列表
     */
    api_WongWork_SendMail(charac_no: number, item_list: any, title: string = 'DNF管理员', text: string = '非常感谢您的支持！', gold: number = 0): void {
        // 添加道具附件
        const vector = Memory.alloc(100);
        HookNative.std_pair_vector(vector);
        HookNative.std_pair_clear(vector);
        for (let i = 0; i < item_list.length; ++i) {
            const item_id = Memory.alloc(4); // 道具id
            const item_cnt = Memory.alloc(4); // 道具数量
            item_id.writeInt(item_list[i][0]);
            item_cnt.writeInt(item_list[i][1]);
            const pair = Memory.alloc(100);
            HookNative.std_pair_make(pair, item_id, item_cnt);
            HookNative.std_pair_push_back(vector, pair);
        }
        // 邮件支持10个道具附件格子
        const addition_slots = Memory.alloc(1000);
        for (let i = 0; i < 10; ++i) {
            HookNative.Inven_Item(addition_slots.add(i * 61));
        }
        HookNative.WongWork_CMailBoxHelper_MakeSystemMultiMailPostal(vector, addition_slots, 10);
        const title_ptr = Memory.allocUtf8String(title); // 邮件标题
        const text_ptr = Memory.allocUtf8String(text); // 邮件正文
        const text_len = HookNative.strlen(text_ptr); // 邮件正文长度
        // 发邮件给角色
        HookNative.WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(title_ptr, addition_slots, item_list.length, gold, charac_no, text_ptr, text_len, 0, 99, 1);
    }

    /**
     * 给角色发经验
     * @param user User指针
     * @param exp 经验值
     */
    api_CUser_gain_exp_sp(user: any, exp: number): void {
        const a2 = Memory.alloc(4);
        const a3 = Memory.alloc(4);
        HookNative.CUser_gain_exp_sp(user, exp, a2, a3, 0, 0, 0);
    }

    /**
     * 给角色发道具
     * @param user User指针
     * @param item_id 物品id
     * @param item_cnt 发送的物品数量
     */
    api_CUser_AddItem(user: any, item_id: number, item_cnt: number): void {
        const item_space = Memory.alloc(4);
        const slot = HookNative.CUser_AddItem(user, item_id, item_cnt, 6, item_space, 0);
        if (slot >= 0) {
            // console.log(slot);
            // 通知客户端有游戏道具更新
            HookNative.CUser_SendUpdateItemList(user, 1, item_space.readInt(), slot);
        }
    }

    /**
     * 获取道具数据
     * @param item_id 物品id
     */
    find_item(item_id: number): any {
        return HookNative.CDataManager_find_item(HookNative.G_CDataManager(), item_id);
    }

    /**
     * 获取背包中指定道具数量
     * @param user User指针
     * @param item_id 物品id
     * @returns 道具数量
     */
    api_getItemCount(user: any, itemid: number): number {
        if (!itemid) return 0;
        const inven = HookNative.CUserCharacInfo_getCurCharacInvenW(user); // 获取角色背包
        const itemAddr = Memory.alloc(116);
        const invenData = HookNative.CInventory_GetInvenData(inven, itemid, itemAddr);
        if (invenData < 0) return 0;
        const count = itemAddr.add(7).readU32(); // readU16 最大值65535
        return count;
    }

    /**
     * 获取副本名称
     * @param dungeonId 副本id
     * @returns 副本名称
     */
    api_CDungeon_getDungeonName(dungeonId: any): any {
        const dungeon = HookNative.CDataManager_find_dungeon(HookNative.G_CDataManager(), dungeonId);
        if (!dungeon.isNull()) {
            return HookNative.CDungeon_getDungeonName(dungeon).readUtf8String(-1);
        }
        return dungeonId.toString();
    }

    /**
     * 获取道具名字
     * @param item_id 道具id
     * @returns 道具名字
     */
    api_CItem_getItemName(item_id: any): any {
        const citem = HookNative.CDataManager_find_item(HookNative.G_CDataManager(), item_id);
        if (!citem.isNull()) {
            return HookNative.CItem_getItemName(citem).readUtf8String(-1);
        }
        return item_id.toString();
    }

    /**
     * 获取道具详情
     * @param item_id 道具id
     * @returns 道具详情
     */
    api_CItem_getItemDetail(item_id?: any, CItem?: any): any {
        CItem = !CItem ? this.find_item(item_id) : CItem;
        if (!CItem.isNull()) {
            return {
                name: HookNative.CItem_getItemName(CItem).readUtf8String(-1),
                rarity: HookNative.CItem_getRarity(CItem),
                grade: HookNative.CItem_GetGrade(CItem), // 装备等级
                itemId: HookNative.Inven_Item_getKey(CItem),
                index: HookNative.CItem_GetIndex(CItem),
                price: HookNative.CItem_GetPrice(CItem),
                groupName: HookNative.CItem_GetItemGroupName(CItem),
                genRate: HookNative.CItem_GetGenRate(CItem)
            };
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

    /**
     * 在dispatcher线程执行(args为函数f的参数组成的数组, 若f无参数args可为null)
     * @param func Function
     * @param args 参数列表
     */
    api_scheduleOnMainThread(func: Function, args: any): void {
        let _self = this;
        // 线程安全
        const guard = this.api_Guard_Mutex_Guard();
        this.timer_dispatcher_list.push([func.bind(_self), args]); // 改变this指向
        HookNative.Destroy_Guard_Mutex_Guard(guard);
        return;
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

    // 挂接消息分发线程 确保代码线程安全
    hook_TimerDispatcher_dispatch(): void {
        let _self = this;
        // hook TimerDispatcher::dispatch
        // 服务器内置定时器 每秒至少执行一次
        Interceptor.attach(ptr(0x8632a18), {
            onEnter: function (args) {},
            onLeave: function (retval) {
                // 清空等待执行的任务队列
                _self.do_timer_dispatch();
            }
        });
    }

    // 处理到期的自定义定时器
    do_timer_dispatch(): void {
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

    // 初始化数据库(打开数据库/建库建表/数据库字段扩展)
    init_db(): void {
        // 配置文件
        const config = this.global_config['db_config'];
        const db_ip = '127.0.0.1';
        const db_port = 3306;
        const db_account = config['account'];
        const db_password = config['password'];

        // 打开数据库连接
        if (this.mysql_taiwan_cain == null) {
            this.mysql_taiwan_cain = this.api_MYSQL_open('taiwan_cain', db_ip, db_port, db_account, db_password);
        }
        if (this.mysql_taiwan_cain_2nd == null) {
            this.mysql_taiwan_cain_2nd = this.api_MYSQL_open('taiwan_cain_2nd', db_ip, db_port, db_account, db_password);
        }
        if (this.mysql_taiwan_billing == null) {
            this.mysql_taiwan_billing = this.api_MYSQL_open('taiwan_billing', db_ip, db_port, db_account, db_password);
        }
        // 建库frida
        this.api_MySQL_exec(this.mysql_taiwan_cain, 'create database if not exists frida default charset utf8;');
        if (this.mysql_frida == null) {
            this.mysql_frida = this.api_MYSQL_open('frida', db_ip, db_port, db_account, db_password);
        } else {
            // 建表frida.game_event
            this.api_MySQL_exec(
                this.mysql_frida,
                'CREATE TABLE game_event (event_id varchar(30) NOT NULL, event_info mediumtext NULL, PRIMARY KEY (event_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;'
            );

            // 建表frida.dp_login
            this.api_MySQL_exec(
                this.mysql_frida,
                'CREATE TABLE if not exists frida.dp_login(id INT(10) not null primary key AUTO_INCREMENT, uid INT(10) default 0 not null, cid INT(10) default 0 not null, first_login_time INT(10) UNSIGNED default 0 not null, create_time DATETIME DEFAULT NULL)'
            );
            // 载入活动数据
            this.event_villageattack_load_from_db();
        }
    }

    // 从数据库载入怪物攻城活动数据
    event_villageattack_load_from_db(): void {
        if (this.api_MySQL_exec(this.mysql_frida, "select event_info from game_event where event_id = 'villageattack';")) {
            if (HookNative.MySQL_get_n_rows(this.mysql_frida) == 1) {
                HookNative.MySQL_fetch(this.mysql_frida);
                const info = this.api_MySQL_get_str(this.mysql_frida, 0);
                this.villageAttackEventInfo = JSON.parse(info);
            }
        }
    }

    // 关闭数据库（卸载插件前调用）
    uninit_db(): void {
        // 活动数据存档
        this.event_villageattack_save_to_db();
        // 关闭数据库连接
        if (this.mysql_taiwan_cain) {
            HookNative.MySQL_close(this.mysql_taiwan_cain);
            this.mysql_taiwan_cain = null;
        }
        if (this.mysql_taiwan_cain_2nd) {
            HookNative.MySQL_close(this.mysql_taiwan_cain_2nd);
            this.mysql_taiwan_cain_2nd = null;
        }
        if (this.mysql_taiwan_billing) {
            HookNative.MySQL_close(this.mysql_taiwan_billing);
            this.mysql_taiwan_billing = null;
        }
        if (this.mysql_frida) {
            HookNative.MySQL_close(this.mysql_frida);
            this.mysql_frida = null;
        }
    }

    // 怪物攻城活动数据存档
    event_villageattack_save_to_db(): void {
        this.api_MySQL_exec(this.mysql_frida, `replace into game_event (event_id, event_info) values ('villageattack', '${JSON.stringify(this.villageAttackEventInfo)}');`);
    }

    /**
     * 申请锁(申请后务必手动释放!!!)
     */
    api_Guard_Mutex_Guard(): any {
        const a1 = Memory.alloc(100);
        HookNative.Guard_Mutex_Guard(a1, HookNative.G_TimerQueue().add(16));
        return a1;
    }

    // 打开数据库
    api_MYSQL_open(db_name: string, db_ip: string, db_port: number, db_account: string, db_password: string): any {
        // mysql初始化
        const mysql = Memory.alloc(0x80000);
        HookNative.MySQL_MySQL(mysql);
        HookNative.MySQL_init(mysql);
        //连接数据库
        const db_ip_ptr = Memory.allocUtf8String(db_ip);
        const db_name_ptr = Memory.allocUtf8String(db_name);
        const db_account_ptr = Memory.allocUtf8String(db_account);
        const db_password_ptr = Memory.allocUtf8String(db_password);
        const ret = HookNative.MySQL_open(mysql, db_ip_ptr, db_port, db_name_ptr, db_account_ptr, db_password_ptr);
        if (ret) {
            logger(`Connect MYSQL DB <${db_name}> SUCCESS!`);
            return mysql;
        }
        return null;
    }
    // mysql查询(返回mysql句柄)(注意线程安全)
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

    /**
     * hook函数 Interceptor.attach
     * @param gameEvent hook函数名称
     * @param params 拓展参数
     */
    hook(gameEvent: string, params?: object): void {
        const _self = this;
        if (typeof this.eventHandlers[gameEvent] === 'function') {
            this.eventHandlers[gameEvent](_self, params ?? {});
            logger(`[hook][${gameEvent}]`);
        } else {
            console.error(`No handler found for event: ${gameEvent}`);
        }
    }

    /***********************以下为系统工具函数*******************************/
    /**
     * Frida.version版本
     */
    echoVersion(): void {
        // const base_address = ptr(0x1ac790c);
        // const offset = 0x258;
        // const target_address = base_address.add(offset);
        logger('[version]', Frida.version);
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
        this.global_config = JSON.parse(data ?? '{}');
    }

    /**
     * 获取系统UTC时间(秒)
     * @returns 系统UTC时间(秒)
     */
    local_getSysUTCSec() {
        return HookNative.GlobalData_systemTime.readInt();
    }
}

export default _HookEvent;
