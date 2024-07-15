/**
 * 系统工具类
 */
import GameNative from './GameNative';
import { logger } from '@/utils/tool';

export default class Gmt {
    static instance: Gmt; // 私有静态属性

    public global_config: any = {};
    public timer_dispatcher_list: any = []; // 需要在dispatcher线程执行的任务队列(热加载后会被清空)

    // 已打开数据库句柄集合
    public MySQL_Handle: any = {
        taiwan_cain: null,
        taiwan_cain_2nd: null,
        taiwan_billing: null,
        frida: null
    };

    // 私有构造函数，防止外部通过new关键字创建实例
    private constructor() {}

    /**
     * 获取HookEvent实例(单例模式)
     */
    static getInstance(): Gmt {
        if (!Gmt.instance) {
            Gmt.instance = new Gmt();
        }
        return Gmt.instance;
    }

    /**
     * 服务器组包
     * @returns packet_guard
     */
    api_PacketGuard_PacketGuard(): any {
        const packet_guard = Memory.alloc(0x20000);
        GameNative.PacketGuard_PacketGuard(packet_guard);
        return packet_guard;
    }

    /**
     * 发送字符串给客户端
     * @param packet_guard packet_guard
     * @param s
     */
    api_InterfacePacketBuf_put_string(packet_guard: any, s: any): void {
        const p = Memory.allocUtf8String(s);
        const len = GameNative.strlen(p);
        GameNative.InterfacePacketBuf_put_int(packet_guard, len);
        GameNative.InterfacePacketBuf_put_binary(packet_guard, p, len);
        return;
    }

    /**
     * 从客户端封包中读取数据(失败会抛异常, 调用方必须做异常处理)
     * @param packet_buf
     * @returns data.readU8
     */
    api_PacketBuf_get_byte(packet_buf: any): any {
        const data = Memory.alloc(1);
        if (GameNative.PacketBuf_get_byte(packet_buf, data)) {
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
        if (GameNative.PacketBuf_get_short(packet_buf, data)) {
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
        if (GameNative.PacketBuf_get_int(packet_buf, data)) {
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
        if (GameNative.PacketBuf_get_binary(packet_buf, data, len)) {
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

    /**
     * 申请锁(申请后务必手动释放!!!)
     */
    api_Guard_Mutex_Guard(): any {
        const a1 = Memory.alloc(100);
        GameNative.Guard_Mutex_Guard(a1, GameNative.G_TimerQueue().add(16));
        return a1;
    }

    // 打开数据库
    api_MYSQL_open(db_name: string, db_ip: string, db_port: number, db_account: string, db_password: string): any {
        // mysql初始化
        const mysql = Memory.alloc(0x80000);
        GameNative.MySQL_MySQL(mysql);
        GameNative.MySQL_init(mysql);
        //连接数据库
        const db_ip_ptr = Memory.allocUtf8String(db_ip);
        const db_name_ptr = Memory.allocUtf8String(db_name);
        const db_account_ptr = Memory.allocUtf8String(db_account);
        const db_password_ptr = Memory.allocUtf8String(db_password);
        const ret = GameNative.MySQL_open(mysql, db_ip_ptr, db_port, db_name_ptr, db_account_ptr, db_password_ptr);
        if (ret) {
            logger(`Connect MYSQL DB <${db_name}> SUCCESS!`);
            return mysql;
        }
        return null;
    }
    // mysql查询(返回mysql句柄)(注意线程安全)
    api_MySQL_exec(mysql: any, sql: string): any {
        const sql_ptr = Memory.allocUtf8String(sql);
        GameNative.MySQL_set_query_2(mysql, sql_ptr);
        return GameNative.MySQL_exec(mysql, 1);
    }

    // 查询sql结果
    // 使用前务必保证api_MySQL_exec返回0
    // 并且MySQL_get_n_rows与预期一致
    api_MySQL_get_int(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == GameNative.MySQL_get_int(mysql, field_index, v)) return v.readInt();
        // log('api_MySQL_get_int Fail!!!');
        return null;
    }

    api_MySQL_get_uint(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == GameNative.MySQL_get_uint(mysql, field_index, v)) return v.readUInt();
        //log('api_MySQL_get_uint Fail!!!');
        return null;
    }

    api_MySQL_get_short(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == GameNative.MySQL_get_short(mysql, field_index, v)) return v.readShort();
        //log('MySQL_get_short Fail!!!');
        return null;
    }

    api_MySQL_get_float(mysql: any, field_index: any): any {
        const v = Memory.alloc(4);
        if (1 == GameNative.MySQL_get_float(mysql, field_index, v)) return v.readFloat();
        //log('MySQL_get_float Fail!!!');
        return null;
    }

    api_MySQL_get_str(mysql: any, field_index: any): any {
        const binary_length = GameNative.MySQL_get_binary_length(mysql, field_index);
        if (binary_length > 0) {
            var v = Memory.alloc(binary_length);
            if (1 == GameNative.MySQL_get_binary(mysql, field_index, v, binary_length)) return v.readUtf8String(binary_length);
        }
        //log('MySQL_get_str Fail!!!');
        return null;
    }

    api_MySQL_get_binary(mysql: any, field_index: any): any {
        const binary_length = GameNative.MySQL_get_binary_length(mysql, field_index);
        if (binary_length > 0) {
            var v = Memory.alloc(binary_length);
            if (1 == GameNative.MySQL_get_binary(mysql, field_index, v, binary_length)) return v.readByteArray(binary_length);
        }
        //log('api_MySQL_get_binary Fail!!!');
        return null;
    }

    // 初始化数据库(打开数据库/建库建表/数据库字段扩展)
    init_db(): void {
        // 配置文件
        const config = this.global_config['db_config'];
        const db_ip = '127.0.0.1';
        const db_port = 3306;
        const db_account = config['account'];
        const db_password = config['password'];
        const db_handle = this.MySQL_Handle;
        const sys_db = ['taiwan_cain', 'taiwan_cain_2nd', 'taiwan_billing']; // 系统默认连接库

        sys_db.forEach((dbname) => {
            // 打开sys_db数据库列表 数据库连接
            if (db_handle[dbname] == null) {
                db_handle[dbname] = this.api_MYSQL_open(dbname, db_ip, db_port, db_account, db_password);
            }
        });
        // 建库frida
        this.api_MySQL_exec(db_handle.taiwan_cain, 'create database if not exists frida default charset utf8;');
        let mysql_frida = db_handle.frida;

        if (mysql_frida == null) {
            db_handle.frida = this.api_MYSQL_open('frida', db_ip, db_port, db_account, db_password);
        } else {
            // 建表frida.game_event
            this.api_MySQL_exec(
                mysql_frida,
                'CREATE TABLE game_event (event_id varchar(30) NOT NULL, event_info mediumtext NULL, PRIMARY KEY (event_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;'
            );

            // 建表frida.dp_login
            this.api_MySQL_exec(
                mysql_frida,
                'CREATE TABLE if not exists frida.dp_login(id INT(10) not null primary key AUTO_INCREMENT, uid INT(10) default 0 not null, cid INT(10) default 0 not null, first_login_time INT(10) UNSIGNED default 0 not null, create_time DATETIME DEFAULT NULL)'
            );
        }
    }

    // 关闭数据库（卸载插件前调用）
    uninit_db(): void {
        let db_handle = this.MySQL_Handle;
        Object.keys(db_handle).forEach((dbname) => {
            if (db_handle[dbname]) {
                // 关闭数据库连接
                GameNative.MySQL_close(db_handle[dbname]);
                db_handle[dbname] = null;
                logger(`Close <${dbname}> MYSQL DB SUCCESS!`);
            }
        });
    }

    /**
     * 获取数据库句柄
     * @param dbname
     */
    getMySQLHandle(dbname: string): any {
        return this.MySQL_Handle[dbname] || null;
    }

    /**
     * 挂接消息分发线程 确保代码线程安全
     */
    TimerDispatcher(): void {
        let _self = this;
        // TimerDispatcher::dispatch
        // 服务器内置定时器 每秒至少执行一次
        Interceptor.attach(ptr(0x8632a18), {
            onEnter: function (args) {},
            onLeave: function (retval) {
                // 清空等待执行的任务队列
                _self.DoTimerDispatcher();
            }
        });
    }

    /**
     * 处理到期的自定义定时器
     */
    DoTimerDispatcher(): void {
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
        GameNative.Destroy_Guard_Mutex_Guard(guard);
        // 执行任务
        for (let i = 0; i < task_list.length; ++i) {
            let task = task_list[i];
            let func = task[0];
            let args = task[1];
            // 确保args是数组或类数组对象
            if (Array.isArray(args)) {
                func.apply(this, args);
            } else {
                // 使用call传递单个参数
                func.call(this, args);
            }
        }
    }

    /**
     * 在dispatcher线程执行(args为函数f的参数组成的数组, 若f无参数args可为null)
     * @param func Function gmt内部实例方法
     * @param args 参数列表
     */
    scheduleOnMainThread(func: Function, args: any): void {
        // 线程安全
        const guard = this.api_Guard_Mutex_Guard();
        this.timer_dispatcher_list.push([func, args]);
        GameNative.Destroy_Guard_Mutex_Guard(guard);
        return;
    }

    /**
     * scheduleOnMainThread 测试函数
     *  - args[Array] ...args
     *  - args{object} arg
     */
    logArgs(arg: any) {
        logger('[Gmt.args]', arg?.a1);
    }

    /**
     * 读取文件
     * @param path 文件路径
     * @param mode 文件读取模式
     * @param len 读取数据长度
     */
    readFile(path: string, mode: string, len: number): any {
        const path_ptr = Memory.allocUtf8String(path);
        const mode_ptr = Memory.allocUtf8String(mode);
        const f = GameNative.fopen(path_ptr, mode_ptr);
        if (f == 0) return null;
        const data = Memory.alloc(len);
        const fread_ret = GameNative.fread(data, 1, len, f);
        GameNative.fclose(f);
        // 返回字符串
        if (mode == 'r') return data.readUtf8String(fread_ret);
        // 返回二进制buff指针
        return data;
    }

    /**
     * 加载本地配置文件(json格式)
     * @param path 文件路径
     */
    loadConfig(path: string): void {
        const data = this.readFile(path, 'r', 10 * 1024 * 1024);
        this.global_config = JSON.parse(data ?? '{}');
    }
}
