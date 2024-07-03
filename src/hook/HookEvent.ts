import { HookNative } from './HookType';
import hookGameEvent from './HookGameEvent';

// 定义HookEvent类
class _HookEvent {
    static readonly INVENTORY_TYPE_ITEM: number = 1; // 物品栏
    static readonly INVENTORY_TYPE_AVARTAR: number = 2; // 时装栏
    private eventHandlers: any = hookGameEvent;

    // 构造函数，用于初始化对象
    constructor() {}

    // 服务器组包
    api_PacketGuard_PacketGuard(): any {
        const packet_guard = Memory.alloc(0x20000);
        HookNative.PacketGuard_PacketGuard(packet_guard);
        return packet_guard;
    }

    // 发送字符串给客户端
    api_InterfacePacketBuf_put_string(packet_guard: any, s: any): void {
        const p = Memory.allocUtf8String(s);
        const len = HookNative.strlen(p);
        HookNative.InterfacePacketBuf_put_int(packet_guard, len);
        HookNative.InterfacePacketBuf_put_binary(packet_guard, p, len);
        return;
    }

    // 从客户端封包中读取数据(失败会抛异常, 调用方必须做异常处理)
    api_PacketBuf_get_byte(packet_buf: any): any {
        const data = Memory.alloc(1);
        if (HookNative.PacketBuf_get_byte(packet_buf, data)) {
            return data.readU8();
        }
        throw new Error('PacketBuf_get_byte Fail!');
    }

    api_PacketBuf_get_short(packet_buf: any): any {
        const data = Memory.alloc(2);
        if (HookNative.PacketBuf_get_short(packet_buf, data)) {
            return data.readShort();
        }
        throw new Error('PacketBuf_get_short Fail!');
    }

    api_PacketBuf_get_int(packet_buf: any): any {
        const data = Memory.alloc(4);
        if (HookNative.PacketBuf_get_int(packet_buf, data)) {
            return data.readInt();
        }
        throw new Error('PacketBuf_get_int Fail!');
    }

    // 世界广播(频道内公告)
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

    // 给角色发消息
    api_CUser_SendNotiPacketMessage(user: any, msg: string, msg_type: number): void {
        const p = Memory.allocUtf8String(msg);
        HookNative.CUser_SendNotiPacketMessage(user, p, msg_type);
        return;
    }

    // 测试弹窗消息（客户端会崩溃，木青1031插件中修复，未测试）
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

    // 获取角色名字
    api_CUserCharacInfo_getCurCharacName(user: any): any {
        const p = HookNative.CUserCharacInfo_getCurCharacName(user);
        if (p.isNull()) {
            return '';
        }
        return p.readUtf8String(-1);
    }

    // 获取道具名字
    api_CItem_GetItemName(item_id: any): any {
        const citem = HookNative.CDataManager_find_item(HookNative.G_CDataManager(), item_id);
        if (!citem.isNull()) {
            return HookNative.CItem_GetItemName(citem).readUtf8String(-1);
        }
        return item_id.toString();
    }

    // 点券充值 (禁止直接修改billing库所有表字段, 点券相关操作务必调用数据库存储过程!)
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

    // 代币充值 (禁止直接修改billing库所有表字段, 点券相关操作务必调用数据库存储过程!)
    api_recharge_cash_cera_point(user: any, amount: number): void {
        // 充值
        HookNative.WongWork_IPG_CIPGHelper_IPGInputPoint(ptr(0x941f734).readPointer(), user, amount, 4, ptr(0), ptr(0));
        // 通知客户端充值结果
        HookNative.WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941f734).readPointer(), user);
    }

    hook(gameEvent: string): void {
        const _self = this;
        if (typeof this.eventHandlers[gameEvent] === 'function') {
            this.eventHandlers[gameEvent](_self);
            this.logger(`[hook][${gameEvent}]`);
        } else {
            console.error(`No handler found for event: ${gameEvent}`);
        }
    }

    // 打印日志
    logger(...args: any[]): void {
        try {
            console.log(`[${new Date()}][${process.env.loggername}]${args.join('')}`);
        } catch (e: any) {
            console.error(e);
        }
    }

    // 获取随机数
    get_random_int(min: number, max: number): number {
        return Math.floor(Math.random() * (max - min)) + min;
    }
}

export default _HookEvent;
