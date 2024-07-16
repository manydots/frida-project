import GameNative from './GameNative';
import { ENUM_ITEMSPACE } from '@/enum/enum';
import Gmt from './Gmt';
const gmt: Gmt = Gmt.getInstance();

class User {
    private CUser: any = null; // User指针

    // 构造函数
    constructor(user: any) {
        this.CUser = user;
    }

    /**
     * 获取当前队伍信息
     * @returns CParty
     */
    GetParty(): any {
        const CParty = GameNative.CUser_GetParty(this.CUser);
        return CParty;
    }

    /**
     * 获取账号ID
     * @returns AccId
     */
    GetAccId(): number {
        return GameNative.CUser_GetAccId(this.CUser);
    }

    /**
     * 获取角色ID
     * @returns CharacNo
     */
    GetCharacNo(): number {
        return GameNative.CUser_GetCharacNo(this.CUser);
    }

    /**
     * 获取角色名字
     * @returns 角色名字
     */
    GetCharacName(): any {
        const p = GameNative.CUser_GetCharacName(this.CUser);
        if (p.isNull()) {
            return '';
        }
        return p.readUtf8String(-1);
    }

    /**
     * 获取角色等级
     * @returns 角色等级
     */
    GetCharacLevel(): number {
        return GameNative.CUser_GetCharacLevel(this.CUser);
    }

    /**
     * 获取角色职业
     * @returns 角色职业
     */
    GetCharacJob(): number {
        return GameNative.CUser_GetCharacJob(this.CUser);
    }

    /**
     * 获取角色转职职业
     * @returns 角色转职职业
     */
    GetCharacGrowType(): number {
        return GameNative.CUser_GetCharacGrowType(this.CUser);
    }

    /**
     * 获取角色觉醒职业
     * @returns 角色觉醒职业
     */
    GetCharacSecondGrowType(): number {
        return GameNative.CUser_GetCharacSecondGrowType(this.CUser);
    }

    /**
     * 获取角色已用疲劳值
     * @returns 角色已用疲劳值
     */
    GetFatigue(): number {
        return GameNative.CUser_GetFatigue(this.CUser);
    }

    /**
     * 获取角色最大疲劳值
     * @returns 角色最大疲劳值
     */
    GetMaxFatigue(): number {
        return GameNative.CUser_GetMaxFatigue(this.CUser);
    }

    /**
     * 设置角色虚弱值
     * @param stamina 虚弱值0-100
     */
    SetCurCharacStamina(stamina: number): void {
        if (stamina < 0 || stamina > 100) {
            throw new Error(`Invalid stamina value: ${stamina}. Stamina must be between 0 and 100.`);
        }
        GameNative.CUser_SetCurCharacStamina(this.CUser, stamina);
        const packet_guard = gmt.api_PacketGuard_PacketGuard();
        GameNative.InterfacePacketBuf_put_header(packet_guard, 0, 33);
        GameNative.InterfacePacketBuf_put_byte(packet_guard, stamina);
        GameNative.InterfacePacketBuf_finalize(packet_guard, 1);
        GameNative.CUser_Send(this.CUser, packet_guard);
        GameNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * 获取角色当前城镇/区域/坐标
     */
    GetLocation(): any {
        const user = this.CUser;
        const village = GameNative.CUser_GetCurCharacVill(user);
        const area = GameNative.CUser_GetArea(user, village);
        const x = GameNative.CUser_GetPosX(user);
        const y = GameNative.CUser_GetPosY(user);

        return { village, area, x, y };
    }

    /**
     * 给角色发道具
     * @param item_id 物品id
     * @param item_cnt 发送的物品数量
     */
    AddItem(item_id: number, item_cnt: number): void {
        const user = this.CUser;
        const item_space = Memory.alloc(4);
        const slot = GameNative.CUser_AddItem(user, item_id, item_cnt, 6, item_space, 0);
        if (slot >= 0) {
            // console.log(slot);
            // 通知客户端有游戏道具更新
            GameNative.CUser_SendUpdateItemList(user, 1, item_space.readInt(), slot);
        }
    }

    /**
     * 给角色发经验
     * @param exp 经验值
     */
    AddCharacExp(exp: number): void {
        const user = this.CUser;
        const a2 = Memory.alloc(4);
        const a3 = Memory.alloc(4);
        GameNative.CUser_gain_exp_sp(user, exp, a2, a3, 0, 0, 0);
    }

    /**
     * 检查副职业是否开启
     *  - 副职业对象(分解机摆摊才有值)
     */
    GetCurCharacExpertJob(): number {
        const user = this.CUser;
        return GameNative.CUser_GetCurCharacExpertJob(user);
    }

    /**
     * 分解道具
     * @param space 装备位置 ItemSpace
     * @param slot 背包类型 默认 INVENTORY 物品栏
     * @param callee CUser谁的分解机  传null表示诺顿
     */
    Disjoint(space: any, slot: number = ENUM_ITEMSPACE.INVENTORY, callee: any = null) {
        // if (this.GetCurCharacExpertJob() == 0) {
        //     gmt.SendNotiPacketMessage('注意： 副职业没有开启！', 16);
        //     return;
        // }
        const user = this.CUser;
        GameNative.DisPatcher_DisJointItem_disjoint(user, space, slot, 239, callee || user, 0xffff);
        GameNative.CUser_SendUpdateItemList(user, 1, slot, space);
    }

    /**
     * 点券充值 (禁止直接修改billing库所有表字段, 点券相关操作务必调用数据库存储过程!)
     * @param amount 点券数量
     */
    ChargeCera(amount: number): void {
        const user = this.CUser;
        // 充值
        GameNative.WongWork_IPG_CIPGHelper_IPGInput(
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
        GameNative.WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941f734).readPointer(), user);
    }

    /**
     * 代币充值
     * @param amount 代币数量
     */
    ChargeCeraPoint(amount: number): void {
        const user = this.CUser;
        // 充值
        GameNative.WongWork_IPG_CIPGHelper_IPGInputPoint(ptr(0x941f734).readPointer(), user, amount, 4, ptr(0), ptr(0));
        // 通知客户端充值结果
        GameNative.WongWork_IPG_CIPGHelper_IPGQuery(ptr(0x941f734).readPointer(), user);
    }

    /**
     * 获得角色背包对象
     */
    GetCurCharacInvenW(): any {
        return GameNative.CUser_getCurCharacInvenW(this.CUser);
    }

    /**
     * 给角色发消息
     * @param msg 发送文本
     * @param msg_type 消息类型
     */
    SendNotiPacketMessage(msg: string, msg_type: number = 2): void {
        const user = this.CUser;
        const p = Memory.allocUtf8String(msg);
        GameNative.CUser_SendNotiPacketMessage(user, p, msg_type);
        return;
    }

    /**
     * 给角色发送邮件
     * @param charac_no 角色id
     * @param title 邮件标题(发件人名称)
     * @param text 邮件正文
     * @param gold 金钱
     * @param item_list 物品列表 [[item_id,item_cnt],...]
     */
    SendMail(item_list: any, charac_no?: number, title: string = 'DNF管理员', text: string = '非常感谢您的支持！', gold: number = 0): void {
        let _charac_no = charac_no || this.GetCharacNo();
        // 添加道具附件
        const vector = Memory.alloc(100);
        GameNative.std_pair_vector(vector);
        GameNative.std_pair_clear(vector);
        for (let i = 0; i < item_list.length; ++i) {
            const item_id = Memory.alloc(4); // 道具id
            const item_cnt = Memory.alloc(4); // 道具数量
            item_id.writeInt(item_list[i][0]);
            item_cnt.writeInt(item_list[i][1]);
            const pair = Memory.alloc(100);
            GameNative.std_pair_make(pair, item_id, item_cnt);
            GameNative.std_pair_push_back(vector, pair);
        }
        // 邮件支持10个道具附件格子
        const addition_slots = Memory.alloc(1000);
        for (let i = 0; i < 10; ++i) {
            GameNative.Inven_Item(addition_slots.add(i * 61));
        }
        GameNative.WongWork_CMailBoxHelper_MakeSystemMultiMailPostal(vector, addition_slots, 10);
        const title_ptr = Memory.allocUtf8String(title); // 邮件标题
        const text_ptr = Memory.allocUtf8String(text); // 邮件正文
        const text_len = GameNative.strlen(text_ptr); // 邮件正文长度
        // 发邮件给角色
        GameNative.WongWork_CMailBoxHelper_ReqDBSendNewSystemMultiMail(title_ptr, addition_slots, item_list.length, gold, _charac_no, text_ptr, text_len, 0, 99, 1);
    }

    /**
     * 物品信息弹窗包
     * @param itemId 物品id
     */
    SendItemMessage(itemId: number): void {
        const user = this.CUser;
        const packet_guard = gmt.api_PacketGuard_PacketGuard();
        GameNative.InterfacePacketBuf_clear(packet_guard);
        GameNative.InterfacePacketBuf_put_header(packet_guard, 1, 339);
        GameNative.InterfacePacketBuf_put_byte(packet_guard, 1);

        GameNative.InterfacePacketBuf_put_int(packet_guard, itemId); // 物品id
        GameNative.InterfacePacketBuf_put_short(packet_guard, 0);

        GameNative.InterfacePacketBuf_finalize(packet_guard, 1);
        GameNative.CUser_Send(user, packet_guard);
        GameNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * 测试弹窗消息（客户端会崩溃，木青1031插件中修复，未测试）
     * @param msg 发送文本
     */
    SendPacketMessage(msg: string): void {
        const user = this.CUser;
        const packet_guard = gmt.api_PacketGuard_PacketGuard();
        GameNative.InterfacePacketBuf_put_header(packet_guard, 0, 233);
        GameNative.InterfacePacketBuf_put_byte(packet_guard, 1);
        GameNative.InterfacePacketBuf_put_byte(packet_guard, msg.length);
        gmt.api_InterfacePacketBuf_put_string(packet_guard, msg);

        GameNative.InterfacePacketBuf_finalize(packet_guard, 1);
        GameNative.CUser_Send(user, packet_guard);
        GameNative.Destroy_PacketGuard_PacketGuard(packet_guard);
    }

    /**
     * 获取背包中指定道具数量
     * @param item_id 物品id
     * @returns 道具数量
     */
    GetItemCount(itemid: number): number {
        if (!itemid) return 0;
        const inven = this.GetCurCharacInvenW(); // 获取角色背包
        const itemAddr = Memory.alloc(116);
        const invenData = GameNative.CInventory_GetInvenData(inven, itemid, itemAddr);
        if (invenData < 0) return 0;
        const count = itemAddr.add(7).readU32(); // readU16 最大值65535
        return count;
    }

    /**
     * 角色城镇瞬移
     */
    Move_Area(village: number, area: number, pos_x: number, pos_y: number): void {
        // const { village } = this.GetLocation();
        GameNative.GameWorld_Move_Area(GameNative.G_GameWorld(), this.CUser, village, area, pos_x, pos_y, 0, 0, 0, 0, 0);
    }

    /**
     * 设置角色等级(最高70级)
     * @param new_level 角色等级
     */
    SetCharacLevel(new_level: number = 60): void {
        if (new_level < 0 || new_level > 70) {
            throw new Error(`Invalid Level value: ${new_level}. Level must be between 0 and 70.`);
        }
        // 为该角色临时开通GM权限
        const old_gm_mode = this.SetGameMasterMode(this.CUser, 1);
        GameNative.DisPatcher_DebugCommandSetLevel(ptr(0), this.CUser, new_level);
        // 恢复原始GM权限
        this.SetGameMasterMode(this.CUser, old_gm_mode);
    }

    /**
     * 修改角色职业
     * @param new_job 角色职业
     * @param new_growtype 转职职业
     */
    changeJob(new_job: number, new_growtype: number): void {
        const user = this.CUser;
        this.SetCharacLevel(this.GetCharacLevel()); // 设置角色等级(原等级)
        // 在数据库中修改角色职业和转职
        const characNo = this.GetCharacNo();
        const mysql_taiwan_cain = gmt.getMySQLHandle('taiwan_cain');
        gmt.api_MySQL_exec(mysql_taiwan_cain, `update charac_info set job=${new_job}, grow_type=${new_growtype} where charac_no=${characNo};`);
        // 返回选择角色界面
        gmt.ReturnToCharac(user);
    }

    /**
     * 转职与觉醒
     * @param first_grow_type 转职类型 growType[0-7]
     * @param second_grow_type 觉醒进度, 0=未觉醒, 1=觉醒, 2=二次觉醒
     * @param reason integer
     */
    ChangeGrowType(first_grow_type: number, second_grow_type: number = 1, reason: number = 1): void {
        console.log(first_grow_type, second_grow_type, reason);
    }

    /**
     * 所有副本开王图
     */
    UnlockDungeon(): void {
        let a3 = Memory.allocUtf8String('3'); // 副本解锁难度: 0-3
        GameNative.DoUserDefineCommand(this.CUser, 120, a3);
    }

    /**
     * 角色临时开GM权限
     */
    SetGameMasterMode(user: any, enable: any): any {
        let old_gm_mode = user.add(463320).readU8();
        user.add(463320).writeU8(enable);
        // 返回旧权限
        return old_gm_mode;
    }
}

export default User;
