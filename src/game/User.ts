import GameNative from './GameNative';
import Gmt from './Gmt';
const gmt: Gmt = Gmt.getInstance();

class User {
    private static instance: User; // 私有静态属性
    private CUser: any = null; // User指针

    // 构造函数
    constructor(user: any) {
        this.CUser = user;
    }

    /**
     * 获取User实例
     * @param user User指针
     * @returns User实例
     */
    static getInstance(user: any): User {
        if (!User.instance) {
            User.instance = new User(user);
        }
        return User.instance;
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
     * 设置角色等级(最高70级)
     * @param new_level 角色等级
     */
    SetMaxLevel(new_level: number = 60): void {
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
        this.SetMaxLevel(this.GetCharacLevel()); // 设置角色等级(原等级)
        // 在数据库中修改角色职业和转职
        const characNo = GameNative.CUser_GetCharacNo(user);
        const mysql_taiwan_cain = gmt.getMySQLHandle('taiwan_cain');
        gmt.api_MySQL_exec(mysql_taiwan_cain, `update charac_info set job=${new_job}, grow_type=${new_growtype} where charac_no=${characNo};`);
        // 返回选择角色界面
        this.ReturnToCharac();
    }

    /**
     * 返回选择角色界面
     */
    ReturnToCharac(): void {
        gmt.scheduleOnMainThread(GameNative.CUser_ReturnToSelectCharacList, [this.CUser, 1]);
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
