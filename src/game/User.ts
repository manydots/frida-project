import GameNative from './GameNative';
import Gmt from './Gmt';
const gm: Gmt = Gmt.getInstance();

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
     * 角色临时开GM权限
     */
    SetGameMasterMode(user: any, enable: any): any {
        let old_gm_mode = user.add(463320).readU8();
        user.add(463320).writeU8(enable);
        // 返回旧权限
        return old_gm_mode;
    }

    /**
     * 设置角色等级(最高70级)
     */
    SetMaxLevel(user: any, new_level: number = 60): void {
        // 为该角色临时开通GM权限
        let old_gm_mode = this.SetGameMasterMode(user, 1);
        GameNative.DisPatcher_DebugCommandSetLevel(ptr(0), user, new_level);
        // 恢复原始GM权限
        this.SetGameMasterMode(user, old_gm_mode);
    }

    /**
     * 返回选择角色界面
     */
    CUser_ReturnToSelectCharacList(user?: any): void {
        gm.scheduleOnMainThread(GameNative.CUser_ReturnToSelectCharacList, [user ?? this.CUser, 1]);
    }

    // 所有副本开王图
    unlock_all_dungeon_difficulty(user?: any): void {
        let a3 = Memory.allocUtf8String('3'); // 副本解锁难度: 0-3
        GameNative.DoUserDefineCommand(user ?? this.CUser, 120, a3);
    }
}

export default User;
