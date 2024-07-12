import GameNative from './GameNative';
import Gmt from './Gmt';
const gm: Gmt = Gmt.getInstance();

class User {
    private static instance: User; // 私有静态属性
    private CUser: any = null; // User指针

    // 构造函数 new User('0xuser'); 或 new User({ user: '0xuser' });
    constructor(userPointer: string);
    constructor(userPointer: { user: string });
    constructor(userPointer: string | { user: string }) {
        // 区分不同的user类型
        if (typeof userPointer === 'string') {
            // 处理字符串类型
            this.CUser = userPointer;
        } else {
            // 处理对象类型
            this.CUser = userPointer?.user;
        }
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
    CUser_ReturnToSelectCharacList(user: any): void {
        gm.scheduleOnMainThread(GameNative.CUser_ReturnToSelectCharacList, [user, 1]);
    }

    // 所有副本开王图
    unlock_all_dungeon_difficulty(user: any): void {
        let a3 = Memory.allocUtf8String('3'); // 副本解锁难度: 0-3
        GameNative.DoUserDefineCommand(user, 120, a3);
    }
}

export default User;
