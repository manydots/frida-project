import GameNative from './GameNative';
import { logger } from '../utils/tool';
// import User from './User';

/**
 * @param pointer 角色User指针
 * @param accId 角色账号id
 * @param characNo 当前角色id
 * @param characName 当前角色名称
 */
interface CPartyMember {
    pointer: any; // 角色User指针
    accId: number; // 角色账号id
    characNo: number; // 当前角色id
    characName: any; // 当前角色名称
}

class Party {
    private static instance: Party; // 私有静态属性
    private CUser: any = null; // User指针

    // 构造函数
    constructor(user: any) {
        this.CUser = user;
    }

    /**
     * 获取当前角色所在的CParty
     * @returns CParty
     */
    // GetCParty(): any {
    //     const CUser = new User(this.CUser);
    //     const CParty = CUser.GetParty();
    //     return CParty;
    // }

    /**
     * 获取当前队伍信息
     * @returns CParty
     */
    GetParty(): any {
        const CParty = GameNative.CUser_GetParty(this.CUser);
        return CParty;
    }

    /**
     * 获取队伍队长
     * @returns CPartyManager队长指针
     */
    GetManager(): any {
        const CParty = this.GetParty();
        const CPartyManager = GameNative.CParty_GetManager(CParty);
        // 测试打印队长名称
        logger('[CPartyManager]', GameNative.CUser_GetCharacName(CPartyManager)?.readUtf8String(-1));
        return CPartyManager;
    }

    /**
     * 遍历队伍玩家信息
     * @returns 队伍玩家信息
     */
    ForEachMember(): CPartyMember[] {
        const CParty = this.GetParty();
        const CPartyMembers = [];

        for (let i = 0; i < 4; i++) {
            const user = GameNative.CParty_GetUser(CParty, i);
            if (!user.isNull()) {
                const accId = GameNative.CUser_GetAccId(user);
                const characNo = GameNative.CUser_GetCharacNo(user);
                const characName = GameNative.CUser_GetCharacName(user)?.readUtf8String(-1);
                CPartyMembers.push({ accId, characNo, characName, pointer: user });
            }
        }
        return CPartyMembers;
    }

    /**
     * 返回城镇
     */
    ReturnToVillage(): void {
        GameNative.CParty_ReturnToVillage(this.GetParty());
    }
}

export default Party;
