import GameNative from '@/native/GameNative';

/**
 * @param pointer 角色User指针
 * @param accId 角色账号id
 * @param characNo 当前角色id
 * @param characName 当前角色名称
 */
interface CPartyMember {
    pointer?: any | null; // 角色User指针
    accId?: number | null; // 角色账号id
    characNo?: number | null; // 当前角色id
    characName?: any | null; // 当前角色名称
}

class Party {
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
        return CParty.isNull() ? null : CParty;
    }

    /**
     * 获取队伍队长
     * @returns pointer 队长指针
     * @returns characName 队长角色名
     */
    GetManager(): CPartyMember {
        const CParty = this.GetParty();
        if (CParty) {
            const CPartyManager = GameNative.CParty_GetManager(CParty);
            return { pointer: CPartyManager, characName: GameNative.CUser_GetCharacName(CPartyManager)?.readUtf8String(-1) };
        }
        return { pointer: null, characName: '' };
    }

    /**
     * 遍历队伍玩家信息
     * @returns 队伍玩家信息
     */
    ForEachMember(): CPartyMember[] {
        const CParty = this.GetParty();
        const CPartyMembers = [];
        if (CParty) {
            for (let i = 0; i < 4; i++) {
                const user = GameNative.CParty_GetUser(CParty, i);
                if (!user.isNull()) {
                    const accId = GameNative.CUser_GetAccId(user);
                    const characNo = GameNative.CUser_GetCharacNo(user);
                    const characName = GameNative.CUser_GetCharacName(user)?.readUtf8String(-1);
                    CPartyMembers.push({ accId, characNo, characName, pointer: user });
                }
            }
        }
        return CPartyMembers;
    }

    /**
     * TODO 获取副本难度
     */
    GetDungeonDiff(): number {
        return GameNative.CParty_GetDungeonDiff(this.GetParty());
    }

    /**
     * 返回城镇
     */
    ReturnToVillage(): void {
        GameNative.CParty_ReturnToVillage(this.GetParty());
    }

    /**
     * 获取副本对象
     * @returns CDungeon
     */
    GetDungeon(): any {
        const dungeonId = GameNative.getDungeonIdxAfterClear(this.CUser);
        const dungeon = GameNative.CDataManager_find_dungeon(GameNative.G_CDataManager(), dungeonId);
        if (!dungeon.isNull()) {
            return GameNative.CDungeon_GetName(dungeon);
        }
        return null;
    }

    /**
     * 获取副本等级
     * @returns 副本等级
     */
    GetDungeonMinLevel(): number {
        const dungeonId = GameNative.getDungeonIdxAfterClear(this.CUser);
        return GameNative.CDungeon_GetMinLevel(GameNative.G_GameWorld(), dungeonId);
    }

    /**
     * 获取副本名称
     * @returns CDungeonName
     */
    GetDungeonName(): any {
        const CDungeon = this.GetDungeon();
        if (!CDungeon.isNull()) {
            return CDungeon.readUtf8String(-1);
        }
        return '';
    }

    /**
     * 获取副本详情
     * @returns 副本详情
     */
    GetDungeonItem(): any {
        const dungeonId = GameNative.getDungeonIdxAfterClear(this.CUser);
        const dungeon = this.GetDungeon();
        const level = GameNative.CDungeon_GetMinLevel(GameNative.G_GameWorld(), dungeonId);
        const name = !dungeon.isNull() ? dungeon.readUtf8String(-1) : '';

        return { level, name, dungeonId, pointer: dungeon };
    }
}

export default Party;
