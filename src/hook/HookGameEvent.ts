import hookType, { HookNative } from './HookType';
import { INVENTORY_TYPE } from '../enum/enum';

const _HookGameEvent = {
    /**
     *  角色登入登出处理
     *  @param gm HookEvent实例
     */
    userLogout(gm: any): void {
        // 选择角色处理函数
        Interceptor.attach(ptr(hookType.Reach_GameWorld), {
            // 函数入口, 拿到函数参数args
            onEnter: function (args) {
                // 保存函数参数
                this.user = args[1];
                gm.logger(`[Reach_GameWorld][user]${this.user}`);
                // gm.api_SendItemMessage(this.user, 3037); // 测试弹窗物品信息 3037无色小晶体
                // gm.api_setCurCharacStamia(this.user, 50); // 设置角色虚弱值
            },
            // 原函数执行完毕, 这里可以得到并修改返回值retval
            onLeave: function (retval) {
                // 发送频道消息
                gm.api_GameWorld_SendNotiPacketMessage(`玩家【${gm.api_CUserCharacInfo_getCurCharacName(this.user)}】上线了`, 14);
                // 给角色发问候消息
                // gm.api_CUser_SendNotiPacketMessage(this.user, `Hello ${gm.api_CUserCharacInfo_getCurCharacName(this.user)}`, 2);
            }
        });
        // 角色退出处理函数
        Interceptor.attach(ptr(hookType.Leave_GameWorld), {
            onEnter: function (args) {
                const user = args[0];
                gm.logger(`[Leave_GameWorld][user]${user}`);
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * hook捕获玩家游戏日志
     * @param gm HookEvent实例
     */
    historyLog(gm: any): void {
        // cHistoryTrace::operator()
        Interceptor.attach(ptr(hookType.History_Log), {
            onEnter: function (args) {
                const history_log = args[1].readUtf8String(-1);
                const group = history_log?.split(',');
                const game_event = group ? group[13].slice(1) : null; // 玩家游戏事件 删除多余空格
                gm.logger(`[HistoryLog]${game_event}`);
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * 服务端把稀有度超过5 retval.replace(3) 解决需要2个PVF问题
     * @param gm HookEvent实例
     */
    rarityExtension(gm: any): void {
        // CItem::get_rarity(CItem *this)
        Interceptor.attach(ptr(hookType.Rarity_Extension), {
            onLeave: function (retval) {
                // @ts-ignore
                if (retval > 5) retval.replace(3);
            }
        });
    },
    /**
     * 角色副本相关缓存 Cache
     *  - characNo 角色id
     *    - startTime 副本开始时间
     *    - duration 通关时长
     *    - cparty_item_slot 辅助检查物品位置slot
     **/
    user_map_obj: {},
    /**
     * 魔法封印自动解封/分解时装 辅助检查CParty_Item_Slot
     * @param gm HookEvent实例
     */
    autoUnsealEquipment(gm: any): void {
        // CInventory::insertItemIntoInventory
        const user_map_obj = this.user_map_obj as any;
        Interceptor.attach(ptr(hookType.Unseal_Equipment), {
            onEnter: function (args) {
                this.user = args[0].readPointer();
            },
            onLeave: function (retval) {
                // 物品栏新增物品的位置
                const slot = retval.toInt32();
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                if (!user_map_obj[characNo]) {
                    user_map_obj[characNo] = {};
                }
                user_map_obj.cparty_item_slot = slot;
                gm.logger('[CParty_Item_Slot]', slot);
            }
        });
    },
    /**
     * 角色在地下城副本中拾取物品
     * @param gm HookEvent实例
     **/
    CPartyGetItem(gm: any): void {
        // char __cdecl CParty::_onGetItem(CParty *this, CUser *a2, unsigned int a3, unsigned int a4)
        const user_map_obj = this.user_map_obj as any;

        Interceptor.attach(ptr(hookType.CParty_Get_Item), {
            onEnter: function (args) {
                const user = args[1];
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(user);
                const item_id = args[2].toInt32(); // 取值范围
                let num = args[3].toInt32();
                const item_name = gm.api_CItem_getItemName(item_id);
                const charac_name = gm.api_CUserCharacInfo_getCurCharacName(user);
                const itemData = HookNative.CDataManager_find_item(HookNative.G_CDataManager(), item_id);
                let CParty_Item_Slot = user_map_obj[characNo]?.cparty_item_slot;

                // 通过魔法封印自动解封 检验slot
                if (CParty_Item_Slot) {
                    // 角色背包
                    let inven = HookNative.CUserCharacInfo_getCurCharacInvenW(user);
                    // 背包中新增的道具 暂时不知道如何获得slot(物品位置)
                    let inven_item = HookNative.CInventory_GetInvenRef(inven, INVENTORY_TYPE.ITEM, CParty_Item_Slot);
                    // 过滤道具类型
                    if (HookNative.Inven_Item_isEquipableItemType(inven_item)) {
                        num = 1;
                        user_map_obj[characNo].cparty_item_slot = null;
                    }
                }

                // 0白装 1蓝装 2紫装 3粉装 4异界？ 5史诗
                const ItemRarity = HookNative.CItem_getRarity(itemData); // 稀有度
                // 装备数量不可以通过 num 获取
                gm.logger('ItemRarity', ItemRarity);
                if (ItemRarity >= 3) {
                    gm.api_GameWorld_SendNotiPacketMessage(`恭喜「${charac_name}」捡起了传说中的[${item_name}]${num}个`, 14);
                }
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * 获取副本通关时长
     * @param gm HookEvent实例
     **/
    CPartyGetPlayTick(gm: any): void {
        const user_map_obj = this.user_map_obj as any;

        // 选择副本难度时, 获取难度参数
        // Interceptor.attach(ptr(hookType.Dungeon_Difficult), {
        //     onEnter: function (args) {
        //         const dungeon_difficult = args[2].toInt32();
        //         gm.logger(`[Dungeon_Difficult]${[dungeon_difficult]}`);
        //     }
        // });

        // 进入副本
        Interceptor.attach(ptr(hookType.Dungeon_Start), {
            onEnter: function (args) {
                this.user = args[1];
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                if (!user_map_obj[characNo]) {
                    user_map_obj[characNo] = {};
                }
                user_map_obj[characNo].startTime = gm.local_getSysUTCSec();
                gm.logger(`[Dungeon_Start]${[this.user]}`);
            }
        });

        // 放弃副本
        Interceptor.attach(ptr(hookType.Dungeon_GiveUp), {
            onEnter: function (args) {
                this.user = args[1];
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                user_map_obj[characNo] = null;
                gm.logger(`[Dungeon_GiveUp]${[this.user]}`);
            }
        });

        // 副本房间怪物死亡
        // Interceptor.attach(ptr(hookType.Dungeon_Mob_Die), {
        //     onEnter: function (args) {
        //         this.user = args[1];
        //         const monster_id = args[2].toInt32();
        //         gm.logger(`[Dungeon_Mob_Die]${[monster_id]}`);
        //     },
        //     onLeave: function (retval) {}
        // });

        // 通关地下城(触发2次 hookType存在问题)
        Interceptor.attach(ptr(hookType.Dungeon_Clear), {
            onEnter: function (args) {
                this.user = args[1];
                gm.logger(`[Dungeon_Clear]${[this.user]}`);
            }
        });

        // 副本完成(翻牌通关经验奖励)
        Interceptor.attach(ptr(hookType.Dungeon_Finish), {
            onEnter: function (args) {
                this.user = args[1];
                gm.logger(`[Dungeon_Finish]${[this.user]}`);
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                const dungeonName = gm.api_CDungeon_getDungeonName(HookNative.getDungeonIdxAfterClear(this.user));
                const endTime = gm.local_getSysUTCSec();
                const startTime = user_map_obj[characNo]?.startTime;
                const duration = endTime - startTime;

                if (duration && startTime && endTime && duration > 0) {
                    user_map_obj[characNo].startTime = null;
                    user_map_obj[characNo].duration = duration;
                    gm.api_GameWorld_SendNotiPacketMessage(`玩家[${gm.api_CUserCharacInfo_getCurCharacName(this.user)}]${gm.formatTime(duration)}通关了地下城[${dungeonName}]`, 16);
                }
            }
        });
    },

    /**
     * 测试
     * @param gm HookEvent实例
     **/
    debugCode(gm: any): void {}
};

export default _HookGameEvent;
