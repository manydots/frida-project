import hookType, { HookNative } from './HookType';
import { INVENTORY_TYPE, ENUM_ITEMSPACE } from '../enum/enum';
import { logger, get_timestamp, formatTime } from '../utils/tool';
import Gmt from '@/game/Gmt';
import Party from '@/game/Party';
import User from '@/game/User';

const gmt = Gmt.getInstance();

interface Params {
    repair?: boolean; // 是否自动修理
}

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
                logger(`[Reach_GameWorld][user]${this.user}`);
            },
            // 原函数执行完毕, 这里可以得到并修改返回值retval
            onLeave: function (retval) {
                let CUser = new User(this.user);
                let characName = CUser.GetCharacName();
                // 发送频道消息
                gmt.SendNotiPacketMessage(`玩家[${characName}]上线了`); // 消息格式1
                // gmt.SendGMMessage(`玩家上线了`, characName, 15, 110); // [角色名可添加好友]消息格式2
                // gmt.SendGMMessage(`玩家上线了`, characName, 33, 11); // [私聊]消息格式3
            }
        });
        // 角色退出处理函数
        Interceptor.attach(ptr(hookType.Leave_GameWorld), {
            onEnter: function (args) {
                const user = args[0];
                logger(`[Leave_GameWorld][user]${user}`);
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
                logger(`[HistoryLog]${game_event}`);
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
                user_map_obj[characNo].cparty_item_slot = slot;
                logger('[CParty_Item_Slot]', slot);
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
                logger('ItemRarity', ItemRarity);
                if (ItemRarity >= 2) {
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
    CPartyGetPlayTick(gm: any, params?: Params): void {
        const user_map_obj = this.user_map_obj as any;
        const autoRepair = params?.repair ?? false;
        const _self = this;

        // 选择副本难度时, 获取难度参数
        Interceptor.attach(ptr(hookType.Dungeon_Difficult), {
            onEnter: function (args) {
                const dungeonId = args[1].toInt32();
                const dungeon_difficult = args[2].toInt32();
                const happyParty = args[3]; // 是否进入深渊
                logger(`[Dungeon_Difficult]${[dungeon_difficult]}[dungeonId:${dungeonId}][happyParty:${happyParty}]`);
            }
        });

        // 进入副本
        Interceptor.attach(ptr(hookType.Dungeon_Start), {
            onEnter: function (args) {
                this.user = args[1];
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                if (!user_map_obj[characNo]) {
                    user_map_obj[characNo] = {};
                }
                user_map_obj[characNo].startTime = gm.local_getSysUTCSec();
                logger(`[Dungeon_Start]${[this.user]}`);

                // 开启自动修理
                if (autoRepair) {
                    _self.autoRepairEqu(gm, this.user);
                }
            },
            onLeave: function (retval) {
                const CParty = new Party(this.user);
                const CPartyItem = CParty.GetDungeonItem();
                logger(`[Interceptor][${CPartyItem.pointer}][${CPartyItem.dungeonId}]`);
                gm.api_CUser_SendNotiPacketMessage(this.user, `进入地下城[${CPartyItem.name}] Lv.${CPartyItem.level}`, 1); // 给角色发消息
            }
        });

        // 放弃副本
        Interceptor.attach(ptr(hookType.Dungeon_GiveUp), {
            onEnter: function (args) {
                this.user = args[1];
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                user_map_obj[characNo] = null;
                logger(`[Dungeon_GiveUp]${[this.user]}`);
            }
        });

        // 副本房间怪物死亡
        // Interceptor.attach(ptr(hookType.Dungeon_Mob_Die), {
        //     onEnter: function (args) {
        //         this.user = args[1];
        //         const monster_id = args[2].toInt32();
        //         logger(`[Dungeon_Mob_Die]${[monster_id]}`);
        //     },
        //     onLeave: function (retval) {}
        // });

        // 通关地下城(触发2次 hookType存在问题)
        Interceptor.attach(ptr(hookType.Dungeon_Clear), {
            onEnter: function (args) {
                this.user = args[1];
                logger(`[Dungeon_Clear]${[this.user]}`);
            }
        });

        // 副本完成(翻牌通关经验奖励)
        Interceptor.attach(ptr(hookType.Dungeon_Finish), {
            onEnter: function (args) {
                this.user = args[1];
                logger(`[Dungeon_Finish]${[this.user]}`);
                const characNo = HookNative.CUserCharacInfo_getCurCharacNo(this.user);
                const dungeonName = gm.api_CDungeon_getDungeonName(HookNative.getDungeonIdxAfterClear(this.user));
                const endTime = gm.local_getSysUTCSec();
                const startTime = user_map_obj[characNo]?.startTime;
                const duration = endTime - startTime;

                if (duration && startTime && endTime && duration > 0) {
                    user_map_obj[characNo].startTime = null;
                    user_map_obj[characNo].duration = duration;
                    gm.api_GameWorld_SendNotiPacketMessage(`玩家[${gm.api_CUserCharacInfo_getCurCharacName(this.user)}]${formatTime(duration)}通关了地下城[${dungeonName}]`, 16);
                }
            }
        });
    },
    /**
     * 玩家指令监听
     * @param gm HookEvent实例
     **/
    GmInput(gm: any): void {
        // HOOK Dispatcher_New_Gmdebug_Command::dispatch_sig
        const _self = this;
        const pattern = /\/\/\s*?use\s+(\d+)\s*?/; // //use 1234
        const showEqu = /\/\/\s*?show\s+([a-zA-Z]+)\s*?/; // //use 1234

        Interceptor.attach(ptr(hookType.GmInput), {
            onEnter: function (args) {
                const user = args[1];
                // 获取原始封包数据
                const raw_packet_buf = gm.api_PacketBuf_get_buf(args[2]);
                // 解析GM DEBUG命令
                const gm_len = raw_packet_buf.readInt();
                const gm_text = raw_packet_buf.add(4).readUtf8String(gm_len);
                const match = gm_text.match(pattern);
                const matchEqu = gm_text.match(showEqu);
                if (matchEqu && matchEqu[1] == 'equ') {
                    _self.autoRepairEqu(gm, user);
                }
                logger('[GmInput]', match ? match[1] : gm_text);
            },
            onLeave: function (retval) {}
        });
    },

    /**
     * 自动修理装备
     * @param gm HookEvent实例
     * @param user User指针
     * @param max 测试手动设置耐久
     **/
    autoRepairEqu(gm: any, user: any, max?: number): void {
        // gm.api_CUser_SendNotiPacketMessage(user, `[${get_timestamp()}]:已自动修理装备`, 8); // 给角色发消息
        // 遍历身上的装备
        const inven = HookNative.CUserCharacInfo_getCurCharacInvenW(user); // 获取角色背包
        for (let slot = 10; slot <= 21; slot++) {
            const equ = HookNative.CInventory_GetInvenRef(inven, INVENTORY_TYPE.BODY, slot);
            const item_id = HookNative.Inven_Item_getKey(equ);

            if (item_id) {
                const detail = gm.api_CItem_getItemDetail(item_id);
                const durability = equ.add(11).readU16(); // 当前耐久
                const item_data = gm.find_item(item_id);
                const durability_max = HookNative.CEquipItem_get_endurance(item_data); // 最大耐久

                // 当前耐久小于最大耐久修理
                if (durability_max > 0 && durability < durability_max) {
                    gm.api_CUser_SendNotiPacketMessage(user, `[${detail.name}]：耐久[${durability}]`, 2); // 给角色发消息
                    // logger(`[${item_id}]durability:${durability}`);
                    equ.add(11).writeU16(max ?? durability_max); // 写入耐久
                    // (客户端指针, 通知方式[仅客户端=1, 世界广播=0, 小队=2, war room=3], itemSpace[装备=0, 时装=1], 道具所在的背包槽)
                    // HookNative.CUser_SendUpdateItemList(user, 0, ENUM_ITEMSPACE.INVENTORY, slot);
                }
            }
        }
        HookNative.CUser_SendNotiPacket(user, 1, 2, 3);
    },

    /**
     * 解锁全部表情
     * @param gm HookEvent实例
     **/
    UnlockEmoji(gm: any): void {
        Interceptor.attach(ptr(hookType.Unlock_Emoji1), {
            onEnter: function (args) {},
            onLeave: function (retval) {
                // @ts-ignore
                retval.replace(1);
            }
        });
        Interceptor.attach(ptr(hookType.Unlock_Emoji2), {
            onEnter: function (args) {},
            onLeave: function (retval) {
                // @ts-ignore
                retval.replace(1);
            }
        });
    },

    /**
     * 解锁副本门口摆摊 PrivateStore
     * @param gm HookEvent实例
     **/
    IgnoreNearDungeon(): void {
        Interceptor.attach(ptr(hookType.Ignore_Near_Dungeon), {
            onEnter: function (args) {},
            onLeave: function (retval) {
                // @ts-ignore
                retval.replace(1);
            }
        });
    },

    /**
     * 允许赛利亚房间的人互相可见
     */
    share_seria_room(): void {
        // Hook Area::insert_user
        Interceptor.attach(ptr(0x86c25a6), {
            onEnter: function (args) {
                // 修改标志位, 让服务器广播赛利亚旅馆消息
                args[0].add(0x68).writeInt(0);
            },
            onLeave: function (retval) {}
        });
    },

    /**
     * 史诗免确认
     */
    cancel_epic_ok(): void {
        Memory.patchCode(ptr(0x085a56ce).add(2), 1, function (code) {
            const cw = new X86Writer(code, { pc: ptr(0x085a56ce).add(2) });
            cw.putU8(9);
            cw.flush();
        });
        Interceptor.attach(ptr(0x08150f18), {
            onLeave: function (retval) {
                // @ts-ignore
                retval.replace(0);
            }
        });
    },

    /**
     * 开启创建缔造
     */
    enable_createCreator(): void {
        Memory.patchCode(ptr(0x081c029e).add(1), 1, function (code) {
            const cw = new X86Writer(code, { pc: ptr(0x081c029e).add(1) });
            cw.putU8(11);
            cw.flush();
        });
    },

    /**
     * 测试
     * @param gm HookEvent实例
     **/
    debugCode(gm: any, params?: object): void {
        logger('[debugCode]', JSON.stringify(params || {}));
    }
};

export default _HookGameEvent;
