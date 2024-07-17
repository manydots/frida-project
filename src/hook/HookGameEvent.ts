import hookType from './HookType';
import GameNative from '@/game/GameNative';
import { INVENTORY_TYPE } from '@/enum/enum';
import Gmt from '@/game/Gmt';
import Party from '@/game/Party';
import User from '@/game/User';

const gmt = Gmt.getInstance();

interface Params {
    repair?: boolean; // 是否自动修理
    upgrade_level?: number; // 处理增幅、强化小于upgrade_level 必成功
}

const _HookGameEvent = {
    /**
     *  角色登入登出处理
     */
    userLogout(): void {
        // 选择角色处理函数
        Interceptor.attach(ptr(hookType.Reach_GameWorld), {
            // 函数入口, 拿到函数参数args
            onEnter: function (args) {
                // 保存函数参数
                this.user = args[1];
                gmt.logger(`[Reach_GameWorld][user]${this.user}`);
            },
            // 原函数执行完毕, 这里可以得到并修改返回值retval
            onLeave: function (retval) {
                const CUser = new User(this.user);
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
                gmt.logger(`[Leave_GameWorld][user]${user}`);
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * hook捕获玩家游戏日志
     */
    historyLog(): void {
        // cHistoryTrace::operator()
        Interceptor.attach(ptr(hookType.History_Log), {
            onEnter: function (args) {
                const history_log = args[1].readUtf8String(-1);
                const group = history_log?.split(',');
                const game_event = group ? group[13].slice(1) : null; // 玩家游戏事件 删除多余空格
                gmt.logger(`[HistoryLog]${game_event}`);
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * 服务端把稀有度超过5 retval.replace(3) 解决需要2个PVF问题
     */
    rarityExtension(): void {
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
     */
    autoUnsealEquipment(): void {
        // CInventory::insertItemIntoInventory
        const user_map_obj = this.user_map_obj as any;
        Interceptor.attach(ptr(hookType.Unseal_Equipment), {
            onEnter: function (args) {
                this.user = args[0].readPointer();
            },
            onLeave: function (retval) {
                const CUser = new User(this.user);
                // 物品栏新增物品的位置
                const slot = retval.toInt32();
                const characNo = CUser.GetCharacNo();
                if (!user_map_obj[characNo]) {
                    user_map_obj[characNo] = {};
                }
                user_map_obj[characNo].cparty_item_slot = slot;
                gmt.logger('[CParty_Item_Slot]', slot);
            }
        });
    },
    /**
     * 角色在地下城副本中拾取物品
     **/
    CPartyGetItem(): void {
        // char __cdecl CParty::_onGetItem(CParty *this, CUser *a2, unsigned int a3, unsigned int a4)
        const user_map_obj = this.user_map_obj as any;

        Interceptor.attach(ptr(hookType.CParty_Get_Item), {
            onEnter: function (args) {
                const user = args[1];
                const CUser = new User(user);
                const characNo = CUser.GetCharacNo();
                const item_id = args[2].toInt32(); // 取值范围
                let num = args[3].toInt32();
                const item_name = gmt.GetItemName(item_id);
                const charac_name = CUser.GetCharacName();
                const itemData = gmt.FindItem(item_id);
                let CParty_Item_Slot = user_map_obj[characNo]?.cparty_item_slot;

                // 通过魔法封印自动解封 检验slot
                if (CParty_Item_Slot) {
                    // 角色背包
                    let inven = CUser.GetCurCharacInvenW();
                    // 背包中新增的道具 暂时不知道如何获得slot(物品位置)
                    let inven_item = GameNative.CInventory_GetInvenRef(inven, INVENTORY_TYPE.ITEM, CParty_Item_Slot);
                    // 过滤道具类型
                    if (GameNative.Inven_Item_isEquipableItemType(inven_item)) {
                        num = 1;
                        user_map_obj[characNo].cparty_item_slot = null;
                    }
                }

                // 0白装 1蓝装 2紫装 3粉装 4异界？ 5史诗
                const ItemRarity = GameNative.CItem_getRarity(itemData); // 稀有度
                // 装备数量不可以通过 num 获取
                gmt.logger('ItemRarity', ItemRarity);
                if (ItemRarity >= 2) {
                    gmt.SendNotiPacketMessage(`恭喜「${charac_name}」捡起了传说中的[${item_name}]${num}个`, 14);
                }
            },
            onLeave: function (retval) {}
        });
    },
    /**
     * 获取副本通关时长
     **/
    CPartyGetPlayTick(params?: Params): void {
        const user_map_obj = this.user_map_obj as any;
        const autoRepair = params?.repair ?? false;
        const _self = this;

        // 进入副本
        Interceptor.attach(ptr(hookType.Dungeon_Start), {
            onEnter: function (args) {
                this.user = args[1];
                const CUser = new User(this.user);
                const characNo = CUser.GetCharacNo();
                if (!user_map_obj[characNo]) {
                    user_map_obj[characNo] = {};
                }
                user_map_obj[characNo].startTime = gmt.getSysUTCSec();
                gmt.logger(`[Dungeon_Start]${[this.user]}`);

                // 开启自动修理
                if (autoRepair) {
                    _self.autoRepairEqu(this.user);
                }
            },
            onLeave: function (retval) {
                const CParty = new Party(this.user);
                const CUser = new User(this.user);
                const CPartyItem = CParty.GetDungeonItem();
                // gmt.logger(`[Interceptor][${CPartyItem.pointer}][${CPartyItem.dungeonId}]`);
                CUser.SendNotiPacketMessage(`进入地下城[${CPartyItem.name}] Lv.${CPartyItem.level}`, 8); // 给角色发消息
            }
        });

        // 选择副本难度时, 获取难度参数
        Interceptor.attach(ptr(hookType.Dungeon_Difficult), {
            onEnter: function (args) {
                // const CParty = args[0];
                // const dungeonId = args[1].toInt32();
                const dungeon_difficult = args[2].toInt32();
                // const happyParty = args[3]; // 是否进入深渊
                gmt.logger(`[Difficult]${dungeon_difficult}`);
            }
        });

        // 放弃副本
        Interceptor.attach(ptr(hookType.Dungeon_GiveUp), {
            onEnter: function (args) {
                this.user = args[1];
                const CUser = new User(this.user);
                const characNo = CUser.GetCharacNo();
                user_map_obj[characNo] = null;
                gmt.logger(`[Dungeon_GiveUp]${[this.user]}`);
            }
        });

        // 副本房间怪物死亡
        // Interceptor.attach(ptr(hookType.Dungeon_Mob_Die), {
        //     onEnter: function (args) {
        //         this.user = args[1];
        //         const monster_id = args[2].toInt32();
        //         gmt.logger(`[Dungeon_Mob_Die]${[monster_id]}`);
        //     },
        //     onLeave: function (retval) {}
        // });

        // 通关地下城(触发2次)
        Interceptor.attach(ptr(hookType.Dungeon_Clear), {
            onEnter: function (args) {
                this.user = args[1];
            },
            onLeave: function (retval) {
                gmt.logger(`[Dungeon_Clear]${[this.user]}`);
            }
        });

        // 副本完成(翻牌通关经验奖励)
        Interceptor.attach(ptr(hookType.Dungeon_Finish), {
            onEnter: function (args) {
                this.user = args[1];
                const CUser = new User(this.user);
                const CParty = new Party(this.user);

                gmt.logger(`[Dungeon_Finish]${[this.user]}`);
                const characNo = CUser.GetCharacNo();
                const dungeonName = CParty.GetDungeonName();
                const endTime = gmt.getSysUTCSec();
                const startTime = user_map_obj[characNo]?.startTime;
                const duration = endTime - startTime;

                if (duration && startTime && endTime && duration > 0) {
                    user_map_obj[characNo].startTime = null;
                    user_map_obj[characNo].duration = duration;
                    gmt.SendNotiPacketMessage(`玩家[${CUser.GetCharacName()}]${gmt.formatTime(duration)}通关了地下城[${dungeonName}]`, 16);
                }
            }
        });
    },
    /**
     * 玩家指令监听
     **/
    GmInput(): void {
        // HOOK Dispatcher_New_Gmdebug_Command::dispatch_sig
        const _self = this;
        const pattern = /\/\/\s*?use\s+(\d+)\s*?/; // //use 1234
        const showEqu = /\/\/\s*?show\s+([a-zA-Z]+)\s*?/; // //use 1234

        Interceptor.attach(ptr(hookType.GmInput), {
            onEnter: function (args) {
                const user = args[1];
                // 获取原始封包数据
                const raw_packet_buf = gmt.api_PacketBuf_get_buf(args[2]);
                // 解析GM DEBUG命令
                const gm_len = raw_packet_buf.readInt();
                const gm_text = raw_packet_buf.add(4).readUtf8String(gm_len).slice(2);
                gmt.logger('[GmInput]', gm_text);
                /**
                 * 3299 虚空魔石
                 * 3037 无色小晶块
                 */
                // 以下为GM测试代码
                if (gm_text?.includes('test')) {
                    // console.log(gmt.GetPacketName(1, 18));
                    // console.log(gmt.GetPacketName(0, 18));
                    // _self.autoRepairEqu(user); // 自动修理
                    let CUser = new User(user);
                    CUser.Disjoint(9); // 9-24 装备前2行
                    // gmt.logger(CUser.GetItemCount(3037));
                    // CUser.AddItem(3299, 100); // 发送物品
                    // CUser.SetCurCharacStamina(50); // 设置角色虚弱值
                    // CUser.AddCharacExp(100000); // x 发送经验(此位置测试需要重新选择角色)
                    // CUser.ChargeCera(10000); // 点券充值
                    // CUser.ChargeCeraPoint(10000); // 代币充值
                    // 发送邮件
                    // CUser.SendMail([
                    //     [3299, 1],
                    //     [3037, 100]
                    // ]);
                    // let CParty = new Party(user);
                    // CParty.ReturnToVillage();
                }
            },
            onLeave: function (retval) {}
        });
    },

    /**
     * 自动修理装备
     * @param user User指针
     * @param max 手动设置耐久
     **/
    autoRepairEqu(user: any, max?: number): void {
        const CUser = new User(user);
        const inven = CUser.GetCurCharacInvenW(); // 获取角色背包
        // 遍历身上的装备
        for (let slot = 10; slot <= 21; slot++) {
            const equ = GameNative.CInventory_GetInvenRef(inven, INVENTORY_TYPE.BODY, slot);
            const item_id = GameNative.Inven_Item_getKey(equ);
            const upgrade_level = equ.add(6).readU8(); // 获取该装备的强化/增幅等级

            if (item_id) {
                const itemName = gmt.GetItemName(item_id);
                const durability = equ.add(11).readU16(); // 当前耐久
                const item_data = gmt.FindItem(item_id);
                const durability_max = GameNative.CEquipItem_get_endurance(item_data); // 最大耐久
                CUser.SendNotiPacketMessage(`[${itemName}]:${upgrade_level}`, 2);

                // 当前耐久小于最大耐久修理
                if (durability_max > 0 && durability < durability_max) {
                    CUser.SendNotiPacketMessage(`[${itemName}]：耐久[${durability}]`, 2); // 给角色发消息
                    // gmt.logger(`[${item_id}]durability:${durability}`);
                    equ.add(11).writeU16(max ?? durability_max); // 写入耐久
                    // (客户端指针, 通知方式[仅客户端=1, 世界广播=0, 小队=2, war room=3], itemSpace[装备=0, 时装=1], 道具所在的背包槽)
                    // GameNative.CUser_SendUpdateItemList(user, 0, ENUM_ITEMSPACE.INVENTORY, slot);
                }
            }
        }
        GameNative.CUser_SendNotiPacket(user, 1, 2, 3);
    },

    /**
     * 解锁全部表情
     **/
    UnlockEmoji(): void {
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
     * 重置强化/增幅结果
     */
    UpgradeItem(params?: Params): void {
        const upgrade_level = params?.upgrade_level ?? 10;
        Interceptor.attach(ptr(0x0854755a), {
            onEnter: function (args) {
                this.user = args[1];
                this.itemData = args[2];
                this.upgrade_level = this.itemData.add(6).readU8(); // 获取该装备的强化/增幅等级
            },
            onLeave: function (retval) {
                // @ts-ignore
                if (retval == 0 && this.upgrade_level <= upgrade_level) {
                    // 强化失败
                    gmt.logger(`Upgrade Fail,Retval Success.`);
                    GameNative.Inven_Item_IncUpgrade(this.itemData);
                    // @ts-ignore
                    retval.replace(1); // 返回强化成功
                }
                // @ts-ignore
                gmt.logger(`[Upgrade]${retval == 0 ? 'Fail' : 'Success'}`);
            }
        });
    },

    /**
     * useItem物品使用
     */
    UseItem1(): void {
        // __cdecl CParty::useItem(CParty *__hidden this, CUser *, const Inven_Item *)
        Interceptor.attach(ptr(hookType.UseItem1), {
            onEnter: function (args) {
                // gmt.logger(args[0], args[1]);
                // const item_id = GameNative.Inven_Item_getKey(args[1]);
                gmt.logger(`[UseItem1]${args[0]}`);
            },
            onLeave: function (retval) {}
        });
    },

    /**
     * 测试
     **/
    debugCode(params?: Params): void {
        gmt.logger('[debugCode]', JSON.stringify(params || {}));
    }
};

export default _HookGameEvent;
