/**
 * 修复时装镶嵌
 * */
import GameNative from '@/native/GameNative';
import { INVENTORY_TYPE } from '@/enum/enum';
import gmt from '@/game/Gmt';
import User from '@/game/User';

// 获取时装在数据库中的uid
function api_get_avartar_ui_id(avartar: any): any {
    return avartar.add(7).readInt();
}

// 设置时装插槽数据(时装插槽数据指针, 插槽, 徽章id)
// jewel_type: 红=0x1, 黄=0x2, 绿=0x4, 蓝=0x8, 白金=0x10
function api_set_JewelSocketData(jewelSocketData: any, slot: any, emblem_item_id: number): void {
    if (!jewelSocketData.isNull()) {
        // 每个槽数据长6个字节: 2字节槽类型+4字节徽章item_id
        // 镶嵌不改变槽类型, 这里只修改徽章id
        jewelSocketData.add(slot * 6 + 2).writeInt(emblem_item_id);
    }
    return;
}

/**
 * 修复时装镶嵌
 * dnf.exe版本
 * 0627 是 1.1180.2.1 不支持
 * 0725 是 1.1200.4.1 支持
 * 1031 是 1.1260.5.1 支持
 * */
function fix_use_emblem(): void {
    // Dispatcher_UseJewel::dispatch_sig
    Interceptor.attach(ptr(0x8217bd6), {
        onEnter: function (args) {
            try {
                const user = args[1];
                const CUser = new User(user);
                const packet_buf = args[2];
                // 校验角色状态是否允许镶嵌
                const state = GameNative.CUser_GetState(user);
                if (state != 3) {
                    return;
                }
                // 解析packet_buf
                // 时装所在的背包槽
                const avartar_inven_slot = gmt.api_PacketBuf_get_short(packet_buf);
                // 时装item_id
                const avartar_item_id = gmt.api_PacketBuf_get_int(packet_buf);
                // 本次镶嵌徽章数量
                const emblem_cnt = gmt.api_PacketBuf_get_byte(packet_buf);
                // 获取时装道具
                const inven = GameNative.CUser_getCurCharacInvenW(user);
                const avartar = GameNative.CInventory_GetInvenRef(inven, INVENTORY_TYPE.AVARTAR, avartar_inven_slot);
                // 校验时装 数据是否合法
                if (
                    GameNative.Inven_Item_isEmpty(avartar) ||
                    GameNative.Inven_Item_getKey(avartar) != avartar_item_id ||
                    GameNative.CUser_CheckItemLock(user, 2, avartar_inven_slot)
                ) {
                    return;
                }
                // 获取时装插槽数据
                const avartar_add_info = GameNative.Inven_Item_get_add_info(avartar);
                const inven_avartar_mgr = GameNative.CInventory_GetAvatarItemMgrR(inven);
                const jewel_socket_data = GameNative.WongWork_CAvatarItemMgr_getJewelSocketData(inven_avartar_mgr, avartar_add_info);

                if (jewel_socket_data.isNull()) {
                    return;
                }
                // 最多只支持3个插槽
                if (emblem_cnt <= 3) {
                    const emblems = {} as any;
                    for (let i = 0; i < emblem_cnt; i++) {
                        // 徽章所在的背包槽
                        const emblem_inven_slot = gmt.api_PacketBuf_get_short(packet_buf);
                        // 徽章item_id
                        const emblem_item_id = gmt.api_PacketBuf_get_int(packet_buf);
                        // 该徽章镶嵌的时装插槽id
                        const avartar_socket_slot = gmt.api_PacketBuf_get_byte(packet_buf);
                        //log('emblem_inven_slot=' + emblem_inven_slot + ', emblem_item_id=' + emblem_item_id + ', avartar_socket_slot=' + avartar_socket_slot);
                        // 获取徽章道具
                        const emblem = GameNative.CInventory_GetInvenRef(inven, INVENTORY_TYPE.ITEM, emblem_inven_slot);
                        // 校验徽章及插槽数据是否合法
                        if (GameNative.Inven_Item_isEmpty(emblem) || GameNative.Inven_Item_getKey(emblem) != emblem_item_id || avartar_socket_slot >= 3) {
                            return;
                        }
                        // 校验徽章是否满足时装插槽颜色要求
                        // 获取徽章pvf数据
                        const citem = GameNative.CDataManager_find_item(GameNative.G_CDataManager(), emblem_item_id);
                        if (citem.isNull()) {
                            return;
                        }
                        // 校验徽章类型
                        if (!GameNative.CItem_is_stackable(citem) || GameNative.CStackableItem_GetItemType(citem) != 20) {
                            return;
                        }
                        // 获取徽章支持的插槽
                        const emblem_socket_type = GameNative.CStackableItem_getJewelTargetSocket(citem);
                        // 获取要镶嵌的时装插槽类型
                        const avartar_socket_type = jewel_socket_data.add(avartar_socket_slot * 6).readShort();
                        if (!(emblem_socket_type & avartar_socket_type)) {
                            // 插槽类型不匹配
                            //log('socket type not match!');
                            return;
                        }
                        emblems[avartar_socket_slot] = [emblem_inven_slot, emblem_item_id];
                    }
                    // 开始镶嵌
                    for (const avartar_socket_slot in emblems) {
                        // 删除徽章
                        const emblem_inven_slot = emblems[avartar_socket_slot][0];
                        GameNative.CInventory_delete_item(inven, 1, emblem_inven_slot, 1, 8, 1);
                        // 设置时装插槽数据
                        const emblem_item_id = emblems[avartar_socket_slot][1];
                        api_set_JewelSocketData(jewel_socket_data, avartar_socket_slot, emblem_item_id);
                        //log('徽章item_id=' + emblem_item_id + '已成功镶嵌进avartar_socket_slot=' + avartar_socket_slot + '的槽内!');
                    }
                    // 时装插槽数据存档
                    GameNative.DB_UpdateAvatarJewelSlot_makeRequest(CUser.GetCharacNo(), api_get_avartar_ui_id(avartar), jewel_socket_data);
                    // 通知客户端时装数据已更新
                    GameNative.CUser_SendUpdateItemList(user, 1, 1, avartar_inven_slot);
                    // 回包给客户端
                    const packet_guard = gmt.api_PacketGuard_PacketGuard();
                    GameNative.InterfacePacketBuf_put_header(packet_guard, 1, 204);
                    GameNative.InterfacePacketBuf_put_int(packet_guard, 1);
                    GameNative.InterfacePacketBuf_finalize(packet_guard, 1);
                    GameNative.CUser_Send(user, packet_guard);
                    GameNative.Destroy_PacketGuard_PacketGuard(packet_guard);
                    //log('镶嵌请求已处理完成!');
                }
            } catch (error) {
                console.log('fix_use_emblem throw Exception:' + error);
            }
        },
        onLeave: function (retval) {
            // 返回值改为0  不再踢线
            // @ts-ignore
            retval.replace(0);
        }
    });
}

export default fix_use_emblem;
