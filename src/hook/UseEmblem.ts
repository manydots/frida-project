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

function lengthCutting(str: any, ystr: any, num: any, maxLength: any): any {
    //ByteArray转十六进制文本数据
    var strArr = '';
    var length = str.length;
    while (str.length < maxLength) {
        str = '0'.concat(str);
    }
    for (var i = 0; i < str.length; i += num) {
        strArr = str.slice(i, i + num).concat(strArr);
    }
    return ystr + strArr;
}

// cid 角色id
// 获取徽章数据,存在返回徽章数据,不存在返回空字节数据
function api_get_jewel_socket_data(mysql_frida: any, id: number) {
    gmt.api_MySQL_exec(mysql_frida, `SELECT jewel_data FROM data where equ_id = ${id};`);
    var v = Memory.alloc(30);
    v.add(0).writeU8(0);
    if (GameNative.MySQL_get_n_rows(mysql_frida) == 1) {
        if (GameNative.MySQL_fetch(mysql_frida)) {
            GameNative.MySQL_get_binary(mysql_frida, 0, v, 30);
        }
    }
    return v;
}

function api_exitjeweldata(id: number) {
    const mysql_frida = gmt.getMySQLHandle('frida');
    // 0代表不存在,存在返回1
    gmt.api_MySQL_exec(mysql_frida, `SELECT index_flag FROM data where equ_id = ${id};`);
    let exit = 0;
    if (GameNative.MySQL_get_n_rows(mysql_frida) == 1) {
        if (GameNative.MySQL_fetch(mysql_frida)) {
            exit = gmt.api_MySQL_get_int(mysql_frida, 0);
        }
    }
    // console.log('exit--->', exit);
    return exit;
}

function save_equiment_socket(socket_data: any, id: number) {
    const mysql_frida = gmt.getMySQLHandle('frida');
    //0 代表保存失败 成功返回1
    if (gmt.api_MySQL_exec(mysql_frida, `UPDATE data SET jewel_data = 0x${socket_data} WHERE equ_id = ${id};`) == 1) {
        return 1;
    }
    return 0;
}

function add_equiment_socket(equipment_type: any) {
    const mysql_frida = gmt.getMySQLHandle('frida');
    // 0代表开孔失败 成功返回标识
    /* 武器10 称号11 上衣12 头肩13 下衣14 鞋子15 腰带16 项链17 手镯18 戒指19 辅助装备20 魔法石21 */
    /*
    红色:'010000000000010000000000000000000000000000000000000000000000'   A
    黄色:'020000000000020000000000000000000000000000000000000000000000'   B
    绿色:'040000000000040000000000000000000000000000000000000000000000'   C
    蓝色:'080000000000080000000000000000000000000000000000000000000000'   D
    白金:'100000000000100000000000000000000000000000000000000000000000'   
    */
    var DB_JewelsocketData = '';
    switch (equipment_type) {
        case 10: // 武器10 SS
            DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000';
            break;
        case 11: //称号11 SS
            DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000';
            break;
        case 12: //上衣12 C
            DB_JewelsocketData = '040000000000040000000000000000000000000000000000000000000000';
            break;
        case 13: //头肩13 B
            DB_JewelsocketData = '020000000000020000000000000000000000000000000000000000000000';
            break;
        case 14: //下衣14 C
            DB_JewelsocketData = '040000000000040000000000000000000000000000000000000000000000';
            break;
        case 15: //鞋子15 D
            DB_JewelsocketData = '080000000000080000000000000000000000000000000000000000000000';
            break;
        case 16: //腰带16 A
            DB_JewelsocketData = '010000000000010000000000000000000000000000000000000000000000';
            break;
        case 17: //项链17 B
            DB_JewelsocketData = '020000000000020000000000000000000000000000000000000000000000';
            break;
        case 18: //手镯18 D
            DB_JewelsocketData = '080000000000080000000000000000000000000000000000000000000000';
            break;
        case 19: //戒指19 A
            DB_JewelsocketData = '010000000000010000000000000000000000000000000000000000000000';
            break;
        case 20: // 辅助装备20 SS
            DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000';
            break;
        case 21: // 魔法石21 SS
            DB_JewelsocketData = '100000000000000000000000000000000000000000000000000000000000';
            break;
        default:
            DB_JewelsocketData = '000000000000000000000000000000000000000000000000000000000000';
            break;
    }
    var date = gmt.get_timestamp();
    // console.log(`INSERT INTO data(index_flag, jewel_data, date) VALUES(1, 0x${DB_JewelsocketData}, '${date}');`);
    if (gmt.api_MySQL_exec(mysql_frida, `INSERT INTO data(index_flag, jewel_data, date) VALUES(1, 0x${DB_JewelsocketData}, '${date}');`) == 1) {
        gmt.api_MySQL_exec(mysql_frida, `SELECT equ_id FROM data where date = '${date}';`);
        if (GameNative.MySQL_get_n_rows(mysql_frida) == 1) {
            if (GameNative.MySQL_fetch(mysql_frida)) {
                return gmt.api_MySQL_get_int(mysql_frida, 0);
            }
        }
    }
    return 0;
}

function CUser_SendUpdateItemList_DB(CUser: any, Slot: any, DB_JewelSocketData: any) {
    // 防装备刷新函数,带镶嵌数据的刷新函数
    var v10 = gmt.api_PacketGuard_PacketGuard();
    GameNative.InterfacePacketBuf_put_header(v10, 0, 14);
    GameNative.InterfacePacketBuf_put_byte(v10, 0);
    GameNative.InterfacePacketBuf_put_short(v10, 1);
    var v4 = GameNative.CUser_getCurCharacInvenW(CUser);
    GameNative.CInventory_MakeItemPacket(v4, 1, Slot, v10);
    GameNative.InterfacePacketBuf_put_binary(v10, DB_JewelSocketData, 30);
    GameNative.InterfacePacketBuf_finalize(v10, 1);
    GameNative.CUser_Send(CUser, v10);
    GameNative.Destroy_PacketGuard_PacketGuard(v10);
}

/**
 * 修复时装镶嵌
 * dnf.exe版本
 * 0627 是 1.180.2.1 客户端插件支持
 * 0725 是 1.200.4.1 支持
 * 1031 是 1.260.5.1 支持
 * */
function fix_use_emblem(): void {
    // Dispatcher_UseJewel::dispatch_sig

    // 称号回包
    Interceptor.replace(
        ptr(0x08641a6a),
        new NativeCallback(
            function (CTitleBook, PacketGuard, a3, Inven_Item) {
                var JewelSocketData = Memory.alloc(30);
                var ret = GameNative.CTitleBook_putItemData(CTitleBook, PacketGuard, a3, Inven_Item);
                const mysql_frida = gmt.getMySQLHandle('frida');
                JewelSocketData = api_get_jewel_socket_data(mysql_frida, Inven_Item.add(25).readU32());
                if (JewelSocketData.add(0).readU8() != 0) {
                    GameNative.InterfacePacketBuf_put_binary(PacketGuard, JewelSocketData, 30);
                    return ret;
                }
                return ret;
            },
            'int',
            ['pointer', 'pointer', 'int', 'pointer']
        )
    );

    // 设计图继承
    Interceptor.replace(
        ptr(0x08671eb2),
        new NativeCallback(
            function (CUser, Inven_Item1, Inven_Item2) {
                var jewelSocketID = Inven_Item2.add(25).readU32();
                Inven_Item1.add(25).writeU32(jewelSocketID);
                return GameNative.CUser_copyItemOption(CUser, Inven_Item1, Inven_Item2);
            },
            'int',
            ['pointer', 'pointer', 'pointer']
        )
    );

    // 装备开孔
    Interceptor.replace(
        ptr(0x0821a412),
        new NativeCallback(
            function (Dispatcher_AddSocketToAvatar, CUser, PacketBuf) {
                const _CUser = new User(CUser);
                var pack = Memory.alloc(0x20000);
                Memory.copy(pack, PacketBuf, 1000);
                var ret = 0;
                try {
                    var equ_slot = gmt.api_PacketBuf_get_short(pack); //装备所在位置
                    var equitem_id = gmt.api_PacketBuf_get_int(pack); //装备代码
                    var sta_slot = gmt.api_PacketBuf_get_short(pack); //道具所在位置
                    var CurCharacInvenW = GameNative.CUser_getCurCharacInvenW(CUser);
                    var inven_item = GameNative.CInventory_GetInvenRef(CurCharacInvenW, 1, equ_slot); //获取背包对应槽位的装备物品对象
                    // var is_equ = inven_item.add(1).readU8()//是否为装备物品
                    if (equ_slot > 56) {
                        // 修改后：大于56则是时装装备   原：如果不是装备文件就调用原逻辑
                        equ_slot = equ_slot - 57;
                        var C_PacketBuf = gmt.api_PacketBuf_get_buf(PacketBuf); //获取原始封包数据
                        C_PacketBuf.add(0).writeShort(equ_slot); //修改掉装备位置信息 时装类镶嵌从57开始。
                        return GameNative.Dispatcher_AddSocketToAvatar_dispatch_sig(Dispatcher_AddSocketToAvatar, CUser, PacketBuf);
                    }
                    var equ_id = inven_item.add(25).readU32();
                    if (api_exitjeweldata(equ_id) == 1) {
                        // 判断是否存在数据槽位
                        GameNative.CUser_SendCmdErrorPacket(CUser, 209, 19);
                        return 0;
                    }

                    var item = GameNative.CDataManager_find_item(GameNative.G_CDataManager(), equitem_id); //取出pvf文件
                    var ItemType = GameNative.CEquipItem_GetItemType(item); // 这个地方是获取标识的 10是武器 11是称号
                    if (ItemType == 10) {
                        _CUser.SendPacketMessage('武器类型的装备暂不支持打孔！');
                        GameNative.CUser_SendCmdErrorPacket(CUser, 209, 0); //回包防假死
                        return 0;
                    } else if (ItemType == 11) {
                        _CUser.SendPacketMessage('称号类型的装备暂不支持打孔！');
                        GameNative.CUser_SendCmdErrorPacket(CUser, 209, 0); //回包防假死，注意称号不要关闭，不然扔到称号铺炸数据！
                        return 0;
                    }
                    // 判断装备是否处于锁定状态
                    if (GameNative.CUser_CheckItemLock(CUser, 1, equ_slot)) {
                        _CUser.SendPacketMessage('装备未解锁！');
                        GameNative.CUser_SendCmdErrorPacket(CUser, 209, 0); //回包防假死
                        return 0;
                    }

                    var id = add_equiment_socket(ItemType); //生成槽位
                    GameNative.CInventory_delete_item(CurCharacInvenW, 1, sta_slot, 1, 8, 1); //删除打孔道具
                    inven_item.add(25).writeU32(id); //写入槽位标识
                    GameNative.CUser_SendUpdateItemList(CUser, 1, 0, equ_slot);
                    var packet_guard = gmt.api_PacketGuard_PacketGuard();
                    GameNative.InterfacePacketBuf_put_header(packet_guard, 1, 209);
                    GameNative.InterfacePacketBuf_put_byte(packet_guard, 1);
                    GameNative.InterfacePacketBuf_put_short(packet_guard, equ_slot + 104); //装备槽位 从104开始返回给本地处理显示正确的装备
                    GameNative.InterfacePacketBuf_put_short(packet_guard, sta_slot); //道具槽位
                    GameNative.InterfacePacketBuf_finalize(packet_guard, 1);
                    GameNative.CUser_Send(CUser, packet_guard);
                    GameNative.Destroy_PacketGuard_PacketGuard(packet_guard);
                } catch (error) {
                    console.log(error);
                }
                return 0;
            },
            'int',
            ['pointer', 'pointer', 'pointer']
        )
    );

    // 装备镶嵌和时装镶嵌
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
                const inven = GameNative.CUser_getCurCharacInvenW(user);

                //下面是参照原时装镶嵌的思路写的。个别点标记出来。
                if (avartar_inven_slot > 104) {
                    //为了不与时装镶嵌冲突,用孔位来判断,小于104是时装装备
                    var equipment_inven_slot = avartar_inven_slot - 104; //取出真实装备所在背包位置值
                    var equipment = GameNative.CInventory_GetInvenRef(inven, 1, equipment_inven_slot);
                    if (
                        GameNative.Inven_Item_isEmpty(equipment) ||
                        GameNative.Inven_Item_getKey(equipment) != avartar_item_id ||
                        GameNative.CUser_CheckItemLock(user, 1, equipment_inven_slot)
                    ) {
                        CUser.SendPacketMessage('装备未解锁！');
                        // TODO刷新背包
                        GameNative.CUser_SendCmdErrorPacket(user, 209, 0); //回包防假死
                        return;
                    }

                    var id = equipment.add(25).readU32();
                    var JewelSocketData = Memory.alloc(30); // 空字节数据
                    const mysql_frida = gmt.getMySQLHandle('frida');
                    JewelSocketData = api_get_jewel_socket_data(mysql_frida, id); //取出原有的孔位以及徽章数据
                    if (JewelSocketData.isNull()) {
                        //为空则不进行镶嵌
                        GameNative.CUser_SendCmdErrorPacket(user, 209, 0); //回包防假死
                        return;
                    }

                    if (emblem_cnt <= 3) {
                        var emblems = {} as any;
                        for (var i = 0; i < emblem_cnt; i++) {
                            var emblem_inven_slot = gmt.api_PacketBuf_get_short(packet_buf);
                            var emblem_item_id = gmt.api_PacketBuf_get_int(packet_buf);
                            var equipment_socket_slot = gmt.api_PacketBuf_get_byte(packet_buf);
                            var emblem = GameNative.CInventory_GetInvenRef(inven, 1, emblem_inven_slot);
                            if (GameNative.Inven_Item_isEmpty(emblem) || GameNative.Inven_Item_getKey(emblem) != emblem_item_id || equipment_socket_slot >= 3) {
                                return;
                            }

                            var citem = GameNative.CDataManager_find_item(GameNative.G_CDataManager(), emblem_item_id);
                            if (citem.isNull()) {
                                return;
                            }

                            if (!GameNative.CItem_is_stackable(citem) || GameNative.CStackableItem_GetItemType(citem) != 20) {
                                return;
                            }

                            var emblem_socket_type = GameNative.CStackableItem_getJewelTargetSocket(citem);
                            var avartar_socket_type = JewelSocketData.add(equipment_socket_slot * 6).readU16();

                            if (!(emblem_socket_type & avartar_socket_type)) {
                                return;
                            }

                            emblems[equipment_socket_slot] = [emblem_inven_slot, emblem_item_id];
                        }
                    }

                    for (let equipment_socket_slot in emblems) {
                        var emblem_inven_slot = emblems[equipment_socket_slot][0];
                        GameNative.CInventory_delete_item(inven, 1, emblem_inven_slot, 1, 8, 1);
                        var emblem_item_id = emblems[equipment_socket_slot][1];
                        // @ts-ignore
                        JewelSocketData.add(2 + 6 * equipment_socket_slot).writeU32(emblem_item_id);
                    }
                    var DB_JewelSocketData = ''; //用于生成镶嵌后的数据
                    for (var i = 0; i <= 4; i++) {
                        DB_JewelSocketData = lengthCutting(
                            JewelSocketData.add(i * 6)
                                .readU16()
                                .toString(16),
                            DB_JewelSocketData,
                            2,
                            4
                        );
                        DB_JewelSocketData = lengthCutting(
                            JewelSocketData.add(2 + i * 6)
                                .readU32()
                                .toString(16),
                            DB_JewelSocketData,
                            2,
                            8
                        );
                    }
                    var a = save_equiment_socket(DB_JewelSocketData, id); //保存数据,向数据库中写入数据
                    if (a == 0) {
                        //0为失败
                        return;
                    }
                    CUser_SendUpdateItemList_DB(user, equipment_inven_slot, JewelSocketData); // 用于更新镶嵌后的装备显示,这里用的是带镶嵌数据的更新背包函数,并非CUser_SendUpdateItemList
                    var packet_guard = gmt.api_PacketGuard_PacketGuard();
                    GameNative.InterfacePacketBuf_put_header(packet_guard, 1, 209); //呼出弹窗
                    GameNative.InterfacePacketBuf_put_byte(packet_guard, 1);
                    GameNative.InterfacePacketBuf_put_short(packet_guard, equipment_inven_slot + 104); //装备槽位+104发送回本地让本地处理正确的数据
                    GameNative.InterfacePacketBuf_finalize(packet_guard, 1);
                    GameNative.CUser_Send(user, packet_guard);
                    return;
                }

                // 以下是fr自带的嵌入逻辑
                // 获取时装道具
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
                const avartar_add_info = avartar.add(7).readInt();
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

    // 额外数据包,发送装备镶嵌数据给本地处理
    Interceptor.replace(
        ptr(0x0815098e),
        new NativeCallback(
            function (PacketBuf, Inven_Item) {
                var ret = GameNative.InterfacePacketBuf_put_packet(PacketBuf, Inven_Item);
                // 是否为装备物品
                if (Inven_Item.add(1).readU8() == 1) {
                    var JewelSocketData = Memory.alloc(30);
                    const mysql_frida = gmt.getMySQLHandle('frida');
                    JewelSocketData = api_get_jewel_socket_data(mysql_frida, Inven_Item.add(25).readU32());
                    if (JewelSocketData.add(0).readU8() != 0) {
                        GameNative.InterfacePacketBuf_put_binary(PacketBuf, JewelSocketData, 30);
                        return ret;
                    }
                }
                return ret;
            },
            'int',
            ['pointer', 'pointer']
        )
    );

    Interceptor.replace(
        ptr(0x084d7758),
        new NativeCallback(
            function (Inter_AuctionResultMyRegistedItems, CUser, src, a4) {
                //上架显示
                // 每个物品占117字节 所以每个物品的偏移量是117
                var JewelSocketData = Memory.alloc(30);
                var count = src.add(5).readU8(); //获取上架物品数量
                const mysql_frida = gmt.getMySQLHandle('frida');

                for (var i = 0; i < count; i++) {
                    //遍历写入数据
                    var item_id = src.add(37 + 117 * i).readU32();
                    var item = GameNative.CDataManager_find_item(GameNative.G_CDataManager(), item_id);
                    var item_groupname = GameNative.CItem_GetItemGroupName(item);
                    if (item_groupname > 0 && item_groupname < 59) {
                        //1-58是装备
                        JewelSocketData = api_get_jewel_socket_data(mysql_frida, src.add(59 + i * 117).readU32());
                        Memory.copy(src.add(89 + i * 117), JewelSocketData, 30);
                    }
                }
                var ret = GameNative.Inter_AuctionResultMyRegistedItems_dispatch_sig(Inter_AuctionResultMyRegistedItems, CUser, src, a4);
                return ret;
            },
            'int',
            ['pointer', 'pointer', 'pointer', 'int']
        )
    );

    Interceptor.replace(
        ptr(0x084d75bc),
        new NativeCallback(
            function (Inter_AuctionResultMyRegistedItems, CUser, src, a4) {
                //搜索显示
                //每个物品占137字节 所以每个物品的偏移量是137
                var JewelSocketData = Memory.alloc(30);
                var count = src.add(5).readU8(); //获取上架物品数量
                const mysql_frida = gmt.getMySQLHandle('frida');

                for (var i = 0; i < count; i++) {
                    //遍历写入数据
                    var item_id = src.add(54 + 137 * i).readU32();
                    var item = GameNative.CDataManager_find_item(GameNative.G_CDataManager(), item_id);
                    var item_groupname = GameNative.CItem_GetItemGroupName(item);
                    if (item_groupname > 0 && item_groupname < 59) {
                        //1-58是装备
                        JewelSocketData = api_get_jewel_socket_data(mysql_frida, src.add(76 + i * 137).readU32());
                        Memory.copy(src.add(106 + i * 137), JewelSocketData, 30);
                    }
                }
                var ret = GameNative.Inter_AuctionResultItemList_dispatch_sig(Inter_AuctionResultMyRegistedItems, CUser, src, a4);
                return ret;
            },
            'int',
            ['pointer', 'pointer', 'pointer', 'int']
        )
    );

    Interceptor.replace(
        ptr(0x084d78f4),
        new NativeCallback(
            function (Inter_AuctionResultMyRegistedItems, CUser, src, a4) {
                //竞拍显示
                //每个物品占125字节 所以每个物品的偏移量是125
                var JewelSocketData = Memory.alloc(30);
                var count = src.add(5).readU8(); //获取上架物品数量
                const mysql_frida = gmt.getMySQLHandle('frida');
                for (var i = 0; i < count; i++) {
                    //遍历写入数据
                    var item_id = src.add(46 + 125 * i).readU32();
                    var item = GameNative.CDataManager_find_item(GameNative.G_CDataManager(), item_id);
                    var item_groupname = GameNative.CItem_GetItemGroupName(item);
                    if (item_groupname > 0 && item_groupname < 59) {
                        //1-58是装备
                        JewelSocketData = api_get_jewel_socket_data(mysql_frida, src.add(68 + i * 125).readU32());
                        Memory.copy(src.add(98 + i * 125), JewelSocketData, 30);
                    }
                }
                var ret = GameNative.Inter_AuctionResultMyBidding_dispatch_sig(Inter_AuctionResultMyRegistedItems, CUser, src, a4);
                return ret;
            },
            'int',
            ['pointer', 'pointer', 'pointer', 'int']
        )
    );

    Interceptor.replace(
        ptr(0x0814a62e),
        new NativeCallback(
            function (Inven_Item, CInven_Item) {
                //装备全字节复制
                Memory.copy(Inven_Item, CInven_Item, 61);
                return Inven_Item;
            },
            'pointer',
            ['pointer', 'pointer']
        )
    );

    Interceptor.replace(
        ptr(0x080cb7d8),
        new NativeCallback(
            function (Inven_Item) {
                //装备全字节删除
                var MReset = Memory.alloc(61);
                Memory.copy(Inven_Item, MReset, 61);
                return Inven_Item;
            },
            'pointer',
            ['pointer']
        )
    );

    Memory.patchCode(ptr(0x085a6563), 72, function (code) {
        //装备掉落全字节保存
        var cw = new X86Writer(code, {
            pc: ptr(0x085a6563)
        });
        cw.putLeaRegRegOffset('eax', 'ebp', -392); //lea eax, [ebp-188h]
        cw.putLeaRegRegOffset('ebx', 'ebp', -213); //lea ebx, [ebp-0D5h]
        cw.putMovRegOffsetPtrU32('esp', 8, 61);
        cw.putMovRegOffsetPtrReg('esp', 4, 'eax');
        cw.putMovRegOffsetPtrReg('esp', 0, 'ebx');
        cw.putCallAddress(ptr(0x0807d880));
        cw.putLeaRegRegOffset('eax', 'ebp', -392); //lea eax, [ebp-188h]
        cw.putLeaRegRegOffset('ebx', 'ebp', -300); //
        cw.putAddRegImm('ebx', 0x10); //add ebx,0x10
        cw.putMovRegOffsetPtrU32('esp', 8, 61); //mov [esp+8],61
        cw.putMovRegOffsetPtrReg('esp', 4, 'eax');
        cw.putMovRegOffsetPtrReg('esp', 0, 'ebx');
        cw.putCallAddress(ptr(0x0807d880));
        cw.putNop();
        cw.putNop();
        cw.putNop();
        cw.putNop();
        cw.putNop();
        cw.flush();
    });
    // 装备调整箱强制最上级
    //	Memory.patchCode(ptr(0x0820154E), 12, function (code) {
    //       var cw = new X86Writer(code, { pc: ptr(0x0820154E)});
    //        cw.putMovRegU32('eax',0x5);
    //		cw.putNop()
    //		cw.putNop()
    //		cw.putMovRegU32('eax',0x5);
    //        cw.flush();
    //    });
}

export default fix_use_emblem;
