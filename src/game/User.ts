import GameNative from './GameNative';

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
}

export default User;
