/**
 * 打印日志
 * @param args 打印参数
 */
function logger(...args: any[]): void {
    try {
        console.log(`[${get_timestamp()}][${process.env.loggername}]${args.join('')}`);
    } catch (e: any) {
        console.error(e);
    }
}

// 本地时间戳
function get_timestamp(): string {
    let date = new Date();
    date = new Date(date.setHours(date.getHours())); // 转换到本地时间
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hour = date.getHours();
    const minute = date.getMinutes();
    const second = date.getSeconds();
    const ms = date.getMilliseconds();
    const dateArr = [year, month, day];
    let _dateArr: (number | string)[] = [];
    dateArr.forEach((time) => {
        let _time = time <= 9 ? `0${time}` : time;
        _dateArr.push(_time);
    });

    const timeArr = [hour, minute, second];
    let _timeArr: (number | string)[] = [];
    timeArr.forEach((time) => {
        let _time = time <= 9 ? `0${time}` : time;
        _timeArr.push(_time);
    });
    return `${_dateArr.join('-')} ${_timeArr.join(':')}.${ms}`;
}

/**
 * 格式化通关时间
 * @param value 通关时间(单位:秒)
 */
function formatTime(value: number): string {
    let secondTime = value ?? 0;
    let minuteTime = 0; // 计算分钟数
    let hourTime = 0; // 计算小时数
    if (secondTime >= 60) {
        minuteTime = Math.floor(secondTime / 60);
        // 获取秒数，秒数取佘，得到整数秒数
        secondTime = Math.floor(secondTime % 60);
        // 如果分钟大于60，将分钟转换成小时
        if (minuteTime >= 60) {
            //获取小时，获取分钟除以60，得到整数小时
            hourTime = Math.floor(minuteTime / 60);
            //获取小时后取佘的分，获取分钟除以60取佘的分
            minuteTime = Math.floor(minuteTime % 60);
        }
    }

    const timeArr = [hourTime, minuteTime, secondTime];
    const _indexArr = ['时', '分', '秒'];
    let _timeArr: (string | number)[] = [];
    timeArr.forEach((time, index) => {
        let _time = time <= 9 ? `0${time}` : time;
        _time = `${_time}${_indexArr[index]}`;
        // 小时 <0 不拼接
        if (index == 0 && time > 0) {
            _timeArr.push(_time);
        } else if (index > 0) {
            _timeArr.push(_time);
        }
    });
    return _timeArr.join('');

    // const fmtSecondTime = secondTime <= 9 ? `0${secondTime}` : secondTime;
    // const fmtMinuteTime = minuteTime <= 9 ? `0${minuteTime}` : minuteTime;
    // const fmtHourTime = hourTime <= 9 ? `0${hourTime}` : hourTime;
    // let result = `${fmtHourTime}:${fmtMinuteTime}:${fmtSecondTime}`;
    // return result;
}

/**
 * 获取随机数
 * @param min 最小值
 * @param max 最大值
 * @returns 返回min与max之间的随机数
 */
function get_random_int(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min)) + min;
}

/**
 * Frida.version版本
 */
function echoVersion(): void {
    // const base_address = ptr(0x1ac790c);
    // const offset = 0x258;
    // const target_address = base_address.add(offset);
    logger('[version]', Frida.version);
}

/**
 * 内存十六进制打印
 */
function bin2hex(p: any, len: any): any {
    let hex = '';
    for (let i = 0; i < len; i++) {
        let s = p.add(i).readU8().toString(16);
        if (s.length == 1) s = '0' + s;
        hex += s;
        if (i != len - 1) hex += ' ';
    }
    return hex;
}

export { logger, formatTime, get_timestamp, get_random_int, echoVersion, bin2hex };
