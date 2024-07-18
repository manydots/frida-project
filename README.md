## 工具说明

[frida-project](https://github.com/manydots/frida-project)

-   基于 Webpack4 + TypeScript + Babel 可根据自己的个人爱好拆分Frida代码结构
-   源码使用ES6语法 const、let、Class、`${字符串模版}`
-   通过 Babel 转义为 ES5 语法兼容目前的 frida.so 使用，不需要替换so文件
-   混淆压缩Frida代码

-   现有版本frida.so问题: console.log打印中文乱码、拓展方法有些语法不支持
-   Webpack5、Vite、frida-compile构建方式，有时间再研究下
-   本质就是代码兼容转换，不管用什么语法只要转换成低版本兼容语法即可！！！

-   **如果没有以上需要，建议忽略！！！**
-   给有强迫症的吧友一点点启发
-   需要一点点门槛
-   **总结：好像也没有啥用！！！**

### 1.资源安装

```sh
node -v
git clone https://github.com/manydots/frida-project.git

cd frida-project
git pull
npm install
```

### 1.1 构建dp2.8+版本

```sh
npm run dp
```

### 1.2 构建frida版本

```sh
npm run frida
```

### 1.3 【不推荐，已放弃】Vite编译frida/dp(vite.config.mjs build.minify = false 禁用最小化混淆)

```sh
npm run vite:frida
npm run vite:dp
```

### 1.4 【不推荐，已放弃】frida-compile编译(-c压缩)

```sh
npm run build:min
npm run build
```

### 1.5 package.json重要参数说明

```JavaScript
/**
 *  cross-env minimize=false filename=df_game_r.js is_dp=true webpack
 *
 *  - cross-env: 设置全局变量的命令
 *  - minimize: 混淆压缩参数 true开启 false关闭
 *  - filename: 构建输出文件名称
 *  - is_dp/is_frida: 当前构建环境标记(不推荐修改)
 *  - webpack: 使用webpack构建项目,配置文件webpack.config.js
 *
 *  vite与frida-compile构建方式未完善、存在问题
 *  - .env.dp .env.frida vite构建使用的全局变量
 *  - vite.config.mjs
*/
```

### 2.常见问题FAQ

#### 2.1 打包构建后【不需要、不需要、不需要】替换原有frida.so文件！

-   基于原有模式，对hook进行简单拆分，打包后理论与原有文件【frida.js、df_game_r.js】逻辑保持一致。

#### 2.2 TypeScript配置相关(异常按照提示修改)

```json
// tsconfig.json文件
{
    "compilerOptions": {
        "module": "esnext"
        //...其他配置
    },
    "include": ["src/**/*"],
    "exclude": ["node_modules", "dist"]
}
```

#### 2.3 import.meta.env 类型ImportMeta上不存在属性env

```TypeScript
// env.d.ts文件
/// <reference types="vite/client" />
interface ImportMetaEnv {
    readonly VITE_XXX: string;
}
```

[详情参见Vite TypeScript 的智能提示](https://cn.vitejs.dev/guide/env-and-mode.html#intellisense)

#### 2.4 frida-compile建议使用^10.2.1版本【不推荐】

```JavaScript
// 高版本frida-compile构建存在插入无用的日志输出，需要手动删除

// 对于使用 Node.js 绑定物的应用, 这个api可以被这样使用
const frida = require('frida');
const fs = require('fs');
const path = require('path');
const util = require('util');
const readFile = util.promisify(fs.readFile);

let session, script;
async function run() {
  const source = await readFile(path.join(__dirname, '_agent.js'), 'utf8');
  session = await frida.attach('iTunes');
  script = await session.createScript(source);
  script.message.connect(onMessage);
  await script.load();
  console.log(await script.exports.add(2, 3));
  console.log(await script.exports.sub(5, 3));
}

run().catch(onError);

function onError(error) {
  console.error(error.stack);
}

function onMessage(message, data) {
  if (message.type === 'send') {
    console.log(message.payload);
  } else if (message.type === 'error') {
    console.error(message.stack);
  }
}

// rpc.exports
rpc.exports = {
  add: function (a, b) {
    return a + b;
  },
  sub: function (a, b) {
    return new Promise(function (resolve) {
      setTimeout(function () {
        resolve(a - b);
      }, 100);
    });
  }
};
```

#### 2.5 Windows Error: error:0308010C:digital envelope routines::unsupported

```JavaScript
// Windows 命令行增加配置
NODE_OPTIONS=--openssl-legacy-provider

// Mac不支持NODE_OPTIONS参数, 以构建dp为例
// 方式一: 单独定义一个编译命令
// "dp:mac": "cross-env minimize=true filename=df_game_r.js is_dp=true webpack"

// 方式二: 定义scripts/build.dp.js脚本(不推荐)
// 脚本内部判断平台类型，拼接命令后通过exec执行
// "dp:script": "node scripts/build.dp.js"
```

#### 2.6 /filter/records.js为dp2.9的records.lua文件(地址枚举)

```sh
# test.js为模糊搜索基础符号
# filter.address.js hook地址拷贝
# filter.attach.js 为模糊搜索地址Interceptor.attach便于批量测试匹配
npm run filter
# 或
cd ./filter
node test.js
```

#### 2.7 Frida-Gadget ES6问题(64位系统也需要使用frida-gadget-x-linux-x86.so版本)

```JavaScript
// Frida12 不支持
// Frida16 支持(frida-gadget-16.4.2-linux-x86.so已测试，可配合升级Webpack5、Vite构建)
// Webpack5 构建后会包裹箭头函数
```

#### 2.8 数据库连接异常请检查frida_config.json文件

#### 3.项目结构

frida-project
├── src -- 主功能
│ ├── hook
│ │ ├── HookEvent.ts -- 封装常用api_xxx方法
│ │ ├── HookGameEvent.ts -- 核心逻辑实现
│ │ ├── HookNative.ts -- new NativeFunction定义
│ │ └── HookType.ts -- hook地址枚举, 也可以在HookGameEvent中直接使用ptr(0x地址)不需要单独定义
│ ├── enum -- 枚举文件暂时未使用
│ └── main.ts -- 核心功能入口文件
├── package.json
├── tsconfig.json -- ts配置
├── webpack.config.js -- webpack配置
│

#### 4.其他资源

-   [Frida](https://frida.re/docs/javascript-api/#console)
-   [Vite](https://cn.vitejs.dev/guide/env-and-mode.html)
-   [frida-compile](https://github.com/frida/frida-compile)
-   [frida-compile example](https://github.com/oleavr/frida-agent-example)
-   [gadget-linux-x86(\_64).so](https://github.com/frida/frida/releases)
-   [Node.js](https://nodejs.org/zh-cn/download/prebuilt-installer)
-   [VSCode](https://code.visualstudio.com/)

#### 5.更新日志

##### 2024-07-09

-   增加自动修理装备
-   增加玩家指令监听

##### 2024-07-05

-   HookEvent Class变更为单例模式
-   区分构建平台Windows/Mac命令
