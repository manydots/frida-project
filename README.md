## 工具说明

-   基于 Webpack4 + TypeScript + Babel 可根据自己的个人爱好拆分Frida代码结构
-   通过 Babel 转义为 es5 语法兼容目前的 frida.so 使用，不需要替换so文件
-   给强迫症吧友一点点启发
-   需要一点点门槛
-   总结：好像也没有啥用！！！

### 1.资源安装（依赖资源参见：3.其他资源）

```sh
cd frida-project
npm install
```

### 1.1 构建dp2.8+版本

```sh
cd frida-project
npm run dp
```

### 1.2 构建frida版本(未测试)

```sh
cd frida-project
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

### 2.常见问题解答FAQ

#### 2.1 打包构建后【不需要、不需要、不需要】替换原有frida.so文件！

-   基于原有模式，对hook进行简单拆分，打包后理论与原有文件【frida.js、df_game_r.js】逻辑保持一致。

#### 2.2 TypeScript配置相关(异常按照提示修改)

```json
    // tsconfig.json文件
    {
        "compilerOptions": {
            "module": "esnext",
            ...其他配置
        },
        "include": ["src/**/*"],
        "exclude": ["node_modules", "dist"]
    }
```

#### 2.3 import.meta.env 类型ImportMeta上不存在属性env

```text
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

#### 3.其他资源

-   [Frida](https://frida.re/docs/javascript-api/#console)
-   [Vite](https://cn.vitejs.dev/guide/env-and-mode.html)
-   [frida-compile](https://github.com/frida/frida-compile)
-   [frida-compile example](https://github.com/oleavr/frida-agent-example)
-   [gadget-linux-x86(\_64).so](https://github.com/frida/frida/releases)
-   [Node.js](https://nodejs.org/zh-cn/download/prebuilt-installer)
