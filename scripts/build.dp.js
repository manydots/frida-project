const { exec } = require('child_process');
const os = require('os');
const chalk = require('chalk');

const isWindows = os.platform() === 'win32';
const NODE_OPTIONS = isWindows ? 'NODE_OPTIONS=--openssl-legacy-provider' : ''; // windows平台需要设置NODE_OPTIONS=--openssl-legacy-provider
const command = `cross-env minimize=true filename=df_game_r.js is_dp=true ${NODE_OPTIONS} webpack`;

exec(command, (error, stdout, stderr) => {
    if (error) {
        chalkLog(`exec error: ${error}`);
        return;
    }
    chalkLog(`stdout: ${stdout}`, '#20c139');
    if (stderr) {
        chalkLog(`stderr: ${stderr}`);
    }
});

function chalkLog(str, color = '#FF4500') {
    console.log(chalk.hex(color)(str)); // hex 十六进制值
}
