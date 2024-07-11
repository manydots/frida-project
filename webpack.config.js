const path = require('path');
const webpack = require('webpack');
const { minimize, filename } = process.env;

module.exports = {
    mode: 'production',
    entry: './src/main.ts',
    output: {
        filename: filename,
        path: path.resolve(__dirname, 'dist')
    },
    optimization: {
        minimize: JSON.parse(minimize ?? 'false')
    },
    plugins: [
        new webpack.DefinePlugin({
            'process.env.filename': JSON.stringify(filename.split('.')[0]),
            'process.env.loggername': JSON.stringify('Frida'),
            'process.env.is_dp': JSON.stringify(process.env.is_dp),
            'process.env.is_frida': JSON.stringify(process.env.is_frida)
        })
    ],
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: 'ts-loader',
                exclude: /node_modules/
            },
            {
                test: /\.js$/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-env']
                    }
                },
                exclude: /node_modules/
            }
        ]
    },
    resolve: {
        alias: {
            '@': path.resolve(__dirname, 'src/') // 将@设置为项目src目录的绝对路径
        },
        extensions: ['.tsx', '.ts', '.js'] // 解析文件扩展名
    }
};
