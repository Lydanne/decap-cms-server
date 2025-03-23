const path = require('path');
const webpack = require('webpack');
const nodeExternals = require('webpack-node-externals');
const TsconfigPathsPlugin = require('tsconfig-paths-webpack-plugin');
const { NODE_ENV = 'production' } = process.env;

const allowlist = [/^decap-cms-lib-util/];

module.exports = {
  entry: { index: path.join('src', 'index.ts'), middlewares: path.join('src', 'middlewares.ts') },
  mode: NODE_ENV,
  target: 'node',
  devtool: 'source-map',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    libraryTarget: 'commonjs2',
  },
  resolve: {
    plugins: [new TsconfigPathsPlugin()],
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: [
          {
            loader: 'ts-loader',
            options: {
              // 添加此选项允许编译 node_modules 中的 TypeScript 文件
              allowTsInNodeModules: true,
              // 为了提高性能，可以针对 node_modules 禁用类型检查
              transpileOnly: true
            }
          }
        ],
      },
    ],
  },
  externals: [
    nodeExternals({ allowlist }),
    nodeExternals({
      allowlist,
      modulesDir: path.resolve(__dirname, path.join('..', '..', 'node_modules')),
    }),
  ],
  plugins: [new webpack.BannerPlugin({ banner: '#!/usr/bin/env node', raw: true })],
};
