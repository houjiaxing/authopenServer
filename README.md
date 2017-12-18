# 使用指南

## 文档修订记录


文档版本号 | 修订时间 | 修订内容 | 撰写人|
:---|:---|:---|:---|
V1.0 | 2017-12-17 | 初始版本 | Luke|


## 目录结构说明


```bash
.
├── README.md
├── package.json            # 描述文件
├── app.js                  # 入口文件
├── apidoc.json             # apidoc 配置文件
├── build.sh                # 一键配置脚本
├── util                    # 工具方法目录
│   └── db.js               # 数据库方法
│   └── log.js              # 日志打印方法
│   └── output.js           # 统一数据输出方法
│   └── tools.js            # 文件读写相关方法
│   └── db.js               # 用户系统方法
├── routes                  # 路由目录
│   ├── develop.js          # 开发者工具路由
│   ├── index.js            # 登录、下载路由
│   ├── users.js            # 用户系统路由
├── public                  # 文件目录
│   ├── demo                # demo资源目录
│   ├── img                 # 图片资源目录
│   ├── interfaceDoc        # pdf资源目录
│   ├── mds                 # markdown资源目录
├── control                 # 控制器目录
│   ├── common.js           # 公共控制器（token验证方法）
│   ├── devtools.js         # 开发者工具控制器
│   ├── download.js         # 文件下载控制器
│   ├── interdoc.js         # 接口文档控制器
│   ├── login.js            # 登录控制器
│   ├── user.js             # 用户控制器
├── consts                  # 静态目录
│   ├── consts.js           # 静态变量文件
├── config                  # 配置文件目录
│   ├── dbConfig.json       # 数据库配置文件
│   ├── log4js.json         # 日志配置文件
```


## 自动化部署

==未完成==




