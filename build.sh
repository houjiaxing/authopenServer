#!/bin/bash
echo "build start"

# 如果有使用node-sass，则使用这一句。不能把node-sass添加在package.json配置上，因为node-sass安装时会通过外网域名下载额外的依赖，CI编译机不具有外网访问权限。
export PATH=$PATH:./node_modules/.bin

#安装依赖
tnpm install

# 运行测试用例。测试用例结果会首先输出在./res/testResult/test.xml
#npm run test

# 执行代码覆盖率检查, 生产报告 coverage/cobertura.xml
#npm run cov

# 运行代码格式检查
#npm run eslint
#npm run eslint-html
# 新建bin目录, 存放checkstyle文件

# 生成API文档
npm run apidoc

echo "build complete"