var log4js = require('log4js');
var log4json = require('../config/log4js.json');
/**
 * 开发环境配置   log4json.debug
 * 生产环境配置   log4json.build
 */
log4js.configure(log4json.debug);
var authopenLog = log4js.getLogger('authopenLogs');
/**
 * 日志级别 trace < info < debug < warn < error < fatal
 */
exports.logger = authopenLog;