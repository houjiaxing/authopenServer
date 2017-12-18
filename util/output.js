"use strict";
var output = module.exports;

const consts = require('../consts/consts.js');
const common = require('../control/common.js');



/**
 * 统一数据出口（非错误类型）
 * @author Luke
 * @param {string} data 如data非字符串请转换，否则加密报错 .请与前台约定解密后数据类型
 * @returns {object} 
 */

output.doOutput = function(data){
    let outData = {
        "errorcode" : 0,
        "errormsg" : "ok",
        "data" : data
    }
    return outData;
}