'use strict';
const uuidv1 = require('uuid/v1'); //根据时间戳生成uuid
const crypto = require('crypto');  

/**
 * uuid去掉 字符串中的-
 */
exports.uuid = function () {
    return uuidv1().replace(/\-/g, "");
}

/**
 * 生成随机字符串
 * @param {*} len 
 */
exports.random = function (len) {　　
    var $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';　　
    var maxPos = $chars.length;　　
    var pwd = '';　　
    for (let i = 0; i < len; i++) {
        //0~32的整数  
        pwd += $chars.charAt(Math.floor(Math.random() * (maxPos + 1)));　　
    }　　
    return pwd;
}

/**
 * md5加密
 * @param {*} encryptString 
 */
exports.md5Encrypt = function (encryptString) {
    let hasher = crypto.createHash("md5");
    hasher.update(encryptString);
    return hasher.digest("hex");
}