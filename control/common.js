"use strict";

var common = module.exports;

const consts = require('../consts/consts.js');
const log = require('../util/log.js').logger;
const output = require('../util/output.js');
var crypto = require('crypto');

var jwt = require('jsonwebtoken');

var aeskeys = consts.Aeskeys;
var secretOrPrivateKey = consts.Jwtkeys;
/**
 * aes 256 ecb加密方法
 * @author Luke
 * @param data 待加密内容
 * @param timesatmp 必须为10位时间戳
 * @returns {string}
 */
common.encryption = function(data, timestamp) {
    if (!data) {
        return "";
    }

    let key = aeskeys + timestamp;
    let iv = "";
    let clearEncoding = 'utf8';
    let cipherEncoding = 'base64';
    let cipherChunks = [];
    let cipher = crypto.createCipher('aes-256-ecb', key);
    cipher.setAutoPadding(true);
    cipherChunks.push(cipher.update(data, clearEncoding, cipherEncoding));
    cipherChunks.push(cipher.final(cipherEncoding));
    return cipherChunks.join('');
}

/**
 * aes 256 ecb解密方法
 * @author Luke
 * @param data  待解密内容
 * @param timestamp 必须为10位时间戳
 * @returns {string}
 */
common.decryption = function(data, timestamp) {
    if (!data) {
        return "";
    }
    let key = aeskeys + timestamp;
    let iv = "";
    let clearEncoding = 'utf8';
    let cipherEncoding = 'base64';
    let cipherChunks = [];
    let decipher = crypto.createDecipher('aes-256-ecb', key);
    decipher.setAutoPadding(true);
    cipherChunks.push(decipher.update(data, cipherEncoding, clearEncoding));
    cipherChunks.push(decipher.final(clearEncoding));
    return cipherChunks.join('');
}


/**
 * jwt 生成token
 * @author Luke
 * @param data 将要生成token的主题信息
 * @returns {string} 生成的token
 */

common.settoken = function(data) {
    let token = jwt.sign({
            data: data
        },
        secretOrPrivateKey, {
            expiresIn: 60 * 60
        });
    return token;
}

/**
 * jwt 验证token
 * @author Luke
 * @param token 待验证token  取值方式：rq.body.token || rq.query.token || rq.headers["x-access-token"]
 * @returns {string} 验证结果
 */


common.verifytoken = function(data) {
    if (data) {
        log.info('verify token data:' + data);
        try {
            var decoded = jwt.verify(data, secretOrPrivateKey);
        } catch (err) {
            // err
            return consts.MSG.UNLOGIN;
        }
        return output.doOutput(decoded.data);
    } else {
        log.error('no token');
        return consts.MSG.UNLOGIN;
    }
}

//获取url请求客户端ip
common.get_client_ip = function(req) {
    var ip = req.headers['x-forwarded-for'] ||
        req.ip ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress || '';
    if (ip.split(',').length > 0) {
        ip = ip.split(',')[0]
    }
    return ip;
};