"use strict";
var devtools = module.exports;


/*************************引用区域***********************************/
const crypto = require("crypto");
const tools = require('../util/tools.js');
const consts = require('../consts/consts');
const output = require('../util/output.js');
const log = require('../util/log.js').logger;
/***************************************定义变量*******************************************/
let apiList = [];
const md5 = crypto.createHash('md5');

/**
 * 登录系统api控制
 */
devtools.control = function(aInfo) {

    /** 判断api是否存在*/
    if (typeof apiList[aInfo.action] === 'function') {
        return apiList[aInfo.action](aInfo);
    } else {
        return (consts.MSG.APINAME_NOT_EXIST);
    }
}

/**
 * aes解密
 * @author lillian
 */
/**
 * @api {post} /develop/devtools 开发者工具aes解密
 * @apiDescription 开发者工具aes解密接口
 * @apiVersion 1.0.0
 * @apiName aes_check
 * @apiGroup devtools
 *
 * @apiParam {String} x-access-token 该参数放在Header中,用于登录态验证.
 * @apiParam {String} action 该参数放在body中，该接口传入aes_check,必填.
 * @apiParam {String} aeskey 该参数放在body中，aes秘钥，必填.
 * @apiParam {String} aes_ciphertext 该参数放在body中，aes密文，必填.
 * 
 * @apiParamExample {Object} 请求实例
 * {
 *      "action" : "interdoc_list",
 *      "aeskey" : "ausdaafssdfth",
 *      "aes_ciphertext" : "fawefhwejfhwekfhk"
 * }
 *
 * @apiError {Number} errorcode 统一返回错误码.
 * @apiError {String} errormsg  统一返回错误描述.
 * 
 *  
 * @apiSuccessExample {Object} 返回实例
 * {
 *      "errorcode" : 0,
 *      "errormsg" : "ok"
 * }
 */
devtools.aesCheck = function(aInfo) {
    let tIv = "";
    let tKeys = aInfo.aeskey;
    let tCiphertext = aInfo.aes_ciphertext;

    /** 判断长度*/
    if (tKeys.length != 32 || !tCiphertext.length) {
        return consts.MSG.AES_LENGTH_WRONG;
    }
    try {
        /** 组织数据*/
        let tCipherChunks = [tCiphertext];
        let tDecipher = crypto.createDecipheriv('AES-256-ECB', tKeys, tIv);
        let tPlainChunks = new Array;
        for (var i = 0; i < tCipherChunks.length; i++) {
            tPlainChunks.push(tDecipher.update(tCipherChunks[i], 'base64', 'utf8'));
        }
        tPlainChunks.push(tDecipher.final('utf8'));
        var tRet = tPlainChunks.join('');
        return output.doOutput(tRet);

    } catch (e) {
        log.error("devtools---aes :" + e);
        return consts.MSG.HTTP_WRONG_PARAM;
    }
}


/**
 * signature校验函数
 * @author lillian
 */
/**
 * @api {post} /develop/devtools signature校验函数
 * @apiDescription signature校验函数
 * @apiVersion 1.0.0
 * @apiName signature_check
 * @apiGroup devtools
 *
 * @apiParam {String} x-access-token 该参数放在Header中,用于登录态验证.
 * @apiParam {String} action 该参数放在body中，该接口传入signature_check,必填.
 * @apiParam {String} interface_name 该参数放在body中，signature生成参数中的apiname，必填.
 * @apiParam {String} appid 该参数放在body中，signature生成参数中的appid，必填.
 * @apiParam {String} secret_key 该参数放在body中，signature生成参数中的secret_key，必填.
 * @apiParam {String} signature 该参数放在body中，客户生成的signature，必填.
 * 
 * 
 * @apiParamExample {Object} 请求实例
 * {
 *      "action" : "interdoc_list",
 *      "interface_name" : "auth",
 *      "appid" : "4396",
 *      "secret_key":"dsadasdfasfsdfdsgfgfdgrherhe",
 *      "signature":"xdsadasdas"
 * }
 *
 * @apiError {Number} errorcode 统一返回错误码.
 * @apiError {String} errormsg  统一返回错误描述.
 * 
 * 
 * @apiSuccessExample {Object} 返回实例
 * {
 *      "errorcode" : 0,
 *      "errormsg" : "ok"
 * }
 */
devtools.verifyAppSign = function(aInfo) {
    // apiName,appId,appSecretKey,signExpired,orgiSignature
    let apiName = aInfo.interface_name || '', // auth || detectinfo
        appId = aInfo.appid || '',
        appSecretKey = aInfo.secret_key || '',
        signExpired = 600,
        orgiSignature = aInfo.signature || '';


    // apiName 是否为空
    if (!apiName || !appId || !appSecretKey || !orgiSignature) {
        return consts.MSG.SIGNATURE_PARAM_NOT_EXIST;
    }

    // =======================  验证 signature ========================
    var buffer = new Buffer(orgiSignature, 'base64');
    var decodeSign = buffer.toString();

    var now = parseInt(Date.now() / 1000);
    var signArr = decodeSign.split("&");
    if (signArr.length < 3) {
        return consts.MSG.SIGNATURE_LENGTH_WRONG;
    }
    var timeArr = signArr[signArr.length - 2].split("=");
    if (timeArr[0] != 't') {
        return consts.MSG.SIGNATURE_TIMESTAMP_WRONG;
    }
    var orgiTime = parseInt(timeArr[1]);
    if ((now - orgiTime) > signExpired) {
        return consts.MSG.SIGNATURE_TIMEOUT;
    }
    var apiArr = signArr[signArr.length - 3].split("=");
    log.info("signature --- signArr:" + signArr[signArr.length - 3]);
    if (apiArr[0] != 'm' || apiArr[1] != apiName) {
        return consts.MSG.SIGNATURE_APINAME_ERROR;
    }


    var plainText = 'a=' + appId + '&m=' + apiName + '&t=' + orgiTime + '&e=' + signExpired;
    var data = new Buffer(plainText, 'utf8');
    var res = crypto.createHmac('sha1', appSecretKey).update(data).digest();
    var bin = Buffer.concat([res, data]);
    var sign = bin.toString('base64');

    if (sign != orgiSignature) {
        return consts.MSG.SIGNATURE_ERROR;

    }

    return output.doOutput("");

};



apiList['signature_check'] = devtools.verifyAppSign;
apiList['aes_check'] = devtools.aesCheck;