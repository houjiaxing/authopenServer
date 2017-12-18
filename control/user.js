"use strict";

var users = module.exports;

const dbUtil = require("../util/db.js");
const consts = require("../consts/consts.js");
const util = require("../util/util.js");
const tools = require("../util/tools.js");
const log = require('../util/log.js').logger;
const common = require('../control/common.js');
const output = require('../util/output.js');
let apiList = [];



/**
 * 用户系统api控制
 */
users.control = function(aInfo, uid, callback) {

    /** 判断api是否存在*/
    if (typeof apiList[aInfo.action] === 'function') {
        apiList[aInfo.action](aInfo, uid, function(res) {
            callback(res);
        })
    } else {
        callback(consts.MSG.APINAME_NOT_EXIST);
    }
}


/**
 * @api {post} /users 新增用户接口
 * @apiVersion 1.0.0
 * @apiDescription 用于管理员新增用户
 * @apiName adduser
 * @apiGroup User
 *
 * @apiParam {String} action 操作（新增用户操作使用adduser）.
 * @apiParam {String} uemail 数据（用户名信息）.
 * @apiParam {Number} authority 数据（权限信息）.
 * @apiParamExample {Object} 请求Header(具体请从login接口获取)：
 * {
 *      "x-access-token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiNTk5M2IxYjBmZTQyNGI2NWI0MjBiZTI3IiwiaWF0IjoxNTEzNDc5OTEyLCJleHAiOjE1MTM0ODM1MTJ9.5OU11vmi1VktyXBDp_DcgKrqVfGDSGMMpDYWwGq4Cwo",
 * }
 * 
 * @apiParamExample {Object} 请求Body：
 * {
 *      "email" : "luke@21kunpeng.com",
 *      "authority" : 1,
 *      "action" : "adduser"
 * }
 *
 * @apiSuccess {Number} errorcode 统一返回错误码（0为成功）.
 * @apiSuccess {String} errormsg  统一返回错误描述（于errorcode对应）.
 * @apiSuccess {String} data 返回的数据 （新增用户接口为用户密码，errorcode不为0时无该字段）
 * 
 * @apiSuccessExample {Object} 返回实例：
 * {
 *      "errorcode" : 0,
 *      "errormsg" : "ok",
 *      "data" : "123456"
 * }
 * 
 */


users.addUser = function(req, uid, callback) {
    let uemail = req.email; //邮箱
    let authority = req.authoriry; //账号权限
    let isEmail = tools.isEmail(uemail); //邮箱地址是否合法
    //校验请求是否合法
    if (!isEmail) {
        callback(consts.MSG.EMAIL_ERROR);
        return;
    }
    if (consts.AUTHORITY.indexOf(authority) === -1) {
        callback(consts.MSG.HTTP_WRONG_PARAM);
        return;
    }

    let sql = "select count(*) as count from user where uemail = ?"
    let options = [uemail];
    let uuid = util.uuid();
    let rand = util.random(6);
    let pwd = util.md5Encrypt(rand);
    let createtime = Date.now();
    log.info("adduser:options = " + options);
    //查询用户账号是否存在
    dbUtil.operation(sql, options, function(err, results) {
        if (err) {
            // log.putError(err);
            log.error(err);
            callback(consts.MSG.DATABASE_ERROR);
            return;
        }
        if (results[0].count > 0) {
            callback(consts.MSG.USER_EXISTED);
            return;
        } else {
            let insertSQL = `insert into user (uid,uemail,upwd,createtime,authority) 
                                values (?,?,?,?,?)`;
            let insertOptions = [uuid, uemail, pwd, createtime, authority];
            log.info("adduser:insertOptions = " + insertOptions);
            //新建用户账号
            dbUtil.operation(insertSQL, insertOptions, function(err, results) {
                if (err) {
                    // log.putError(err);
                    log.error(err);
                    callback(consts.MSG.DATABASE_ERROR);
                    return;
                } else {
                    let affectedRows = results.affectedRows;
                    if (affectedRows > 0) {
                        callback(output.doOutput(rand));
                        return;
                    } else {
                        callback(consts.MSG.DATABASE_ERROR);
                        return;
                    }
                }
            });
        }

    });
}



/**
* @api {post} /users 获取用户列表接口
* @apiVersion 1.0.0
* @apiDescription 用于获取用户列表
* @apiName selectUser
* @apiGroup User
*
* @apiParam {String} action 操作 (获取用户列表使用selectUser）.
* @apiParamExample {Object} 请求Header(具体请从login接口获取)：
* {
*      "x-access-token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiNTk5M2IxYjBmZTQyNGI2NWI0MjBiZTI3IiwiaWF0IjoxNTEzNDc5OTEyLCJleHAiOjE1MTM0ODM1MTJ9.5OU11vmi1VktyXBDp_DcgKrqVfGDSGMMpDYWwGq4Cwo",
* }
* @apiParamExample {Object} 请求Body：
* {
*      "action" : "selectUser",
* }
*
* @apiSuccess {Number} errorcode 统一返回错误码（0为成功）.
* @apiSuccess {String} errormsg  统一返回错误描述（于errorcode对应）.
* @apiSuccess {Object} data 返回的数据 （获取用户列表接口为 Object类型 用户列表数据，errorcode不为0时无该字段）
* 
* @apiSuccessExample {Object} 返回实例：
* {
*      "errorcode" : 0,
*      "errormsg" : "ok",
*      "data" : [
*          {
               "uid": "5a309c7d2e5a0a4df3a3862e",
               "uemail": "zyl@baitutech.com",
               "upwd": "fdf483693eacc0a559dc365e7200954b",
               "createtime": 1513430530209,
               "expiretime": 0,
               "status": 0,
               "authority": 2,
               "logintimes": 0,
               "lasttime": null,
               "lastip": null,
               "updatetime": null,
               "updateuid": null
           },
           {
               "uid": "5a30c84c2e5a0a4df3a3862f",
               "uemail": "731747860@qq.com",
               "upwd": "79795494c1c0c1f521526dc44d573d48",
               "createtime": 1513430530209,
               "expiretime": 0,
               "status": 0,
               "authority": 2,
               "logintimes": 0,
               "lasttime": null,
               "lastip": null,
               "updatetime": null,
               "updateuid": null
           }
*      ]
* }
* 
*/

users.selectUser = function(req, uid, callback) {
    let sql = `select * from user where authority > (select authority from user where uid = ?)`;
    let options = [uid];
    dbUtil.operation(sql, options, function(err, results) {
        if (err) {
            log.error(err);
            callback(consts.MSG.DATABASE_ERROR);
            return;
        }
        log.info("selectUser=" + results);
        callback(output.doOutput(results));
        return;

    });
}

apiList['selectUser'] = users.selectUser;
apiList['addUser'] = users.addUser;