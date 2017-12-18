"use strict";

var login = module.exports;

const consts = require('../consts/consts.js');
const common = require('./common.js');
const log = require('../util/log.js').logger;
const output = require('../util/output.js');
const db = require('../util/db.js');
const util = require('../util/util.js');

login.control = function(aInfo, aReq, callback) {
    /** 接受参数并解析 */
    if (aInfo && aInfo.action && aInfo.username && aInfo.password) {
        let action = aInfo.action;
        let username = aInfo.username;
        let pwd = aInfo.password;
        if (action == "dologin") {
            let res = login.dologin(username, pwd, aReq, function(res) {
                callback(res);
                return;
            });

        } else {
            callback(consts.MSG.HTTP_WRONG_PARAM);
            return;
        }

    } else {
        callback(consts.MSG.HTTP_UNSET_PARAM);
        return;
    }
}

/**
 * 登录方法
 * @author Luke
 * @param username 用户名
 * @param password 密码
 * @returns {string}
 */

/**
 * @api {post} /login 登录接口
 * @apiVersion 1.0.0
 * @apiDescription 用于请求登录，返回指定用户的token信息
 * @apiName dologin
 * @apiGroup Login
 *
 * @apiParam {String} action 操作（登录操作使用dologin）.
 * @apiParam {String} username 数据（用户名信息）.
 * @apiParam {String} password 数据（密码信息）.
 * @apiParamExample {Object} 请求实例：
 * {
 *      "username" : "luke@21kunpeng.com",
 *      "password" : "TEce@123",
 *      "action" : "dologin"
 * }
 *
 * @apiSuccess {Number} errorcode 统一返回错误码（0为成功）.
 * @apiSuccess {String} errormsg  统一返回错误描述（于errorcode对应）.
 * @apiSuccess {Object} data 返回的数据 （登录接口为{}，errorcode不为0时无该字段）
 * 
 * @apiSuccessExample {Object} 返回实例：
 * {
 *      "errorcode" : 0,
 *      "errormsg" : "ok",
 *      "data" : {
 *          "token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiNTk5M2IxYjBmZTQyNGI2NWI0MjBiZTI3IiwiaWF0IjoxNTEzNDMxODI0LCJleHAiOjE1MTM0MzU0MjR9.yW2Urprwv4N4SJPloNYZww6gH4FbRuu_tolPj7FTy1k",
 *          "authority" : 1
 *      }
 * }
 * 
 */
login.dologin = function(username, password, req, callback) {
    //查询数据库判断登录
    if (username && password) {
        let ucount;
        let sql = "select count(*) as count, uid, authority  from user as count where uemail = ? and upwd = ?";
        let options = [username, util.md5Encrypt(password)];
        db.operation(sql, options, function(err, results) {
            if (err) {
                callback(consts.MSG.DATABASE_ERROR);
                return;
            }
            ucount = results[0].count;
            if (ucount <= 0) {
                callback(consts.MSG.USER_NO_EXIST_OR_PWD_WRONG);
                return;
            } else {
                let clientip = common.get_client_ip(req);
                let timestamp = Date.now();

                let usql = "update user set logintimes = logintimes+1, lasttime = ? , lastip = ? where uemail = ?";
                let uoptions = [timestamp, clientip, username];

                db.operation(usql, uoptions, function() {});


                let token = common.settoken(results[0].uid);
                callback(output.doOutput({ "token": token, "authority": results[0]["authority"] }));
                return;
            }

        })
    } else {
        callback(consts.MSG.HTTP_WRONG_PARAM);
        return;
    }

}