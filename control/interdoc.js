//接口文档控制器函数
"use strict";
var interdoc = module.exports;

const tools = require('../util/tools.js');
const consts = require('../consts/consts.js');
const common = require('../control/common.js');
const log = require('../util/log.js').logger;
const path = require('path');
const output = require('../util/output.js');

let apiList = []; //对外开放接口列表


//入口
interdoc.control = function(aInfo) {
    /** 判断 api 是否存在 */
    if (typeof apiList[aInfo.action] === 'function') {

        return apiList[aInfo.action](aInfo);

    } else {
        log.info("interdoc---APINAME_NOT_EXIST");
        return consts.MSG.APINAME_NOT_EXIST;
    }

}


/**
 * 常见错误码文档
 * @author lillian
 */
/**
 * @api {post} /develop/interdoc 常见错误码文档
 * @apiDescription 获取常见错误码文档
 * @apiVersion 1.0.0
 * @apiName error_list
 * @apiGroup interdoc
 *
 * @apiParam {String} x-access-token 该参数放在Header中,用于登录态验证.
 * @apiParam {String} action 该参数放在body中，该接口传入error_list,必填.
 *
 * 
 * @apiParamExample {Object} 请求实例
 * {
 *      "action" : "error_list"
 * }
 * @apiError {Number} errorcode 统一返回错误码.
 * @apiError {String} errormsg  统一返回错误描述.
 * @apiError {String} data  md文件内容.
 * 
 * @apiSuccessExample {Object} 返回实例
 * {
 *      "errorcode" : 0,
 *      "errormsg" : "ok",
 *      "data" : "xxxsacasdasda"//md字符串
 * }
 */

interdoc.errorList = function(aInfo) {

    let tpath = path.resolve(__dirname, '..');
    let _path = tpath + consts.errorMdPath;
    log.info("interdoc---errorList---_path:" + _path);
    let _result = tools.readmd(_path);

    if (_result) {
        return output.doOutput(_result);
    } else {
        return consts.MSG.FILE_UNEXISTED;
    }
}

/**
 * 接口文档查询接口
 * @author lillian
 */
/**
 * @api {post} /develop/interdoc 接口文档查询接口
 * @apiDescription 获取常见错误码文档
 * @apiVersion 1.0.0
 * @apiName interdoc_list
 * @apiGroup interdoc
 *
 * @apiParam {String} x-access-token 该参数放在Header中,用于登录态验证.
 * @apiParam {String} action 该参数放在body中，该接口传入interdoc_list,必填.
 * @apiParam {String} type 该参数放在body中，类型（0--'public',1--'mix',2--'api',3--'sdk',4--'other'），必填.
 * @apiParam {String} tab_type 该参数放在body中，子分类，示例传入方式 type=0（public数组），tab_type=0(public下的公有部署接口文档)，与旧版本接口参数含义相同，必填.
 * @apiParamExample {String} tab_type的可传参数如下
 * 'public':[
 * 		0:'公有部署接口文档',
 * 		1:'公有部署自有库外部证照接口规范'
 *  ],
 *  'mix':[
 * 		0:'混合部署接口文档',
 * 		1:'混合部署自有库证照接口规范'
 *  ],
 *  'api':[
 * 		0:'1v1',
 * 		1:'OCR',
 * 		2:'活体+1v1',
 * 		3:'仅活体'
 *  ],
 *  'sdk':[
 * 		0:'androidSDK接口文档',
 * 		1:'iosSDK接口文档'
 *  ],
 *  'other':[
 *  	0:'外部养老金领取资格接口规范',
 *  	1:'小程序'
 *  ]
 *
 * @apiParamExample {Object} 请求实例
 * {
 *      "action" : "interdoc_list",
 *      "type" : 2,
 *      "tab_type" : 2
 * }
 * 
 * @apiSuccess {Number} errorcode 统一返回错误码.
 * @apiSuccess {String} errormsg  统一返回错误描述.
 * @apiSuccess {String} data  md文件内容.
 * 
 * @apiSuccessExample {Object} 返回实例
 * {
 *      "errorcode" : 0,
 *      "errormsg" : "ok",
 *      "data" : "xxxsacasdasda"//md字符串
 * }
 */
interdoc.interdocList = function(aInfo) {

    let _type = parseInt(aInfo.type);
    let tab_type = aInfo.tab_type ? parseInt(aInfo.tab_type) : 0;

    let _mdlist = consts.mdList;

    let data = "";

    // 获取md的组名称
    // 接口文档从服务器md文件中读取
    //传入的type大小在 接口种类大小范围内
    if (_type >= 0 && (_type < consts.mdPower.length)) {
        let md_name = consts.mdPower[_type];
        let _md_child_list = _mdlist[md_name];
        if (tab_type >= 0 && (tab_type < _md_child_list.length)) {
            data = tools.mdtotxt(_md_child_list[tab_type]);
        }

        if (data) {
            return output.doOutput(data);
        } else {
            return consts.MSG.FILE_UNEXISTED;
        }


    } else {
        return consts.MSG.FILE_UNEXISTED;
    }

}

apiList['interdoc_list'] = interdoc.interdocList;
apiList['error_list'] = interdoc.errorList;