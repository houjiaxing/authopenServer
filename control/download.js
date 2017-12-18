"use strict";

var download = module.exports;

var path = require('path');
var fs = require('fs');

const consts = require('../consts/consts');
const log = require('../util/log.js').logger;

/**
 * 文件下载
 * @author Luke
 */
/**
 * @api {get} /download 文件下载接口
 * @apiVersion 1.0.0
 * @apiDescription 用于下载文件，直接返回调用浏览器下载功能
 * @apiName download
 * @apiGroup Download
 *
 * @apiParam {String} x-access-token 该参数放在Header中,用于登录态验证.
 * @apiParam {String} name 文件名.
 * @apiParam {String} type 文件类型（可选：pdf，demo）.
 * @apiParamExample {Object} 请求Header(具体请从login接口获取)：
 * {
 *      "x-access-token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiNTk5M2IxYjBmZTQyNGI2NWI0MjBiZTI3IiwiaWF0IjoxNTEzNDc5OTEyLCJleHAiOjE1MTM0ODM1MTJ9.5OU11vmi1VktyXBDp_DcgKrqVfGDSGMMpDYWwGq4Cwo",
 * }
 * @apiParamExample {Object} 请求Url：
 *    http://t.lukex.cc:8080/download?name=aes_java.zip&type=demo
 *
 * @apiSuccess file 直接调用下载文件
 * @apiError {Number} errorcode 统一返回错误码.
 * @apiError {String} errormsg  统一返回错误描述.
 */
download.doDownload = function(req, res) {
    var fileName = req.query.name,
        fileType = req.query.type,
        FileAlldir,
        fReadStream;
    fileName = fileName.replace(/\..\//g, '');

    switch (fileType) {
        case 'pdf':
            FileAlldir = consts.Pdfdir;
            break;
        case 'demo':
            FileAlldir = consts.Demodir;
            break;
        default:
            res.json(consts.MSG.HTTP_WRONG_PARAM);
    }
    var currDir = path.normalize(FileAlldir);
    var currFile = path.join(currDir, fileName);
    try {
        fs.exists(currFile, function(exist) {
            if (exist) {
                res.set({
                    "Content-type": "application/octet-stream",
                    "Content-Disposition": "attachment;filename=" + encodeURI(fileName)
                });
                fReadStream = fs.createReadStream(currFile);
                fReadStream.on("data", (chunk) => res.write(chunk, "binary"));
                fReadStream.on("end", function() {
                    res.end();
                });
            } else {
                res.json(consts.MSG.FILE_UNEXISTED);
            }
        });
    } catch (err) {
        log.error("Get Download File Err:" + err);
        res.status(200);
        res.json(consts.MSG.SERVER_ERROR);
    }
}