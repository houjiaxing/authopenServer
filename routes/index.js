var express = require('express');

var path = require('path');
var fs = require('fs');
/* ***********引用区域************ */
const login = require('../control/login');
const common = require('../control/common');
const download = require('../control/download');

var router = express.Router();


//登录接口
router.post('/login', function (aReq, aRes, aNext) {
    var tInfo = aReq.body;
    login.control(tInfo,aReq, function(res){
        aRes.json(res);
    })
});



//文件下载（目前支持单文件下载）读取方式： /download?name=xxx

router.get('/download',function(req, res, next){
    let verifytoken = common.verifytoken(req.headers["x-access-token"]);
    if( verifytoken.errorcode  == 0){
        download.doDownload(req, res);
    }
    else{
        res.json(verifytoken);
    }
});

module.exports = router;