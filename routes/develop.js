var express = require('express');
/* ***********引用区域************ */
const consts = require('../consts/consts');
const devtools = require('../control/devtools');
const interdoc = require('../control/interdoc');
const common = require('../control/common');

var router = express.Router();


//接口文档接口
router.post('/interdoc', function (aReq, aRes, aNext) {
    var tInfo = aReq.body;
    /** 判断 token*/
    var _to_check = common.verifytoken(aReq.headers["x-access-token"]) ;
    if(_to_check.errorcode == 0){
        aRes.json(interdoc.control(tInfo));
    }
    else{
        aRes.json(_to_check);
    }
    
});

//开发者工具
router.post('/devtools', function (aReq, aRes, aNext) {
    var tInfo = aReq.body;
    /** 判断 token*/
    var _to_check = common.verifytoken(aReq.headers["x-access-token"]) ;
    
    if(_to_check.errorcode == 0){
        aRes.json(devtools.control(tInfo));
    }
    else{
        aRes.json(_to_check);
    }
    
});



module.exports = router;