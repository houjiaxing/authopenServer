const express = require('express');
const router = express.Router();
const common = require('../control/common');
const user = require('../control/user');


//登录接口
router.post('/', function(aReq, aRes, aNext) {
    var tInfo = aReq.body;
    let verifytoken = common.verifytoken(aReq.headers["x-access-token"]);
    //校验请求是否合法
    if (verifytoken.errorcode != 0) {
        aRes.json(verifytoken).end();
    } else {
        user.control(tInfo, verifytoken.data, function(res) {
            aRes.json(res);
        })
    }

});


module.exports = router;