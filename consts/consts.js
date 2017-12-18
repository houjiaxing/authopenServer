var consts = module.exports = {};
consts.MSG = {
    /**成功 */
    ok: {
        "errorcode": 0,
        "errormsg": "success",
        "errorInfo": "ok"
    },
    //开发者工具signature解析成功
     SIGNATURE_SUCCESS:{
        'errorcode': 200,
        'errormsg': 'signature ok'
    },
    //文件不存在
    FILE_UNEXISTED: {
        "errorcode": -100,
        "errormsg": "file unexisted"
    },
    //邮箱格式错误
    EMAIL_ERROR: {
        "errorcode": -101,
        "errormsg": 'email error'
    },
    //缺少参数
    HTTP_UNSET_PARAM: {
        'errorcode': -102,
        'errormsg': 'param unset'
    },
    // 参数错误
    HTTP_WRONG_PARAM: {
        'errorcode': -103,
        'errormsg': 'param wrong'
    },
    //登录态过期
    UNLOGIN: {
        'errorcode': -104,
        'errormsg': 'login time over'
    },
    //apiname 不存在
    APINAME_NOT_EXIST: {
        'errorcode': -105,
        'errormsg': 'apiname not exit'
    }, 
    //开发者工具signature中的某个参数为空
    SIGNATURE_PARAM_NOT_EXIST:{
        'errorcode': -106,
        'errormsg': 'signature param not exit'
    },
    //开发者工具signature中的长度不对
    SIGNATURE_LENGTH_WRONG:{
        'errorcode': -107,
        'errormsg': 'signature length wrong'
    },
    //开发者工具signature中时间戳错误
    SIGNATURE_TIMESTAMP_WRONG:{
        'errorcode': -108,
        'errormsg': 'signature timestamp wrong'
    },
    //开发者工具signature过期
    SIGNATURE_TIMEOUT:{
        'errorcode': -109,
        'errormsg': 'signature time out'
    },
    //开发者工具signature中的apiname与传入的不同
    SIGNATURE_APINAME_ERROR:{
        'errorcode': -110,
        'errormsg': 'signature apiname error'
    },
    //开发者工具signature解析错误
    SIGNATURE_ERROR:{
        'errorcode': -111,
        'errormsg': 'signature error'
    },
    //404的重写
    NOT_FOUND:{
         'errorcode': -112,
         'errormsg': 'duck no found'
    },
    //500的重写
    SERVER_ERROR:{
         'errorcode': -113,
         'errormsg': 'duck error'
    },
    //aes解密工具，数据长度不对
    AES_LENGTH_WRONG:{
         'errorcode': -114,
         'errormsg': 'data length wrong'
    },
    //数据库操作失败
    DATABASE_ERROR:{
         'errorcode': -115,
         'errormsg': 'database error'
    },
    //数据库连接异常
    DATABASE_CONNECT_ERROR:{
        'errorcode': -116,
        'errormsg': 'database connect error'
    },
    //新增用户账号时，数据库中用户已存在
    USER_EXISTED:{
        'errorcode': -117,
        'errormsg': 'user existed'
    },
    //登录密码错误或者用户不存在
    USER_NO_EXIST_OR_PWD_WRONG:{
        'errorcode': -118,
        'errormsg': 'user no exist or pwd wrong'
    },
    //账号已经失效
    USER_INVALID:{
        'errorcode': -119,
        'errormsg': 'user invalid'
    },
    //账号状态是禁用
    USER_DISABLE:{
        'errorcode': -120,
        'errormsg': 'user disable'
    },
    //此用户没有查询用户列表的权限，非内部账号
    USER_NO_AUTHORITY:{
        'errorcode': -121,
        'errormsg': 'user no authority'
    }
}

//服务器静态文件文件夹名称
consts.resouceDirPath = '/public/';

//服务器md文件夹名称
consts.mdDirPath = '/public/mds/';

//服务器pdf文件夹名称
consts.pdfDirPath = '/public/interfaceDoc/';

//服务器demo文件夹名称
consts.demoDirPath = '/public/demo/';

//服务器常见错误码md路径
consts.errorMdPath = '/public/mds/errorlist.md';


//接口文档权限对应表
consts.mdPower =['public','mix','api','sdk','other'];


//接口文档md文件
consts.mdList = {//类型：{子分类}
    'public':[//公有部署接口文档
        'public',//公有云文档
        'public_document'//公有云自有库外部证照接口规范
    ],
    'mix':[//混合部署接口文档
        'mix',//混合部署
        'mix_document'//混合部署自有库证照接口规范
    ],
    'api':[//独立接口
        '1v1H5',//1v1
        'ocr',//OCR
        'startlivecomparison',//活体+1v1
        'startonlylive'//仅活体
    ],
    'sdk':[//appsdk接口文档
        'sdk_android',//android
        'sdk_ios'//ios
    ],
    'other':[//其他接口
        'pension_eligibility',//外部养老金领取资格接口
        'routine'   //小程序接口
    ]
};

//账号权限
consts.AUTHORITY = [0,1,2,3];

//aes秘钥长度为32位，其中十位为拼接时间戳因此此处定义22位
consts.Aeskeys = "city2muchtaoluiwilgonc";

//jwt生成秘钥
consts.Jwtkeys = "sbkill1rqlb6x";

//静态文件目录（demo）限制下载目录
consts.Demodir = "./public/demo";
consts.Pdfdir = "./public/interfaceDoc"