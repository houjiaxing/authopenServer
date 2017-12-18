"use strict";
var tools = module.exports;

const fs = require("fs");
const path = require('path');
const consts = require('../consts/consts.js');
const log = require('./log.js');
//校验邮箱格式
tools.isEmail = function(str) {
    return /^\w+((-\w+)|(\.\w+))*\@[A-Za-z0-9]+((\.|-)[A-Za-z0-9]+)*\.[A-Za-z0-9]+$/.test(str);
}

//读取md文件
tools.readmd = function(fileRoute) {
    let file = fs.existsSync(fileRoute); //判断文件是否存在
    if (file) {
        return fs.readFileSync(fileRoute, "UTF-8"); //文件存在返回文件内容
    } else {
        return null;
    }
   
}

 //判断值是否是数字,是否是空值
tools.isNumber = function(value) {
	if(typeof value==="number"){
		console.log("valueIsNunber is erro");
		return false;
	}
	return true;
};

//通过参数读取Md读文档
//@ ainfo 文件名
tools.mdtotxt = function(aInfo){

    let _name = aInfo;
    let md_list = consts.mdList;
    let tpath = path.resolve(__dirname, '..');
    let file_path = tpath+consts.mdDirPath+_name+'.md';//文件地址
    log.putTrans("tools---file_path:"+file_path);
    let tDoc = tools.readmd(file_path);

    return tDoc;
}

//判断是否为范围内的数字（整数），且是否不为-1
tools.checkInt = function(_min,_max,num){
    if(num == -1|| num == ""){
        return false;
    }
    else if((num<_min) || (num>_max)){//超过范围
        return false;
    }
    else if(Math.floor(num) !== num){//是否为整数
        return false;
    }
    else{
        return true;
    }
};

//判断数组长度是否超出范围，以及数组字段是否超出已有数组范围
//只适合小数据的数组，数组数据过多的情况，此方法会影响代码运行总耗时
tools.checkArr = function(arr,arr_base){

    let arr_count = arr.length;
    let arr_base_count = arr_base.length;

    if(arr_count>arr_base_count){//参数个数超过最大范围
        return false;
    }
    else{
        var i = 0;
        let _tmp = '';
        for(i =0;i<arr_count;i++){
            _tmp = arr[i].indexOf(arr_base);
            if(_tmp == -1){//如果不存在base数组中，即为无效数据
                _tmp =consts.MSG.OVER_BASE.errorcode;//错误的标识位
                break;
            }else{
                _tmp = 0;
            }
        }
        if(_tmp == consts.MSG.OVER_BASE.errorcode){
            return false;
        }
        else{
            return true;
        }
    }
}
