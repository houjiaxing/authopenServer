const mysql = require("mysql");
const dbConfig = require("../config/dbConfig.json");


/**
 * 创建数据库连接池
 */
let pool = mysql.createPool(dbConfig.dev);

/**
 * 数据库操作
 * @param {*} sql 
 * @param {*} options 
 * @param {*} callback 
 */
exports.operation = function (sql,options,callback){
    // return new Promise(function(resolve,reject){
    //     pool.getConnection(function(err,conn){
    //         if(err) {
    //             reject(err);
    //         }else{
    //             conn.query(sql,options,function(err,results){  
    //                 //释放连接  
    //                 conn.release();  
    //                 //事件驱动回调  
    //                 if(err){
    //                     reject(err);
    //                 }
    //                 else{
    //                     resolve(results);   
    //                 }
                    
    //             });
    //         }
    //     })
    // });
    pool.getConnection(function(err,conn){
        if(err) {
            callback(err);
        }else{
            conn.query(sql,options,function(err,results){  
                //释放连接  
                conn.release();  
                //事件驱动回调  
                callback(err,results);
            });
        }
    })
}