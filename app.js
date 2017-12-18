var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var helmet = require('helmet');

var index = require('./routes/index');
var users = require('./routes/users');
var develop = require('./routes/develop');
var consts = require('./consts/consts.js');

var app = express();


//测试环境开启js跨域支持
app.all('*', function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Headers', 'Content-Type, Content-Length, Authorization, Accept, X-Requested-With , yourHeaderFeild,x-access-token');
    res.header('Access-Control-Allow-Methods', 'POST, GET');
    next();
});

app.use(helmet());
app.use(helmet.hidePoweredBy({ setTo: 'Hello! Thank you! Thank you very much!' }));

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

//删除日志目录、public目录托管（如无需则删除）
//  app.use(express.static(path.join(__dirname, 'public')));

// app.use(express.static(path.join(__dirname, 'data/authOpen')));

//托管静态资源目录img到虚拟目录static
app.use('/img', express.static('public/img'));
//托管 apidoc  目录
app.use(express.static('res'));

app.use('/', index);
app.use('/users', users);
app.use('/develop', develop);

// 捕获404异常并抛给错误处理模块
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// // 错误处理模块
app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    // render the error page
    res.status(200);
    switch (err.status) {
        case 404:
            res.json(consts.MSG.NOT_FOUND);
            break;
        default:
            res.json(consts.MSG.SERVER_ERROR);
            break;
    }
});

module.exports = app;