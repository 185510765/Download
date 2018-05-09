<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006-2014 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------

// 应用入口文件

// 检测PHP环境
if(version_compare(PHP_VERSION,'5.3.0','<'))  die('require PHP > 5.3.0 !');

//设置字符集
header("content-type:text/html;charset=UTF-8");

//把目前的tp模式改为开发模式(开发模式错误显示更详细),默认是flase生产模式
define("APP_DEBUG", true);

// 定义应用目录
define('APP_PATH','./Application/');

//引入ThinkPHP框架的核心程序
include "./ThinkPHP/ThinkPHP.php";

// 亲^_^ 后面不需要任何代码了 就是如此简单