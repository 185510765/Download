<?php
return array(
	//'配置项'=>'配置值'
	
	
	'URL_CASE_INSENSITIVE'=>true,  //URL不区分大小写
	'URL_MODEL'=>1,                //URL模式
	'SESSION_AUTO_START' => true,  //是否开启session

	'DB_PARAMS' => array(\PDO::ATTR_CASE => \PDO::CASE_NATURAL),   //防止thinkphp把从数据库调出来的字段大写都变成小写
	
	//数据库连接配置
    'DB_TYPE'               =>  'mysql',           // 数据库类型
    'DB_HOST'               =>  'localhost', 	   // 服务器地址
    'DB_NAME'               =>  'wbguard',         // 数据库名
    'DB_USER'               =>  'root',      	   // 用户名
    'DB_PWD'                =>  '123456',          // 密码
    'DB_PORT'               =>  '3306',       	   // 端口
    'DB_PREFIX'             =>  'guard_',    	   // 数据库表前缀
    'DB_FIELDTYPE_CHECK'    =>  false,       	   // 是否进行字段类型检查
    'DB_FIELDS_CACHE'       =>  true,        	   // 启用字段缓存
    'DB_CHARSET'            =>  'utf8',      	   // 数据库编码默认采用utf8


);