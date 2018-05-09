<?php 




//判断nav类型
function type($tpye){
	switch ($tpye) {
		case '0':
			return 'nav导航';
			break;
		case '1':
			return 'top_left顶部左边';
			break;
		case '2':
			return 'top_right顶部右边';
			break;
		case '3':
			return 'footer底部全站导航';
			break;
		case '4':
			return 'footer底部在线服务';
			break;
	}
}

//展示状态
function status($status){
	switch ($status) {
		case '0':
			return '停用业务';
			break;
		case '1':
			return '前台业务';
			break;
		case '2':
			return '强制业务';
			break;	
		default:
			return '<span style="color:red;">测试业务</span>';
			break;
	}
}

//去除空格，html，换行
function deleteHtml($str) {
    $str = trim($str); //清除字符串两边的空格
    $str = preg_replace("/\t/","",$str); //使用正则表达式替换内容，如：空格，换行，并将替换为空。
    $str = preg_replace("/\r\n/","",$str); 
    $str = preg_replace("/\r/","",$str); 
    $str = preg_replace("/\n/","",$str); 
    $str = preg_replace("/ /","",$str);
    $str = preg_replace("/  /","",$str);  //匹配html中的空格
    return trim($str); //返回字符串
}

//正则表达式过滤特殊字符
function replaceSpecialChar($strParam){
    $patten='/^SELECT|select|DELETE|delete|UPDATE|update|INSERT|insert|from|into|OR|or|WHERE|where|AND|and|DROP|drop|order|by|table|database|script|alert|values|\<|\>|union|into|outfile$/';
    return preg_replace($patten,"",$strParam);
}


//处理提交上来的值  $value提交值  $default数字默认返回值  $type类型 默认txt字符串 
function transformData($value,$default='',$type='txt'){
	//设置 类型判断
	if ($type=='int') {    //如果是数字
		if (is_numeric($value)) {
			return $value;
		}else{
			return $default;
		}
	}

	//转义特殊字符   输出数据的时候在反转义
	// $value=htmlspecialchars(addslashes($value));
	$value=htmlspecialchars(addslashes($value));

	// //去除空格，html，换行
	// $value = trim($value); //清除字符串两边的空格
	// $value = preg_replace("/\t/","",$value); //使用正则表达式替换内容，如：空格，换行，并将替换为空。
	// $value = preg_replace("/\r\n/","",$value); 
	// $value = preg_replace("/\r/","",$value); 
	// $value = preg_replace("/\n/","",$value); 
	// $value = preg_replace("/ /","",$value);
	// $value = preg_replace("/  /","",$value);  //匹配html中的空格
	// // $value = preg_replace("'","",$value);   //单引号
	// // $value = preg_replace("\"","",$value);   //双引号

	//正则表达式过滤特殊字符
	$patten='/^SELECT|select|DELETE|delete|UPDATE|update|INSERT|insert|from|into|WHERE|where|AND|and|DROP|drop|table|database|alert|values|union|into|outfile$/';
	return preg_replace($patten,"",$value);
}

// //待优化 反转义 看能不能直接一次性反转义所有的数据
// function unescape($list){
// 	if (is_array($list)) {    //是数组
// 		foreach ($list as $key => $value) {
// 			$list[$key]=htmlspecialchars_decode(stripslashes($value));
// 		}
// 	}else{    //不是数组
// 		$list=htmlspecialchars_decode(stripslashes($list));
// 	}
// 	return $list;
// }


//反转义 最终目的就是转义数组里面的数据
function unescape($list){
	if (is_array($list)) {    //是数组
		if (count($list) == count($list, 1)) {   //一维数组
		    foreach ($list as $key => $value) {
		    	$list[$key]=htmlspecialchars_decode(stripslashes($value));
		    }
		} else {       //二维数组
		    foreach ($list as $key => $value) {
		    	foreach ($list[$key] as $k => $v) {
		    		$list[$key][$k]=htmlspecialchars_decode(stripslashes($v));
		    	}
		    }
		}
	}else{    //不是数组
		$list=htmlspecialchars_decode(stripslashes($list));
	}
	return $list;
}


//判断是否含有非法字符  
function findSpecialChar($char){
	$patten='/^SELECT|select|DELETE|delete|UPDATE|update|INSERT|insert|from|into|WHERE|where|AND|and|DROP|drop|table|database|alert|values|union|into|outfile$/';
	if (preg_match($patten,$char)) {
		return false;
	}else{
		return true;
	}
}

//业务列表 web配置 加载配置单独写的
function config($char){
	$patten='/^SELECT|select|DELETE|delete|UPDATE|update|INSERT|insert|from|into|OR|WHERE|where|AND|DROP|drop|order|by|table|database|script|alert|values|\<|\>|union|into|outfile$/';
	if (preg_match($patten,$char)) {
		return false;
	}else{
		return true;
	}
}
function replaceConfig($char){
	$patten='/^SELECT|select|DELETE|delete|UPDATE|update|INSERT|insert|from|into|OR|WHERE|where|AND|DROP|drop|order|by|table|database|script|alert|values|\<|\>|union|into|outfile$/';
	return preg_replace($patten,"",$char);
}


//检测是否为空
function checkEmpty($char){
	if ($char=='' || $char==null) {
		return false;
	}
	return true;
}

//检测是否是正整数 (包括0)
function checkNum($num){
	if ($num=='' || $num==null) {
		return true;
	}else{
		$patten='/^\+?[0-9][0-9]*$/';
		if (preg_match($patten,$num)) {
			return true;
		}else{
			return false;
		}

	}
}

//邮箱验证
function checkEmail($email){
	if ($email!='' && $email!=null) {
		// $pattern='/^[A-Za-z\d]+([-_.][A-Za-z\d]+)*@([A-Za-z\d]+[-.])+[A-Za-z\d]{2,4}$/';
		$pattern='/^(\w)+(\.\w+)*@(\w)+((\.\w{2,3}){1,3})$/';
		if (preg_match($pattern,$email)) {
			return true;
		}else return false;
	}else return true;
}

//验证整数或小数二位的正则(不包括0)
function checkFloat($float){
	$patten='/^[0-9]+(.[0-9]{1,2})?$/';
	if (preg_match($patten,$float)) {
		return true;
	}else{
		return false;
	}
}

//判断邮政编码 可以为空
function checkZipcode($num){
	if ($num!='' && $num!==null) {
		$pattern='/^[a-zA-Z0-9 ]{3,12}$/';
		if (preg_match($pattern,$num)){
			return true;
		}else{
			return false;
		}
	}else return true;
}

//判断电话 座机和手机  可以为空
function checkPhone($num){
	if ($num!='' && $num!==null) {
		$isTel='/^([0-9]{3,4}-)?[0-9]{7,8}$/';    //固定电话
		$isPhone='/^((\+?86)|(\(\+86\)))?(13[012356789][0-9]{8}|15[012356789][0-9]{8}|18[02356789][0-9]{8}|147[0-9]{8}|1349[0-9]{7})$/';  //手机
		if (preg_match($isTel,$num) || preg_match($isPhone,$num)){
			return true;
		}else{
			return false;
		}
	}else return true;
}

//判断插件类型函数
function stype($stype){
	switch ($stype) {
		case '0':
			return '单选';
			break;
		case '1':
			return '多选';
			break;
		default:
			return '混合';
			break;
	}
}

//判断插件后缀类型函数
function petype($petype){
	switch ($petype) {
		case '0':
			return 'EXE';
			break;
		case '1':
			return 'dll';
			break;
		case '2':
			return 'sys';
			break;
	}
}

//获取软件版本信息
function getFileVersion($filename)
{
    $fileversion='';
    $fpFile = @fopen($filename, "rb");
    $strFileContent = @fread($fpFile, filesize($filename));
    fclose($fpFile);
    if($strFileContent)
    {
        $strTagBefore = 'F\0i\0l\0e\0V\0e\0r\0s\0i\0o\0n\0\0\0\0\0';
        $strTagAfter = '\0\0';
        if (preg_match("/$strTagBefore(.*?)$strTagAfter/", $strFileContent,$arrMatches))
        {
            if(count($arrMatches)==2) $fileversion=str_replace("\0",'',$arrMatches[1]);
        }
    }
    return $fileversion;
}

//获取上传文件后缀名
function get_extension($file) {    //文件名称，不含路径
	return substr(strrchr($file, '.'), 1);
} 

//加密
function base64encode($string) {
   $data = base64_encode($string);
   $data = str_replace(array('+','/','='),array('-','_',''),$data);
   return $data;
}

//解密
function base64decode($string) {
   $data = str_replace(array('-','_'),array('+','/'),$string);
   $mod4 = strlen($data) % 4;
   if ($mod4) {
       $data .= substr('====', $mod4);
   }
   return base64_decode($data);
}

//验证码函数
function code($_width=75,$_height=25,$_rnd_code=4){
	//创建随机码，
	// $_rnd_code=4;
	for ($i=0; $i < $_rnd_code; $i++) { 
		@$_nmsg.=dechex(mt_rand(0,15));
	}
	//保存在session里面
	$_SESSION['code']=$_nmsg;
	//验证码
	header('content-type:image/png'); //标头
	$_width=75;  //长和高
	$_height=30;
	$_img=imagecreatetruecolor($_width, $_height);//创建一张图像
	$_white=imagecolorallocate($_img,255,255,255); //分配颜色
	imagefill($_img, 0, 0, $_white); //填充颜色,要在下面边框上面才行

	 $_black=imagecolorallocate($_img, 0, 0, 0);
	// imagerectangle($_img, 0, 0, $_width-1, $_height-1, $_black);//边框

	// //随机画出6个线条
	// for ($i=0; $i < 3; $i++) { 
	// 	$_rnd_color=imagecolorallocate($_img, mt_rand(0,255), mt_rand(0,255), mt_rand(0,255)); //随机色
	// 	imageline($_img, mt_rand(0,$_width),mt_rand(0,$_height),mt_rand(0,$_width),mt_rand(0,$_height),$_rnd_color); //6条随机色线条
	// }

	// //随机雪花
	// for ($i=0; $i < 100; $i++) { 
	// 	$_rnd_color=imagecolorallocate($_img, mt_rand(200,255), mt_rand(200,255), mt_rand(200,255)); //随机色(淡色，数值越大，颜色越淡)
	// 	imagestring($_img, 1,mt_rand(1,$_width),mt_rand(1,$_height),'*', $_rnd_color);
	// }

	//输出验证码
	for ($i=0; $i <strlen($_SESSION['code']) ; $i++) { 
		$_rnd_color=imagecolorallocate($_img, mt_rand(0,100), mt_rand(0,150), mt_rand(0,200)); //随机色
		imagestring($_img,mt_rand(3,5),$i*$_width/$_rnd_code+mt_rand(1,10),mt_rand(1,$_height/2),$_SESSION['code'][$i],$_rnd_color);  //定位x，y的位置
	}

	imagepng($_img); //输出图像
	imagedestroy($_img);//销毁
}



//判断是管理员还是用户
function user($status){
	return $status==0?'管理员':'用户';
}

//根据时间戳返回星期几
function weekday($time){
	$weekday = array('星期日','星期一','星期二','星期三','星期四','星期五','星期六');
	return $weekday[date('w',$time)];
}

// 生成Random_code 随机盐值 一般8位数
function BuildRandom_Code($num)
{
	$str = "123456789abcdefghijkmnpqrstuvwxyz";
	$code = '';
	for ($i = 0; $i < $num; $i++) {
		$code .= $str[mt_rand(0, strlen($str)-1)];
	}
	return $code;
}

//加盐 只是用法
function salt(){
	//密码加盐(注册的时候创建盐值，登录的时候查询盐值salt 对比存入数据库的password)
	//用户注册->提交密码->产生salt->腌制好的密码存入数据库->salt存入数据库。
   //用户登录->提交密码->调用salt接到提交密码的后面->进行HASH->调用之前注册腌制好的密码->对比HASH值是否和这个密码相同
	// $salt=BuildRandom_Code(8);   盐值
	// $password=sha1($password.$salt); 
}

//cookie加密
function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {   
	// 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙   
	$ckey_length = 4;   
	// 密匙   
	// $key = md5($key ? $key : $GLOBALS['discuz_auth_key']);   
	$key = md5($key ? $key : sha1('scriptKey'));   //如果为空默认这个
	// // 密匙a会参与加解密   
	$keya = md5(substr($key, 0, 16));   
	// 密匙b会用来做数据完整性验证   
	$keyb = md5(substr($key, 16, 16));   
	// 密匙c用于变化生成的密文   
	$keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';   
	// 参与运算的密匙   
	$cryptkey = $keya.md5($keya.$keyc);   
	$key_length = strlen($cryptkey);   
	// 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyb(密匙b)， //解密时会通过这个密匙验证数据完整性   // 如果是解码的话，会从第$ckey_length位开始，因为密文前$ckey_length位保存 动态密匙，以保证解密正确   
	$string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;   
	$string_length = strlen($string);   
	$result = '';   $box = range(0, 255);   
	$rndkey = array();   
	// 产生密匙簿   
	for($i = 0; $i <= 255; $i++) {     
		$rndkey[$i] = ord($cryptkey[$i % $key_length]);  
	}   
	// 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度   
	for($j = $i = 0; $i < 256; $i++) {     
		$j = ($j + $box[$i] + $rndkey[$i]) % 256;     
		$tmp = $box[$i];     $box[$i] = $box[$j];    
	    $box[$j] = $tmp;  
	}   
	// 核心加解密部分   
	for($a = $j = $i = 0; $i < $string_length; $i++) {    
		$a = ($a + 1) % 256;     
		$j = ($j + $box[$a]) % 256;     
		$tmp = $box[$a];     
		$box[$a] = $box[$j];     
		$box[$j] = $tmp;     
		// 从密匙簿得出密匙进行异或，再转成字符    
		$result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));   
	}   
	if($operation == 'DECODE') {     
		// 验证数据有效性，请看未加密明文的格式     
		if((substr($result, 0, 10) == 0 || substr($result, 0, 10)) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {  return substr($result, 26);     
		} else {       
			return '';     
		}   
	} else {     
		// 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因     
		// 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码     
		return $keyc.str_replace('=', '', base64_encode($result));   
	} 
}

function use124(){   //上面用法
	$str = 'abcdef'; 
	$key = getIp();                        //密匙$key用ip 绑定ip 防止复制cookie到另外一台机器登录
	$jm = authcode($str,'ENCODE',$key,0); //加密 
	      authcode($jm ,'DECODE',$key,0); //解密 
}

// function url(){         //http://localhost/wbguard/ 域名后第一个目录 根目录
// 	// $protocol = empty($_SERVER['HTTP_X_CLIENT_PROTO']) ? 'http:' : $_SERVER['HTTP_X_CLIENT_PROTO'] . ':';  //协议类型，http或者是https
// 	// $directory=explode('/',$_SERVER['PHP_SELF']);     //根目录
// 	// //完整路径   协议           域名，主机名              根目录          下载路径      文件名
// 	// $url = ''.$protocol.'//'.$_SERVER['HTTP_HOST'].'/'.$directory[1];
// 	$PHP_SELF=$_SERVER['PHP_SELF'];
// 	$url='http://'.$_SERVER['HTTP_HOST'].substr($PHP_SELF,0,strrpos($PHP_SELF,'/')+1);
// 	return dirname($url);
// }

//获取目录url  文件夹目录
function getUrl(){    //当前文件的上一个路径 不含当前文件  http://localhost/wbguard/Admin/Controller/
	$PHP_SELF=$_SERVER['PHP_SELF'];
	$url='http://'.$_SERVER['HTTP_HOST'].substr($PHP_SELF,0,strrpos($PHP_SELF,'/')+1);
	return $url;
}

//获取本地文件上传路径 文件上传只能本地路径 不能url
function upload_url(){                    //当前路径的上一个路径 本地路径 C:/Users/Administrator/Desktop/file
	return str_replace('\\','/',dirname(dirname(dirname(__FILE__)))).'/';
}




//ip获取
function getIp()
{
    $arr_ip_header = array(
        'HTTP_CDN_SRC_IP',
        'HTTP_PROXY_CLIENT_IP',
        'HTTP_WL_PROXY_CLIENT_IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'REMOTE_ADDR',
    );
    $client_ip = 'unknown';
    foreach ($arr_ip_header as $key)
    {
        if (!empty($_SERVER[$key]) && strtolower($_SERVER[$key]) != 'unknown')
        {
            $client_ip = $_SERVER[$key];
            break;
        }
    }
    return $client_ip;
}



//ip转换成int存到数据库 无符号
function ipToInt($ip){
    return sprintf("%u",ip2long($ip));
}

// 根据ip地址获取所在城市  是一个数组
function GetIpLookup($ip = ''){  
    if(empty($ip)){  
        $ip = GetIp();  
    }  
    $res = @file_get_contents('http://int.dpool.sina.com.cn/iplookup/iplookup.php?format=js&ip=' . $ip);  
    if(empty($res)){ return false; }  
    $jsonMatches = array();  
    preg_match('#\{.+?\}#', $res, $jsonMatches);  
    if(!isset($jsonMatches[0])){ return false; }  
    $json = json_decode($jsonMatches[0], true);  
    if(isset($json['ret']) && $json['ret'] == 1){  
        $json['ip'] = $ip;  
        unset($json['ret']);  
    }else{  
        return false;  
    }  
    // return $json;   里面是所有信息 下面是提取需要的信息 
    return $json['country'].$json['province'].$json['city'];  
} 

//管理后台登录验证,判断超时
function checkLogin(){
	//cookie自动登录
	// if (!is_null($_COOKIE['username']) && !is_null($_COOKIE['salt']) && !$_SESSION['userinfo']) {
	if (!is_null($_COOKIE['username']) && !is_null($_COOKIE['salt'])) {
		$salt=authcode($_COOKIE['salt'] ,'DECODE');      //解密 
		$value=explode('|',authcode($_COOKIE['username'] ,'DECODE',$salt,0)); //去ip和username
		$username=$value[0];
		$ip=$value[1];
		if (getIp()==$ip) {   //判断ip 是否是同一台机器
			$result=mysql_query("SELECT * FROM guard_home_user WHERE username='$username' LIMIT 1");
			if (mysql_affected_rows()) {
				while($row=mysql_fetch_assoc($result)){
					$info=$row;
				}
				$time=time();
				// mysql_query("UPDATE guard_home_user SET loginTime='$time' WHERE username='$username'");    //修改登录时间
				//在写入到session
				$userinfo=array(
						'id'=>$info['id'],
						'username'=>$info['username'],
						'loginTime'=>time(),
						'type'=>$info['type'],
					);
				$_SESSION['userinfo']=$userinfo; 
				//刷新cookie
				$directory=explode('/',$_SERVER['PHP_SELF']);     //根目录  设置cookie路径用
				if (isset($_COOKIE['autologin'])) {               //勾了15天
					$autologin=authcode($_COOKIE['autologin'] ,'DECODE');      //解密 
					if ($autologin=='on') {            
						setcookie('username',authcode($info['username'].'|'.getIp(),'ENCODE',$info['salt'],0),time()+3600*24*15,'/'.$directory[1]);
						setcookie('salt',authcode($info['salt'],'ENCODE'),time()+3600*24*15,'/'.$directory[1]);
						setcookie('autologin',authcode($autologin,'ENCODE'),time()+3600*24*15,'/'.$directory[1]);  //15天自动登录判断，防止被当前时间刷新
					}
				}else{                                           //没勾   是判断cookie 
					setcookie('username',authcode($info['username'].'|'.getIp(),'ENCODE',$info['salt'],0),time()+3600*2,'/'.$directory[1]);
					setcookie('salt',authcode($info['salt'],'ENCODE'),time()+3600*2,'/'.$directory[1]);
				}
				mysql_free_result($result);  //释放结果集
				mysql_close();
			}else{
				// return false;
				header('Location: login.php');     // 登出  
			}
		}else{ 
			// return false;
			header('Location: login.php');     // 登出  
		}
	}else{    //不存在 返回登录页面
		// return false;
		header('Location: login.php');     // 登出  
	}

}


//发送邮件 $to发送给谁  $status 0:关闭 1：开启   $type 类型  0：提交问题回复邮件  1：找回密码回复邮件
function sendMail($to,$type){
	if ($to!='' && $to!=null) {   //收件人不为空
		//查询配置信息
		$result=mysql_query("SELECT * FROM guard_home_emailsetting ORDER BY emailId LIMIT 1");
		if (mysql_affected_rows()) {
			while ($rows=mysql_fetch_assoc($result)) {
				$list=$rows;
			}
			$list=unescape($list);
			//邮件配置信息
			$smtpserver = $list['smtpServer'];                        //SMTP服务器
			$smtpserverport=$list['port'];                            //SMTP服务器端口
			$smtpusermail=$list['smtpUsermail'];                      //SMTP服务器的用户邮箱
			$smtpuser=$list['smtpUser'];                              //SMTP服务器的用户帐号    
			$smtppass=$list['smtpPwd'];                               //SMTP服务器的用户密码  一般是授权码
			$mailtype=$list['mailType']=='0'?'HTML':'TXT';            //邮件格式（HTML/TXT）,TXT为文本邮件

			//查询邮件模板内容
			$result=mysql_query("SELECT * FROM guard_home_emailmodel WHERE status='1' AND type='$type'");
			if (mysql_affected_rows()) {
				while($rows=mysql_fetch_assoc($result)){
					$info=$rows;
				}
				//查找这个邮件对应的 用户名
				$result=mysql_query("SELECT id,username FROM guard_home_user WHERE email='$to'");
				if (mysql_affected_rows()) {
					while ($rows=mysql_fetch_array($result)) {
						$user=$rows;
					}
					$info=unescape($info);
					//邮件模板内容
					$smtpemailto=$to;
					$mailtitle=$info['title'];
					$mailcontent='您的ID是：'.$user['id'].'<br/>您的登录名是：'.$user['username'].'<br/>密码重置地址：<a href="'.dirname(getUrl()).'/changepwd.php?id='.authcode($user['id'],'ENCODE').'">点击进行密码重置</a><br>'.$info['content'];    //绝对路径带id参数
					// $mailcontent=$list['username'].$info['content'];   //用户名+内容

					$smtp = new Smtp($smtpserver,$smtpserverport,true,$smtpuser,$smtppass);//这里面的一个true是表示使用身份验证,否则不使用身份验证.
					$smtp->debug = false;//是否显示发送的调试信息
					$state = $smtp->sendmail($smtpemailto, $smtpusermail, $mailtitle, $mailcontent, $mailtype);
				}
				
			}
		}
	}
}

//转换文件大小的单位
function getsize($size, $format = 'kb') {
    $p = 0;
    if ($format == 'kb') {
        $p = 1;
    } elseif ($format == 'mb') {
        $p = 2;
    } elseif ($format == 'gb') {
        $p = 3;
    }
    $size /= pow(1024, $p);
    return number_format($size, 1);   // 1表示保留的是小数点后一位，会四舍五入
}











 ?>
