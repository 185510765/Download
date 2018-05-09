<?php
namespace Home\Controller;
use Think\Controller;

class IndexController extends Controller {

	// // 构造函数
	// public function __construct(){
	// 	parent::__construct();
	// 	if (!checkLogin())
	// 	{
	// 		$this->redirect('/Home/Index/login');
	// 	}
	// }

	//下载页面
    public function download(){
        $this->display('download');
    }

    //点击下载
    public function clickDownload(){
		$User=M('User');
		$map['admin']=array('EQ',transformData(I('get.username')));     //get传参  真正登录后就有数据了
		$info=$User->field('UserID,username,wbCount')->where($map)->find();
		if ($info) {  
			//这里写下载的判断条件，以后会修改
			if ($info['wbCount']>C('WBCOUNT')) {    //网吧数量大于10才给下载

				//文件流下载函数
				function download($fname,$fpath='Public/download/'){
				    //避免中文文件名出现检测不到文件名的情况，进行转码utf-8->gbk
				    $filename=iconv('utf-8', 'gb2312', $fname);
				    $path=$fpath.$filename;
				    if(!file_exists($path)){//检测文件是否存在
				        echo "文件不存在！";
				        die();
				    }
				    $fp=fopen($path,'r');//只读方式打开
				    $filesize=filesize($path);//文件大小

				    //返回的文件(流形式)
				    header("Content-type: application/octet-stream");
				    //按照字节大小返回
				    header("Accept-Ranges: bytes");
				    //返回文件大小
				    header("Accept-Length: $filesize");
				    //这里客户端的弹出对话框，对应的文件名
				    header("Content-Disposition: attachment; filename=".$filename);
				    
				    //================重点====================
				    ob_clean();
				    flush();
				    //=================重点===================
				    //设置分流
				    $buffer=1024;
				    //来个文件字节计数器
				    $count=0;
				    while(!feof($fp)&&($filesize-$count>0)){
				        $data=fread($fp,$buffer);
				        $count+=$data;//计数
				        echo $data;//传数据给浏览器端
				    }
				    fclose($fp);
				}
				download('腾讯.exe');
			}else{
				// echo '很抱歉，网吧数量大于10家的用户才可以下载';
				$this->redirect('Home/User/login','',3,'很抱歉，网吧数量大于10家的用户才可以下载,跳转登录页面中...');
			}
		}else{
			// echo '用户不存在';
			$this->redirect('Home/User/login','',3,'用户不存在,跳转登录页面中...');
		}
    }






}