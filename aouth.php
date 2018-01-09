<?php
//https://docs.openx.com/Content/developers/platform_api/api_report_use_case.html?Highlight=reporting%20api
//第一步：获取aouth_token
//必须参数
$consumer_key = "*****************";
$consumer_secret = '****************';
$username = "*************";
$password = "*************";
$url = array(
    'oauth_token' => 'https://sso.openx.com/api/index/initiate',
    'oauth_verifier' => 'https://sso.openx.com/login/process',
    'access_token' => 'https://sso.openx.com/api/index/token',
);
$time = time();
//组装array
$oauthStr = array(
    // "realm" => "mobimagic",
    "oauth_consumer_key" => $consumer_key,
    "oauth_callback" => 'oob',
    "oauth_signature_method" => 'HMAC-SHA1',
    "oauth_timestamp" => $time,
    "oauth_nonce" => generate_str(),
    "oauth_version" => '1.0',
);
$oauth = basestringTo($url['oauth_token'],$consumer_secret."&",$oauthStr);
//设置header
$headers = array();
$headers[] = 'Authorization: '.$oauth;
//通过curl抓取数据
$return = http($url['oauth_token'],null,$headers);
parse_str($return,$initiate);
print_r($initiate);

//第二步：获取oauth_verifier
// $url = "https://sso.openx.com/login/process";
//组装array
$oauthStr = array(
    // "realm" => "mobimagic",
    "oauth_consumer_key" => $consumer_key,
    "oauth_callback" => 'oob',
    "oauth_signature_method" => 'HMAC-SHA1',
    "oauth_timestamp" => $time,
    "oauth_nonce" => generate_str(),
    "oauth_version" => '1.0',
    "oauth_token" =>$initiate['oauth_token'],
);
$oauth = basestringTo($url['oauth_verifier'],$initiate["oauth_token_secret"]."&",$oauthStr);
//设置header
$headers = array();
$headers[] = 'Authorization: '.$oauth;  
$data = array();
$data["password"] = $password;
$data["oauth_token"] = $initiate["oauth_token"];
$data["email"] = $username;
//通过curl抓取数据
$return = http($url['oauth_verifier'],$data,$headers);
parse_str($return,$process);
print_r($process);


//第三步：获取token
// $url = "https://sso.openx.com/api/index/token";
//组装array
$oauthStr = array(
    // "realm" => "mobimagic",
    "oauth_consumer_key" => $consumer_key,
    "oauth_callback" => 'oob',
    "oauth_signature_method" => 'HMAC-SHA1',
    "oauth_timestamp" => $time,
    "oauth_nonce" => generate_str(),
    "oauth_version" => '1.0',
    "oauth_token" => $initiate['oauth_token'],
    "oauth_verifier" => $process["oauth_verifier"],
);
$secret = $consumer_secret.'&'.$initiate["oauth_token_secret"];
$oauth = basestringTo($url['access_token'],$secret,$oauthStr);
//设置header
$headers = array();
$headers[] = 'Authorization: '.$oauth;  
//通过curl抓取数据
$return = http($url['access_token'],null,$headers);
parse_str($return,$token);
print_r($token);



//处理array
function http_query($array){
    $str = array();
    foreach($array as $key=>$value){
        $str[] = urlencode3986($key)."%3D".urlencode3986($value);
    }
    return implode("%26",$str);
}
function urlencode3986($var){
    return str_replace('%7E', '~', rawurlencode($var));
}
function base64UrlEncode($str){  
    return base64_encode($str);
    $find = array('+', '/');  
    $replace = array('-', '_');  
    return str_replace($find, $replace, base64_encode($str));  
}  
//生成随机字符串
function generate_str( $length = 8 ) { 
    // 字符集
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; 
    $chars = '0123456789'; 
    $str = ""; 
    for ( $i = 0; $i < $length; $i++ ) 
    { 
        // 这里提供两种字符获取方式 
        // 第一种是使用 substr 截取$chars中的任意一位字符； 
        // 第二种是取字符数组 $chars 的任意元素 
        // $password .= substr($chars, mt_rand(0, strlen($chars) – 1), 1); 
        $str .= $chars[ mt_rand(0, strlen($chars) - 1) ]; 
    } 
    return $str; 
}
function basestringTo($url,$consumer_secret,$oauthArr=array()){
    //根据key排序
    ksort($oauthArr);
    //生成base string
    $str = "POST&".urlencode3986($url)."&".http_query($oauthArr);
    //生成oauth_signature
    $keys = urlencode3986(base64UrlEncode(hash_hmac('sha1', $str, $consumer_secret,true)));
    //生成Authorization
    $oauth = "OAuth ".str_replace(array('&','='),array('",','="'),http_build_query($oauthArr))."\",oauth_signature=\"{$keys}\"";
    return $oauth;
}
//参数说明： 
//url:服务器接收处理url
//data: 数组形式的post数据 
//headers: 数组形式的header数据 
function http($url, $data = NULL, $headers = null)
{
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_BINARYTRANSFER, true);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_TIMEOUT, 10);
    if (!empty($data)) {
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
    }
    if($headers){
        curl_setopt($curl, CURLOPT_HTTPHEADER,$headers);
    }
    $res = curl_exec($curl);
    curl_close($curl);
    return $res;
}
?>
