<?php
require_once('metadata_store.php');

$text = file_get_contents("https://mds.fidoalliance.org");
$metadata_TOC = explode('.',$text);
$jwt_header = json_decode(base64url_decode($metadata_TOC[0]));
$payload = json_decode(base64url_decode($metadata_TOC[1]));
$sig = change_siganture_to_der_format(base64url_decode($metadata_TOC[2]));
$msg = $metadata_TOC[0].'.'.$metadata_TOC[1];


//var_dump($jwt_header);
if(isset($jwt_header->x5c)){
        if(!verify_JWS($msg,$sig,$jwt_header->x5c[0])){
                echo 'verify jw signature fail';
                exit;
        }
        //verify_cert_chain($jwt_header->x5c); 
}
//check_metadata_toc_no($payload->no);

//var_dump($payload);
foreach($payload->entries as $entry){

        //$entry = $payload->entries[0];
        $metadata = file_get_contents($entry->url);
        if(strcmp(hash('sha256',$metadata,true),base64url_decode($entry->hash))!==0){
                echo $metadata->aaid.' hash value differ from website';
                continue;
        }
        //var_dump(base64url_decode($metadata));
        process_metadata($metadata);
}






function verify_JWS($msg,$sig,$cert){
        $pemCert  = "-----BEGIN CERTIFICATE-----\r\n";
        $pemCert .= chunk_split($cert, 64);
        $pemCert .= "-----END CERTIFICATE-----";
        if(!openssl_pkey_get_public($pemCert)) {
                var_dump("register openssl get public error!!");
                return false;
        }
        if(openssl_verify($msg,$sig, $pemCert,'sha256') !== 1) {
                var_dump('verify sig fail!');
                return false;
        }
        return true;
}

function change_siganture_to_der_format($sig){
                $sig_hex = bin2hex($sig);
                $i=0;
                $str1 = substr($sig_hex,0,64);
                $str2 = substr($sig_hex,64,64);
                if(hexdec($str1[0]) > 7){
                        $str1 = '022100'.$str1;
                        $i++;
                }else{
                        $str1 = '0220'.$str1;
                }
                if(hexdec($str2[0]) > 7){
                        $str2 = '022100'.$str2;
                        $i++;
                }else{
                        $str2 = '0220'.$str2;
                }
                if($i==0){
                        $out = '3044'.$str1.$str2;
                }elseif($i==1){
                        $out = '3045'.$str1.$str2;
                }else{
                        $out = '3046'.$str1.$str2;
                }
                return hex2bin($out);
}

function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
}

function base64url_encode($data) {
        return trim(strtr(base64_encode($data), '+/', '-_'), '=');
}

?>