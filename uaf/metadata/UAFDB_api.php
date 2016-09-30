<?php
class UAF_DB {

        public function __construct($db_host,$db_user,$db_password,$db_name){
                $this->host = $db_host;
                $this->user = $db_user;
                $this->password = $db_password;
                $this->name = $db_name;
        }
        public function connect_to_database(){
                $conn = new mysqli("localhost","testuser","test","uaf_server");
                //$conn = new mysqli($this->host,$this->user,$this->password,$this->name);
                if($conn->connect_error){
                        die("Connect failed: ".$conn->connect_error);
                }
                return $conn;
        }
        public function store_user_data($connect_db,$username,$password){
                $sql = "INSERT INTO user_data (username,password) VALUES ('$username','$password')";
                $connect_db->query($sql);
        }

/********* token data**************/
        public function store_registration_data($connect_db,$user,$data){
                foreach($data as $value){
                        $keyid = $value['keyid'];
                        $publickey = $value['publickey'];
                        $aaid = $value["aaid"];
                        $version = $value["authenticator_version"];
                        $signcounter = $value["sign_counter"];
                        $sql = "INSERT INTO token_data (username,aaid,keyid,authenticator_version,publickey,sign_counter) VALUES ('$user','$aaid','$keyid','$version','$publickey','$signcounter')";
                        $connect_db->query($sql);
                }

        }

        public function get_already_reg_token($connect_db,$user){
                $sql = "SELECT * FROM token_data WHERE token_data.username = '$user'";
                $result = $connect_db->query($sql);
                $i=0;
                $info = array();
                if($result->num_rows == 0){
                }
                else{
                        while($row = $result->fetch_assoc()){
                                $info[$i] = array();
                                $info[$i]['aaid'] = $row['aaid'];
                                $info[$i]['keyid'] = $row['keyid'];
                                $info[$i]['publickey'] = UAF_DB::base64url_decode($row['publickey']);
                                $info[$i]['authenticator_version'] = (int)$row['authenticator_version'];
                                $info[$i]['sign_counter'] = (int)$row['sign_counter'];
                                $i++;
                        }
                }
                return $info;
        }
		
		 public function update_sign_counter($connect_db,$user,$data){
                foreach($data as $value){
                        $sign_counter = $value['sign_counter'];
                        $aaid = $value['aaid'];
                        $keyid = $value['keyid'];
                        $sql = "UPDATE token_data SET sign_counter = '$sign_counter' WHERE username='$user' && aaid = '$aaid' && keyid = '$keyid'";
                        $connect_db->query($sql);
                }
        }



/******* request ********/
        public function store_request($connect_db,$username,$request,$type){
                $time = getdate();
                $sql = "INSERT INTO request_data (username,request,request_type,request_timestamp) values ('$username','$request','$type','$time[0]')";
                $connect_db->query($sql);
        }
        public function get_request($connect_db,$user,$type){
                $sql = "SELECT * FROM request_data WHERE username = '$user' && request_type = '$type'";
                $result = $connect_db->query($sql);
                if($result->num_rows == 0){
                }else{
                        $row = $result->fetch_assoc();
                }
                $now_time = getdate();
                /*if($now_time[0]-(int)$row['request_timestamp'] > 30){
                        return 'timeout';
                }*/
                return $row['request'];
        }


/********* metadata ***********/

		public function store_metadata_statement($connect_db,$metadata){
                if(!isset($metadata->aaid,$metadata->description,$metadata->authenticatorVersion,$metadata->upv,$metadata->assertionScheme,$metadata->authenticationAlgorithm,$metadata->publicKeyAlgAndEncoding,$metadata->attestationTypes,$metadata->userVerificationDetails,$metadata->keyProtection,$metadata->matcherProtection,$metadata->attachmentHint,$metadata->isSecondFactorOnly,$metadata->tcDisplay,$metadata->attestationRootCertificates,$metadata->icon)){
                        return false;
                }
                $png = null;
                $tc_type = null;
                if(isset($metadata->tcDisplayContentType)){
                        $tc_type = $metadata->tcDisplayContentType;
                }
                if(isset($metadata->tcDisplayPNGCharacteristics)){
                        $png = base64_encode(json_encode($metadata->tcDisplayPNGCharacteristics));
                }
                $upv = json_encode($metadata->upv);
                $attestationTypes = json_encode($metadata->attestationTypes);
                $userVerificationDetails = json_encode($metadata->userVerificationDetails);
                $CA = json_encode($metadata->attestationRootCertificates);
                $sql = "INSERT INTO metadata_statement (aaid,description,authenticatorVersion,upv,assertionScheme,authenticationAlgorithm,publicKeyAlgAndEncoding,attestationTypes,userVerificationDetails,keyProtection,matcherProtection,attachmentHint,isSecondFactorOnly,tcDisplay,tcDisplayContentType,tcDisplayPNGCharacteristics,attestationRootCertificates,icon)  VALUES('$metadata->aaid','$metadata->description','$metadata->authenticatorVersion','$upv','$metadata->assertionScheme','$metadata->authenticationAlgorithm','$metadata->publicKeyAlgAndEncoding','$attestationTypes','$userVerificationDetails','$metadata->keyProtection','$metadata->matcherProtection','$metadata->attachmentHint','$metadata->isSecondFactorOnly','$metadata->tcDisplay','$tc_type','$png','$CA','$metadata->icon')";
                $connect_db->query($sql);
                return true;
        }

        public function get_metadata_statement($connect_db,$aaid){
                $sql = "SELECT * FROM metadata_statement WHERE aaid = '$aaid'";
                $result = $connect_db->query($sql);
                $row = array();
                if($result->num_rows == 0){
                }
                else{
                        $row = $result->fetch_assoc();
                        $row['authenticatorVersion'] = (int)$row['authenticatorVersion'];
                        $row['upv'] = json_decode($row['upv']);
                        $row['authenticationAlgorithm'] = (int)$row['authenticationAlgorithm'];
                        $row['publicKeyAlgAndEncoding'] = (int)$row['publicKeyAlgAndEncoding'];
                        $row['attestationTypes'] = json_decode($row['attestationTypes']);
                        $row['keyProtection'] = (int)$row['keyProtection'];
                        $row['matcherProtection'] = (int)$row['matcherProtection'];
                        $row['attachmentHint'] = (int)$row['attachmentHint'];
                        $row['isSecondFactorOnly'] = (bool)$row['isSecondFactorOnly'];
                        $row['tcDisplay'] = (int)$row['tcDisplay'];
                        $row['userVerificationDetails'] = json_decode($row['userVerificationDetails']);
                        $row['tcDisplayPNGCharacteristics'] = json_decode($row['tcDisplayPNGCharacteristics']);
                        $row['attestationRootCertificates'] = json_decode($row['attestationRootCertificates']);
                }
                return $row;
        }
		
/********base64url encode decode***********/
        private static function base64url_encode($data) {
                return trim(strtr(base64_encode($data), '+/', '-_'), '=');
        }
        private static function base64url_decode($data) {
                return base64_decode(strtr($data, '-_', '+/'));
        }

/***** test ********/
        public function testing($connect_db){
                $user = 'aaaaa';
                $sql = "INSERT INTO metadata_statement (aaid) VALUES ('$user')";
                $connect_db->query($sql);
        }

}
?>