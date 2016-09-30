<?php
require_once('predefined_value.php');
require_once('../metadata/UAFDB_api.php');
require_once('parse_tlv.php');
class UAF {
        public function construct_registration_request($already_reg,$username){
                $header = $this->create_header('registration','','','');
                $challenge = UAF::create_server_challenge();
                $policy = $this->create_policy($already_reg,'registration');
                $request = array();
                $request["header"] = $header;
                $request["challenge"] = $challenge;
                $request["username"] = $username;
                $request["policy"] = $policy;
                $registration_request = array();
                $registration_request[0] = $request;
                $registration_request_json = json_encode($registration_request);
                return $registration_request_json;
        }
        public function construct_authentication_request($already_reg,$mode){
                $header = $this->create_header('authentication','','','');
                $challenge = UAF::create_server_challenge();
                $policy = $this->create_policy($already_reg,$mode);
                $request = array();
                $request["header"] = $header;
                $request["challenge"] = $challenge;
                if($mode == 'transaction'){
                        //get paticipate aaid 
                        //maybe need DB for those aaid which is participated 
                        //set $request["transaction"];
                }
                $request["policy"] = $policy;
                $authentication_request = array();
                $authentication_request[0] = $request;
                $authentication_request_json = json_encode($authentication_request);
                return $authentication_request_json;
        }
        public function process_registration_response($response_object,$request_object){
                // return tuple (state , positive assertion[] )
                $return_tuple = array();
                $return_tuple['state'] = 0;
                $return_tuple['positive_assertion'] = null;
                if(UAF::verify_header_version($response_object->header->upv)===false){
                        $return_tuple['state'] = 1;
                        return $return_tuple;
                }
                // check mandatory field!!!(maybe need metadata or policy)
                /*if(isset($response_object->header->serverData)){
                        $serverdata_result = UAF::verify_serverdata($response_object->header->serverData,$request_objec
t->header->serverData);
                        if(!$serverdata_result){ var_dump('server data error!'); return 'error'; }
                }*/
                $fcp = json_decode(UAF::base64url_decode($response_object->fcParams));
                $tmp = UAF::verify_fcp($fcp,$request_object);
				if($tmp!==true){
                        switch ($tmp){
                                case 1 :
                                        $return_tuple['state'] = 2;
                                        return $return_tuple;
                                        break;
                                case 2 :
                                        $return_tuple['state'] = 3;
                                        return $return_tuple;
                                        break;
                                case 3 :
                                        $return_tuple['state'] = 4;
                                        return $return_tuple;
                                        break;
                                case 4 :
                                        $return_tuple['state'] = 5;
                                        return $return_tuple;
                                        break;
                                default :
                                        $return_tuple['state'] = 100;
                                        return $return_tuple;
                                        break;
                        }
                }

                $index = -1;
                $assertion_flag = true;
                $metadata_info = array();
                $assertion_info = array();
                $identity_tuple = array();
                $positive_assertion = array();
				
				foreach($response_object->assertions as $value){
                        $index = $index+1;
                        $identity_tuple[$index] = array();
                        $positive_assertion[$index] = array();
                        $positive_assertion[$index]['error'] = -1 ;

                        if($value->assertionScheme!='UAFV1TLV'){
                                $positive_assertion[$index]['error'] = 1;
                                $assertion_flag = false;
                                continue;
                        }
                        $assertion_info[$index] = TLVparser::parse_tlv_data($value->assertion);
                        if($assertion_info[$index]=='false'){
                                $positive_assertion[$index]['error'] = 2;
                                $assertion_flag = false;
                                continue;
                        }

                        if(!isset($assertion_info[$index]->UAFV1_REG)){
                                $positive_assertion[$index]['error'] = 3;
                                $assertion_flag = false;
                                continue;
                        }
                        if(key(get_object_vars($assertion_info[$index]->UAFV1_REG))!=='kdr'){
                                $positive_assertion[$index]['error'] = 4;
                                $assertion_flag = false;
                                continue;
                        }

                        $authenticator_aaid = $assertion_info[$index]->UAFV1_REG->kdr->aaid;
                        $authenticator_keyid = $assertion_info[$index]->UAFV1_REG->kdr->keyid;

                        $metadata_info[$index] = UAF_DB::get_metadata_statement(UAF_DB::connect_to_database(),$authenticator_aaid);
                        if($metadata_info[$index] == false){
                                $positive_assertion[$index]['error'] = 5;
                                $assertion_flag = false;
                                continue;
                        }

                /*      if(!UAF::is_metadata_match($assertion_info[$index]->UAFV1_REG,$metadata_info[$index],'reg')){
                                $positive_assertion[$index]['error'] = 6;
                                $assertion_flag = false;
                                continue;
                        }
                */
                        $identity_tuple[$index]['aaid'] = $authenticator_aaid;
                        $identity_tuple[$index]['keyid'] = UAF::base64url_encode($authenticator_keyid);

                }
				if($assertion_flag!==true){
                        $return_tuple['state'] = 7;
                        $return_tuple['positive_assertion'] = $positive_assertion;
                        return $return_tuple;
                }

                if(UAF::is_match_policy($request_object->policy,$identity_tuple,$metadata_info,$index+1)!==true){
                        $return_tuple['state'] = 6;
                        return $return_tuple;
                }
                $FCHash = hash('sha256',$response_object->fcParams,true);
                for($i=0;$i<$index+1;$i++){
                        $pubkey = UAF::get_pubkey_in_raw($assertion_info[$i]->UAFV1_REG);
                        $tmp = UAF::verify_kdr_object($assertion_info[$i]->UAFV1_REG,$metadata_info[$i],$pubkey,$FCHash);
                        if(is_array($tmp)!==true){
                                switch ($tmp){
                                case 1 :
                                        $positive_assertion[$i]['error'] = 7;
                                        break;
                                case 2 :
                                        $positive_assertion[$i]['error'] = 8;
                                        break;
                                case 3 :
                                        $positive_assertion[$i]['error'] = 9;
                                        break;
                                case 4 :
                                        $positive_assertion[$i]['error'] = 10;
                                        break;
                                case 5 :
                                        $positive_assertion[$i]['error'] = 11;
                                        break;
                                default :
                                        $positive_assertion[$i]['error'] = 100;
                                        break;
                                }
                                $return_tuple['state'] = 7;
                        }else{
                                $positive_assertion[$i]['error'] = 0;
                                $positive_assertion[$i]['publickey'] = UAF::base64url_encode($pubkey);
                                $positive_assertion[$i]['keyid'] = $identity_tuple[$i]['keyid'];
                                $positive_assertion[$i]['sign_counter'] = $assertion_info[$i]->UAFV1_REG->kdr->sign_counter;
                                $positive_assertion[$i]['aaid'] = $identity_tuple[$i]['aaid'];
                                $positive_assertion[$i]['authenticator_version'] = $assertion_info[$i]->UAFV1_REG->kdr->authenticator_version;
                                $positive_assertion[$i]['CA_chain'] = json_encode($tmp);
                        }
                }
                $return_tuple['positive_assertion'] = $positive_assertion;
                return $return_tuple;
        }
		
		public function process_authentication_response($response_object,$request_object,$user_token_info){

                $return_tuple = array();
                $return_tuple['state'] = 0;
                $return_tuple['positive_assertion'] = null;
                if(UAF::verify_header_version($response_object->header->upv)===false){
                        $return_tuple['state'] = 1;
                        return $return_tuple;
                }

                // check mandatory field!!!(maybe need metadata or policy)
                if(isset($response_object->header->serverData)){
                        $serverdata_result = UAF::verify_serverdata($response_object->header->serverData,$request_object->header->serverData);
                        if(!$serverdata_result){ var_dump('server data error!'); return 'error'; }
                }
                $fcp = json_decode(UAF::base64url_decode($response_object->fcParams));
                $tmp = UAF::verify_fcp($fcp,$request_object);
                if($tmp!==true){
                        switch ($tmp){
                                case 1 :
                                        $return_tuple['state'] = 2;
                                        return $return_tuple;
                                        break;
                                case 2 :
                                        $return_tuple['state'] = 3;
                                        return $return_tuple;
                                        break;
                                case 3 :
                                        $return_tuple['state'] = 4;
                                        return $return_tuple;
                                        break;
                                case 4 :
                                        $return_tuple['state'] = 5;
                                        return $return_tuple;
                                        break;
                                default :
                                        $return_tuple['state'] = 100;
                                        return $return_tuple;
                                        break;
                        }
                }

                $index = -1;
                $assertion_flag = true;
                $metadata_info = array();
                $assertion_info = array();
                $identity_tuple = array();
                $positive_assertion = array();
				
				foreach($response_object->assertions as $value){
                        $index = $index+1;
                        $identity_tuple[$index] = array();
                        $positive_assertion[$index] = array();
                        $positive_assertion[$index]['error'] = -1 ;

                        if($value->assertionScheme!='UAFV1TLV'){
                                $positive_assertion[$index]['error'] = 1;
                                $assertion_flag = false;
                                continue;
                        }
                        $assertion_info[$index] = TLVparser::parse_tlv_data($value->assertion);
                        if($assertion_info[$index]=='false'){
                                $positive_assertion[$index]['error'] = 2;
                                $assertion_flag = false;
                                continue;
                        }

                        if(!isset($assertion_info[$index]->UAFV1_AUTH)){
                                $positive_assertion[$index]['error'] = 12;
                                $assertion_flag = false;
                                continue;
                        }
                        if(key(get_object_vars($assertion_info[$index]->UAFV1_AUTH))!=='signed_data'){
                                $positive_assertion[$index]['error'] = 13;
                                $assertion_flag = false;
                                continue;
                        }

                        $authenticator_aaid = $assertion_info[$index]->UAFV1_AUTH->signed_data->aaid;
                        $authenticator_keyid = $assertion_info[$index]->UAFV1_AUTH->signed_data->keyid;

                        $metadata_info[$index] = UAF_DB::get_metadata_statement(UAF_DB::connect_to_database(),$authenticator_aaid);
                        if($metadata_info[$index] == false){
                                $positive_assertion[$index]['error'] = 5;
                                $assertion_flag = false;
                                continue;
                        }
                        if(!UAF::is_metadata_match($assertion_info[$index]->UAFV1_AUTH,$metadata_info[$index],'auth')){
                                $positive_assertion[$index]['error'] = 6;
                                $assertion_flag = false;
                                continue;
                        }

                        $identity_tuple[$index]['aaid'] = $authenticator_aaid;
                        $identity_tuple[$index]['keyid'] = UAF::base64url_encode($authenticator_keyid);
                }
                if($assertion_flag!==true){
                        $return_tuple['state'] = 7;
                        $return_tuple['positive_assertion'] = $positive_assertion;
                        return $return_tuple;
                }
				
				if(UAF::is_match_policy($request_object->policy,$identity_tuple,$metadata_info,$index+1)!==true){
                        $return_tuple['state'] = 6;
                        return $return_tuple;
                }

                $FCHash = hash('sha256',$response_object->fcParams,true);
                for($i=0;$i<$index+1;$i++){
                        $token_info = UAF::get_tokendata_info_by_aaid_keyid($identity_tuple[$i]['aaid'],$identity_tuple[$i]['keyid'],$user_token_info);
                        if(!$token_info){
                                $positive_assertion[$i]['error'] = 14;
                                $return_tuple['state'] = 7;
                                continue;
                        }
                        $tmp = UAF::verify_signed_data_object($assertion_info[$i]->UAFV1_AUTH,$metadata_info[$i],$token_info,$FCHash);
                        if($tmp!==true){
                                switch ($tmp){
                                case 1 :
                                        $positive_assertion[$i]['error'] = 7;
                                        break;
                                case 2 :
                                        $positive_assertion[$i]['error'] = 8;
                                        break;
                                case 3 :
                                        $positive_assertion[$i]['error'] = 15;
                                        break;
                                case 4 :
                                        break;
                                case 5 :
                                        $positive_assertion[$i]['error'] = 11;
                                        break;
                                default :
                                        $positive_assertion[$i]['error'] = 100;
                                        break;
                                }
                                $return_tuple['state'] = 7;
                        }else{
                                $positive_assertion[$i]['error'] = 0;
                                $positive_assertion[$i]['aaid'] = $identity_tuple[$i]['aaid'];
                                $positive_assertion[$i]['keyid'] = $identity_tuple[$i]['keyid'];
                                $positive_assertion[$i]['sign_counter'] = $assertion_info[$i]->UAFV1_AUTH->signed_data->sign_counter;
                        }
                }
                $return_tuple['positive_assertion'] = $positive_assertion;
                return $return_tuple;

        }
		
		function construct_deregistration_request($already_reg){
                $header = $this->create_header('deregistration','','','');
                $auths = array();
                foreach($already_reg as $value){
                        $auth = new stdClass();
                        $auth->aaid = $value['aaid'];
                        $auth->keyID = $value['keyid'];
                        array_push($auths,$auth);
                }

                $request = array();
                $request['header'] = $header;
                $request['authenticators'] = $auths;

                $deregistration_request = array();
                $deregistration_request[0] = $request;
                $deregistration_message = json_encode($deregistration_request);
                return $deregistration_message;
        }


        private function create_header($option,$appid,$serverdata,$exts){
                $header = new stdClass();
                $upv = UAF::create_version();
                switch ($option){
                case 'registration':
                        $op = 'Reg';
                        break;
                case 'authentication':
                        $op = 'Auth';
                        break;
                case 'deregistration':
                        $op = 'Dereg';
                        break;
                }
                $header->upv = $upv;
                $header->op = $op;
                //may have appID , serverData , extensions
                if($appid){
                        $header->appID = $appid;
                }
                if($serverdata){
                        $header->serverData = $serverdata;
                }
                if($exts){
                        $header->exts = $exts;
                }
                return $header;
        }
		
		
		private static function create_version(){
                $version = array();
                $version["major"] = 1;
                $version["minor"] = 0;
                return $version;
        }

        private static function create_server_challenge(){
                $random = openssl_random_pseudo_bytes(16);
                $challenge = UAF::base64url_encode($random);
                return $challenge;
        }

        private function create_policy($already_reg,$mode){
                if($mode == 'registration'){
                        $accepted = UAF::create_accepted_policy('','');
                        $disallowed = UAF::create_disallowed_policy($already_reg);
                }else{
                        $accepted = UAF::create_accepted_policy($already_reg,$mode);
                        $disallowed = UAF::create_disallowed_policy('');
                }
                $policy = new stdClass();
                $policy->accepted = $accepted;
                $policy->disallowed = $disallowed;
                //var_dump($policy);
                return $policy;
        }

        private function create_accepted_policy($already_reg,$mode){
                $accepted = array();
                $v = array();
                $i = 0;
                //var_dump($already_reg);
                if($mode == 'step_up'){
                        foreach($already_reg as $value){
                                $metadata_test = new stdClass();
                                $metadata_test->aaid = $value['aaid'];
                                $metadata_test->keyIDs = $value['keyid'];
                                $metadata_test->authenticatorVersion = $value['authenticator_version'];
                                $v[$i] = $metadata_test;
                                $i++;
                        }
                }else{
                        $accepted = get_acceptable_policy();
                }
                return $accepted;
        }
		
		private function create_disallowed_policy($already_reg){
                $disallowed = get_disallow_policy();
                $i = count($disallowed);
                // connect to db to get already registered (aaid,keyid) & disallowed it can use for loop to change value
                if($already_reg!=null){
                        foreach($already_reg as $value){
                                $metadata_test = new stdClass();
                                $metadata_test->aaid = $value['aaid'];
                                $metadata_test->keyIDs = $value['keyid'];
                                $disallowed[$i] = $metadata_test;
                                $i++;
                        }
                }
                return $disallowed;
        }

        private function verify_fcp($fcp,$request){
                if(isset($request->appID)){                             //not sure
                        if($fcp->appID!= $request->appID){
                                return 1;
                        }
                }

                if($fcp->challenge != $request->challenge){
                //      return 2;
                }

                //$fcp->channelBinding  return 3
                //$fcp->facetID is lists of trusted facetID return 4
                return true;
        }

        private static function verify_header_version($header_version){
                if($header_version->major!=1 || $header_version->minor!=0){
                        return false;
                }
                return true;
        }

        private function verify_serverdata($res_serverdata,$req_serverdata){
                if($res_serverdata!=$req_serverdata){
                        return false;
                }
                //maybe do something
                return true;
        }
		
		private function is_metadata_match($token_info,$metadata,$mode){
                if($mode == 'reg'){
                        if($token_info->kdr->publickeyalg_and_encoding != $metadata["publicKeyAlgAndEncoding"]){
                                return false;
                        }
                        foreach($metadata["attestationTypes"] as $value){
                                if($value == 15879 && isset($token_info->attest_full)){
                                        // need verify $metadata['attestationRootCertificates'];
                                        return true;
                                }
                                if($value == 15880 && isset($token_info->attest_surrogate)){
                                        // need verify itself
                                        return true;
                                }
                        }
                        return false;
                }
                if($mode == 'auth'){
                        if($token_info->signed_data->signaturealg_and_encoding != $metadata["authenticationAlgorithm"]){
                                return false;
                        }
                        return true;
                }
        }
		
		private function is_match_policy($policy,$identity_tuple,$metadata,$index){
                //if match disallowed policy
                foreach($policy->disallowed as $disallow){
                        for($i=0;$i<$index;$i++){
                                if(UAF::is_match_criteria($disallow,$identity_tuple[$i],$metadata[$i])===true){
                                        var_dump('match disallowed policy');
                                        break;
                                }
                        }
                }
                //if match accepted policy
                foreach($policy->accepted as $accepted){
                        if(count($accepted)!=$index){
                                continue;
                        }
                        $match_policy = false;
                        $tuple_tmp = $identity_tuple;
                        foreach($accepted as $value){
                                $match_criteria = false;
                                for($i=0;$i<$index;$i++){
                                        if(UAF::is_match_criteria($value,$tuple_tmp[$i],$metadata[$i])===true){
                                                $tuple_tmp[$i]['aaid'] = '';
                                                $match_criteria = true;
                                                break;
                                        }
                                }
                                if($match_criteria === false){
                                        $match_policy = false;
                                        break;
                                }
                                $match_policy = true;
                        }
                        if($match_policy === true){
                                return true;
                        }
                }
                return false;
        }
		
		private function is_match_criteria($policy_criteria,$identity_tuple_info,$metadata){
                if($identity_tuple_info['aaid'] === ''){
                        return false;
                }
                if(isset($policy_criteria->aaid)){
                        $i = 0;
                        foreach($policy_criteria->aaid as $aaid){
                                if($aaid == $identity_tuple_info['aaid']){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==0){
                                return false;
                        }
                }
                if(isset($policy_criteria->vendorID)){
                        $vendorID = substr($identity_tuple_info['aaid'],0,4);
                        $i=0;
                        foreach($policy_criteria->vendorID as $vendor){
                                if($vendor == $vendorID){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==0){
                                return false;
                        }
                }
                if(isset($policy_criteria->keyIDs)){
                        $i=0;
                        foreach($policy_criteria->keyIDs as $keyid){
                                if($keyid == $identity_tuple_info['keyid']){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==0){
                                return false;
                        }
                }
				if(isset($policy_criteria->userVerification)){
                        $entry = count($metadata["userVerificationDetails"]);
                        $verification = 0;
                        if($entry == 1){
                                $tmp = count($metadata["userVerificationDetails"][0]);
                                if($tmp==1){
                                        $verification = $metadata["userVerificationDetails"][0][0]->userVerification;
                                }else{
                                        for($i=0;$i<$tmp;$i++){
                                                $verification = $verification + $metadata["userVerificationDetails"][0][$i]->userVerification;
                                        }
                                        $verification = $verification + 1024;
                                }
                                }else{
                                foreach($metadata["userVerificationDetails"] as $user_verification){
                                        if(count($user_verification)!=1){
                                                return "U";
                                        }
                                        $verification = $verification + $user_verification[0]->userVerification;
                                }
                        }
                        if($policy_criteria->userVerification != $verification){
                                return false;
                        }
                }
                if(isset($policy_criteria->keyProtection)){
                        if($policy_criteria->keyProtection != $metadata["keyProtection"]){
                                return false;
                        }
                }
                if(isset($policy_criteria->matcherProtection)){
                        if($policy_criteria->matcherProtection != $metadata["matcherProtection"]){
                                return false;
                        }
                }
                if(isset($policy_criteria->attachmentHint)){
                        if($policy_criteria->attachmentHint != $metadata["attachmentHint"]){
                                return false;
                        }
                }
                if(isset($policy_criteria->tcDisplay)){
                        if($policy_criteria->tcDisplay != $metadata["tcDisplay"]){
                                return false;
                        }
                }
				if(isset($policy_criteria->authenticationAlgorithms)){
                        $i=0;
                        foreach($policy_criteria->authenticationAlgorithms as $auth_alg){
                                if($auth_alg == $metadata["authenticationAlgorithm"]){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==0){
                                return false;
                        }
                }
                if(isset($policy_criteria->assertionSchemes)){
                        $i=0;
                        foreach($policy_criteria->assertionSchemes as $assertscheme){
                                if($assertscheme == $metadata["assertionScheme"]){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==0){
                                return false;
                        }
                }
                if(isset($policy_criteria->attestationTypes)){
                        $i=0;
                        foreach($policy_criteria->attestationTypes as $attestation_type){
                                if($attestation_type == $metadata["attestationTypes"]){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==0){
                                return false;
                        }
                }
                if(isset($policy_criteria->authenticatorVersion)){
                        if($policy_criteria->authenticatorVersion != $token_info->authenticator_version){
                                return false;
                        }
                }
                if(isset($policy_criteria->exts)){
                        //?
                }
                return true;
        }
		
		private function get_tokendata_info_by_aaid_keyid($aaid,$keyid,$data){
                foreach ($data as $value){
                        if($value['aaid']==$aaid && $value['keyid'] == $keyid){
                                return $value;
                        }
                }
                return false;
        }

        private function get_pubkey_in_raw($reg_info){
                $publickey = $reg_info->kdr->publickey;
                if($reg_info->kdr->publickeyalg_and_encoding == 257){
                        $publickey = UAF::get_ec_public_key_raw($reg_info->kdr->publickey);
                }elseif($reg_info->kdr->publickeyalg_and_encoding == 259){
                        //$publickey = UAF::get_rsa_public_key_raw($reg_info->kdr->publickey);
                }
                return $publickey;
        }
		
		private function verify_kdr_object($reg_info,$metadata_info,$pubkey,$FCHash){

                //confirm attestation type

                if($reg_info->kdr->final_challenge!=$FCHash){
                        return 1;
                }
                if($metadata_info['authenticatorVersion'] > $reg_info->kdr->authenticator_version ){
                        return 2;
                }
                if($reg_info->kdr->reg_counter > REG_COUNTER_ACCEPTABLE){
                        return 3;
                }

                if(isset($reg_info->attest_full)){
                        if($reg_info->kdr->signaturealg_and_encoding == 1){
                                $signature = hex2bin(UAF::change_siganture_to_der_format($reg_info->attest_full->signature));
                        }elseif($reg_info->kdr->signaturealg_and_encoding == 2){
                                $signature = $reg_info->attest_full->signature;
                        }
                        $reg_cert = $reg_info->attest_full->attestation_cert;
                        //reg_cert has order 
                        //need metadata to get attestation root CA to verify this reg_cert chain 
                        //if(isset($metadata_info['attestationRootCertificates']){
                                //UAF::verify_attestation_root($reg_cert,$metadata_info['attestationRootCertificates']);
                        //}else{ return 4;}                     

                        $pemCert  = "-----BEGIN CERTIFICATE-----\r\n";
                        $pemCert .= chunk_split(base64_encode($reg_cert[0]), 64);
                        $pemCert .= "-----END CERTIFICATE-----";
                        if(!openssl_pkey_get_public($pemCert)) {
                                var_dump("register openssl get public error!!"); return 'false';
                        }
                        if(openssl_verify($reg_info->signed_msg,$signature, $pemCert,'sha256') !== 1) {
                                return 5;
                        }
                        $return_array = array();
                        $ind = 0;
                        foreach($reg_cert as $tmp){
                                $return_array[$ind] = base64_encode($tmp);
                        }
                        return $return_array;
				}elseif(isset($reg_info->attest_surrogate)){
                        //if(isset($metadata_info['attestationRootCertificates'])){
                        //      return 4;
                        //}

                        if($reg_info->kdr->signaturealg_and_encoding == 1){
                                $pemPubkey = UAF::public_key_to_pem($pubkey,'secp256r1');
                                $signature = hex2bin(UAF::change_siganture_to_der_format($reg_info->attest_full->signature));
                        }elseif($reg_info->kdr->signaturealg_and_encoding == 2){
                                $pemPubkey = UAF::public_key_to_pem($pubkey,'secp256r1');
                                $signature = $reg_info->attest_full->signature;
                        }

                        if(openssl_verify($reg_info->signed_msg,$signature, $pemPubkey,'sha256') !== 1) {
                                return 5;
                        }
                        $return_array = array();
                        $return_array[0] = 'surrogate';
                        return $return_array;

                }else{
                        var_dump('attest_another');
                }
        }
		
		private function verify_signed_data_object($signed_data_info,$metadata_info,$token_info,$FCHash){

                if($signed_data_info->signed_data->final_challenge != $FCHash){
                        return 1;
                }

                if($metadata_info['authenticatorVersion'] > $signed_data_info->signed_data->authenticator_version){
                        return 2;
                }
                if($signed_data_info->signed_data->sign_counter!=0 && $signed_data_info->signed_data->sign_counter <= $token_info['sign_counter']){
                        return 3;
                }

                if($signed_data_info->signed_data->authentication_mode == 2){
                        //transaction mode 
                }
                $sig = $signed_data_info->signature;
                $msg = $signed_data_info->signed_msg;
                switch ($metadata_info['authenticationAlgorithm']){
                        case 1:
                                $sig = hex2bin(UAF::change_siganture_to_der_format($sig));
                                $pemPubkey = UAF::public_key_to_pem($token_info['publickey'],'secp256r1');
                                $verify_result = openssl_verify($msg,$sig, $pemPubkey,'sha256');
                                break;
                        case 2:
                                $pemPubkey = UAF::public_key_to_pem($token_info['publickey'],'secp256r1');
                                $verify_result = openssl_verify($msg,$sig, $pemPubkey,'sha256');
                                break;
                        case 3:
                                break;
                        case 4:
                                break;
                        case 5:
                                break;
                        case 6:
                                break;
                }
                if($verify_result!==1){
                        return 5;
                }
                return true;
        }
		
		private function change_siganture_to_der_format($sig){
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
                return $out;
        }
		
		private static function get_ec_public_key_raw($subject_public_key_info){
                $i=0;
                while($i<strlen($subject_public_key_info)){
                        switch(substr($subject_public_key_info,$i,1)){
                                case "\x30":
                                        $i++;
                                        $length_info = substr($subject_public_key_info,$i,1);
                                        if($length_info!=="\x82"||$length_info!=="\x81"){
                                                $i++;}
                                        else if($length_info==="\x81"){
                                                $i+=2;}
                                        else{
                                                $i+=3;}
                                        break;
                                case "\x03":
                                        $i++;
                                        $length_info = substr($subject_public_key_info,$i,1);
                                        if($length_info!=="\x82"||$length_info!=="\x81"){
                                                $length = hexdec(bin2hex($length_info));
                                                $i++;
                                                $public_key = substr($subject_public_key_info,$i,$length);
                                                $i+=$length;
                                        }
                                        else if($length_info==="\x81"){
                                                $i++;
                                                $length = hexdec(bin2hex(substr($subject_public_key_info,$i,1)));
                                                $i++;
                                                $public_key = substr($subject_public_key_info,$i,$length);
                                                $i+=$length;
                                        }
                                        else{
                                                $i++;
                                                $length = hexdec(bin2hex(substr($subject_public_key_info,$i,2)));
                                                $i+=2;
                                                $public_key = substr($subject_public_key_info,$i,$length);
                                                $i+=$length;
                                        }
                                        break;

                                case "\x06":
                                        $i++;
                                        $length_info = substr($subject_public_key_info,$i,1);
                                        if($length_info!=="\x82"||$length_info!=="\x81"){
                                                $length = hexdec(bin2hex($length_info));
                                                $i = $i+$length+1;
                                        }
                                        else if($length_info==="\x81"){
                                                $i++;
                                                $length = hexdec(bin2hex(substr($subject_public_key_info,$i,1)));
                                                $i = $i+$length+1;
                                        }
                                        else{
                                                $i++;
                                                $length = hexdec(bin2hex(substr($subject_public_key_info,$i,2)));
                                                $i = $i+$length+2;
                                        }
                                        break;
                        }
                }
				if(substr($public_key,0,1)==="\x00"){
                        $public_key = substr($public_key,1);
                }
                return $public_key;
        }
		
		private function public_key_to_pem($user_public_key,$algorithm){

                /*
                          SEQUENCE( PublicKeyInfo: 2 elem)                                 30 59
                                SEQUENCE( AlgorithmIdentifier: 2 elem)                       30 13
                                        OID1.2.840.10045.2.1 (algorithm: id-ecPublicKey)                   06 07 2a 86 48 ce 3d 02 01
                                        OID1.2.840.10045.3.1.7 (parameters: secp256r1)                     06 08 2a 86 48 ce 3d 03 01 07
                                BIT STRING(PublicKey: 66 bytes)                                          03 42  ..key..
                
                                        OID1.3.132.0.10 (parameters : secp256k1)

                                        OID1.2.840.113549.1.1.1(algorithm:RSA) - no parameters       06 09 2A 86 48 86 F7 0D 01 01 01

                        see https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem    how to encode in pem 
                            https://msdn.microsoft.com/zh-tw/library/windows/desktop/bb540792(v=vs.85).aspx  DER Encoding of ASN.1 Types
                            https://www.yumpu.com/en/document/view/40517530/x509-certificate-and-crl-extensions-profile-for-piv-i-cards/11   
                            https://lapo.it/asn1js/ asn1 parser
                                
                */
                if($algorithm == 'secp256r1'){
                        $pubKey_DER =  "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
                        $pubKey_DER .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
                        $pubKey_DER .= "\0".$user_public_key;
                }elseif($algorithm == 'secp256k1'){

                }elseif($algorithm == 'rsa'){

                }elseif($algorithm == 'der'){
                        $pubKey_DER = $user_public_key;
                }

                $pubKey_pem  = "-----BEGIN PUBLIC KEY-----\r\n";
                $pubKey_pem .= chunk_split(base64_encode($pubKey_DER), 64);
                $pubKey_pem .= "-----END PUBLIC KEY-----";
                return $pubKey_pem;
        }




        private static function base64url_decode($data) {
                return base64_decode(strtr($data, '-_', '+/'));
        }

        private static function base64url_encode($data) {
                return trim(strtr(base64_encode($data), '+/', '-_'), '=');
        }
}

?>