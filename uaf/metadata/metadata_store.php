<?php
require_once('acceptable_policy.php');
require_once('UAFDB_api.php');


function process_metadata($metadata){
        $metadata = json_decode(base64url_decode($metadata));
        if(match_acceptable_policy($metadata)==true){
                $DB = new UAF_DB("localhost","testuser","test","uaf_server");
                $conn = $DB->connect_to_database();
                //var_dump($metadata);
                if($DB->store_metadata_statement($conn,$metadata)){
                        echo $metadata->aaid.' stored success';
                }else{
                        echo $metadata->aaid.' stored fail';
                }
        }else{
                echo $metadata->aaid. ' policy not match';
        }
}

function create_version(){
                $version = array();
                $version["major"] = 1;
                $version["minor"] = 0;
                return $version;
}

function match_acceptable_policy($metadata){
        $acceptable_list = get_acceptable_policy();
        foreach($acceptable_list as $acceptable_set){
                $flag = true;
                foreach($acceptable_set as $acceptable){
                        if(match_acceptable($acceptable,$metadata)!==true){
                                $flag = false;
                                break;
                        }
                }
                if($flag){
                        return true;
                }
        }
        return false;
}

function match_acceptable($acceptable,$metadata){

        if(isset($acceptable->aaid)){
                $i = 0;
                foreach($acceptable->aaid as $aaid){
                        if($aaid == $metadata->aaid){
                                $i=1;
                                break;
                        }
                }
                if($i==0){
                        return false;
                }
        }
        if(isset($acceptable->vendorID)){
                $vendorID = substr($metadata->aaid,0,4);
                $i=0;
                foreach($acceptable->vendorID as $vendor){
                        if($vendor == $vendorID){
                                $i=1;
                                break;
                        }
                }
                if($i==0){
                        return false;
                }
        }
/*      if(isset($policy_criteria->userVerification)){
                $entry = count($metadata["user_verification"]);
                $verification = 0;
                if($entry == 1){
                        $tmp = count($metadata["user_verification"][0]);
                        if($tmp==1){
                                $verification = $metadata["user_verification"][0][0]->userVerification;
                        }else{
                                for($i=0;$i<$tmp;$i++){
                                        $verification = $verification + $metadata["user_verification"][0][$i]->userVerification;
                                }
                                        $verification = $verification + 1024;
                                }
                }else{
                        foreach($metadata["user_verification"] as $user_verification){
                                        if(count($user_verification)!=1){
                                                return "U";                                     
                                        }
                                $verification = $verification + $user_verification[0]->userVerification;
                        }
                }
                if($policy_criteria->userVerification != $verification){
                        return false;
                }
        }*/
        if(isset($acceptable->keyProtection)){
                if($acceptable->keyProtection != $metadata->keyProtection){
                        return false;
                }
        }
        if(isset($acceptable->matcherProtection)){
                if($acceptable->matcherProtection != $metadata->matcherProtection){
                        return false;
                }
        }
        if(isset($acceptable->attachmentHint)){
                if($acceptable->attachmentHint != $metadata->attachmentHint){
                        return false;
                }
        }
        if(isset($acceptable->tcDisplay)){
                if($acceptable->tcDisplay != $metadata->tcDisplay){
                        return false;
                }
        }
		if(isset($acceptable->authenticationAlgorithms)){
                $i=0;
                foreach($acceptable->authenticationAlgorithms as $auth_alg){
                        if($auth_alg == $metadata->authenticationAlgorithm){
                                $i=1;
                                break;
                        }
                }
                if($i==0){
                        return false;
                }
        }
        if(isset($acceptable->assertionSchemes)){
                $i=0;
                foreach($acceptable->assertionSchemes as $assertscheme){
                        if($assertscheme == $metadata->assertionScheme){
                                $i=1;
                                break;
                        }
                }
                if($i==0){
                        return false;
                }
        }
        if(isset($acceptable->attestationTypes)){
                $i=0;
                foreach($acceptable->attestationTypes as $attestation_type){
                        foreach($metadata->attestationTypes as $mata_attest){
                                if($attestation_type == $mata_attest){
                                        $i=1;
                                        break;
                                }
                        }
                        if($i==1){
                                break;
                        }
                }
                if($i==0){
                        return false;
                }
        }
		/*if(isset($policy_criteria->authenticatorVersion)){
                if($policy_criteria->authenticatorVersion != $token_info->authenticator_version){
                        return false;
                }
        }
        if(isset($policy_criteria->exts)){
                //?
        }*/
        return true;
}
?>