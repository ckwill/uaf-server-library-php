<?php
require_once('predefined_value.php');

class TLVparser {
        public function parse_tlv_data($assertion){
                $tlv = new stdClass();
                $data = TLVparser::base64url_decode($assertion);
                $tag = unpack("v*",substr($data,0,2))[1];
                switch ($tag){
                        case hexdec(TAG_UAFV1_REG_ASSERTION):
                                $tlv->UAFV1_REG = TLVparser::parse_tlv_with_little_edian(substr($data,2,2),substr($data,4));
                                break;
                        case hexdec(TAG_UAFV1_AUTH_ASSERTION):
                                $tlv->UAFV1_AUTH = TLVparser::parse_tlv_with_little_edian(substr($data,2,2),substr($data,4));
                                break;
                }
                return $tlv;
        }

        private function parse_tlv_with_little_edian($str_length,$data){
                $tlv_object = new stdClass();
                $str_length = unpack("v*",$str_length)[1];
                if($str_length!=strlen($data)){
                        return 'false';
                }
                while(strlen($data)){
                        $tag = unpack("v*",substr($data,0,2))[1];
                        $tag_length = unpack("v*",substr($data,2,2))[1];
                        switch ($tag){
                        case hexdec(TAG_UAFV1_SIGNED_DATA):
                                $signed_data = TLVparser::parse_object_little_edian(substr($data,4,$tag_length),'auth');
                                $tlv_object->signed_data = $signed_data;
                                $tlv_object->signed_msg = substr($data,0,$tag_length+4);
                                break;
                        case hexdec(TAG_UAFV1_KDR):
                                $kdr = TLVparser::parse_object_little_edian(substr($data,4,$tag_length),'reg');
                                $tlv_object->kdr = $kdr;
                                $tlv_object->signed_msg = substr($data,0,$tag_length+4);
                                break;
                        case hexdec(TAG_SIGNATURE):
                                $tlv_object->signature = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_ATTESTATION_BASIC_FULL):
                                $basic_full = TLVparser::parse_object_little_edian(substr($data,4,$tag_length),'full');
                                $tlv_object->attest_full = $basic_full;
                                break;
                        case hexdec(TAG_ATTESTATION_BASIC_SURROGATE):
                                $basic_surrogate = TLVparser::parse_object_little_edian(substr($data,4,$tag_length),'surrogate');
                                $tlv_object->attest_surrogate = $basic_surrogate;
                                break;
                        }
                        $data = substr($data,$tag_length+4);
                }
                return $tlv_object;
        }
		
		 private function parse_object_little_edian($data,$mode){
                $output_data = new stdClass();
                $attestation_counter = 0;
                while (strlen($data)>0){
                        $tag = unpack("v*",substr($data,0,2))[1];
                        $tag_length = unpack("v*",substr($data,2,2))[1];
                        switch ($tag){
                        case hexdec(TAG_AAID):
                                $output_data->aaid = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_ASSERTION_INFO):
                                $output_data->authenticator_version = unpack("v*",substr($data,4,2))[1];
                                $output_data->authentication_mode = bin2hex(substr($data,6,1));
                                $output_data->signaturealg_and_encoding = unpack("v*",substr($data,7,2))[1];
                                if($mode == 'reg'){
                                        $output_data->publickeyalg_and_encoding = unpack("v*",substr($data,9,2))[1];
                                }
                                break;
                        case hexdec(TAG_AUTHENTICATOR_NONCE):
                                $output_data->authenticator_nonce = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_FINAL_CHALLENGE):
                                $output_data->final_challenge = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_TRANSACTION_CONTENT_HASH):
                                $output_data->transaction_content_hash = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_KEYID):
                                $output_data->keyid = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_COUNTERS):
                                $output_data->sign_counter = unpack("V*",substr($data,4,4))[1];
                                if($mode == 'reg'){
                                        $output_data->reg_counter = unpack("v*",substr($data,8,4))[1];
                                }
                                break;
                        case hexdec(TAG_PUB_KEY):
                                $output_data->publickey = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_SIGNATURE):
                                $output_data->signature = substr($data,4,$tag_length);
                                break;
                        case hexdec(TAG_ATTESTATION_CERT):
                                $output_data->attestation_cert[$attestation_counter] = substr($data,4,$tag_length);
                                $attestation_counter++;
                                break;
                        }
                        $data = substr($data,$tag_length+4);
                }
                return $output_data;
        }

        private static function base64url_decode($data) {
                return base64_decode(strtr($data, '-_', '+/'));
        }
}

?>