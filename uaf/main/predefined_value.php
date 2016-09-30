<?php
define("USER_VERIFY_PASSCODE",4);
define("UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW",1);
define("ASSERTIONSCHEMES","UAFV1TLV");
define("TAG_UAFV1_REG_ASSERTION",'3e01');
define("TAG_UAFV1_AUTH_ASSERTION",'3e02');
define("TAG_UAFV1_KDR",'3e03');
define("TAG_UAFV1_SIGNED_DATA",'3e04');
define("TAG_ATTESTATION_CERT",'2e05');
define("TAG_SIGNATURE",'2e06');
define("TAG_ATTESTATION_BASIC_FULL",'3e07');
define("TAG_ATTESTATION_BASIC_SURROGATE",'3e08');
define("TAG_KEYID",'2e09');
define("TAG_FINAL_CHALLENGE",'2e0a');
define("TAG_AAID",'2e0b');
define("TAG_PUB_KEY",'2e0c');
define("TAG_COUNTERS",'2e0d');
define("TAG_ASSERTION_INFO",'2e0e');
define("TAG_AUTHENTICATOR_NONCE",'2e0f');
define("TAG_TRANSACTION_CONTENT_HASH",'2e10');
define("TAG_EXTENSION",'2e11');
define("TAG_EXTENSION_ID",'2e13');
define("TAG_EXTENSION_DATA",'2e14');
define("REG_COUNTER_ACCEPTABLE",1000);


function get_acceptable_policy(){
        $acceptable_policy_list = array();

        //first set of accepted policy
        $acceptable_policy_list[0] = array();
        $acceptable_policy_list[0][0] = new stdClass();
        $acceptable_policy_list[0][0]->authenticationAlgorithms = array(1);
        //$acceptable_policy_list[0][0]->keyProtection = 1;
        //$acceptable_policy_list[0][0]->matcherProtection = 1;
        //$acceptable_policy_list[0][0]->attachmentHint = 1;
        //$acceptable_policy_list[0][0]->assertionSchemes = array();
        $acceptable_policy_list[0][0]->assertionSchemes[0] = 'UAFV1TLV';
        //$acceptable_policy_list[0][0]->attestationTypes = array(15879);
        return $acceptable_policy_list;
}
function get_disallow_policy(){
        $disallow_policy_set = array();

        //first disallow policy
        $disallow_policy_set[0] = new stdClass();
        $disallow_policy_set[0]->keyProtection = 100;

        return $disallow_policy_set;
}

?>