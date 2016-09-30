<?php

function get_acceptable_policy(){
        $acceptable_policy_list = array();

        //first set of accepted policy
        $acceptable_policy_list[0] = array();
        $acceptable_policy_list[0][0] = new stdClass();
        $acceptable_policy_list[0][0]->authenticationAlgorithms = array(2);
        $acceptable_policy_list[0][0]->keyProtection = 1;
        $acceptable_policy_list[0][0]->matcherProtection = 1;
        $acceptable_policy_list[0][0]->attachmentHint = 1;
        $acceptable_policy_list[0][0]->assertionSchemes = array();
        $acceptable_policy_list[0][0]->assertionSchemes[0] = 'UAFV1TLV';
        $acceptable_policy_list[0][0]->attestationTypes = array(15879);

        $acceptable_policy_list[1] = array();
        $acceptable_policy_list[1][0] = new stdClass();
        $acceptable_policy_list[1][0]->authenticationAlgorithms = array(1);
        $acceptable_policy_list[1][0]->keyProtection = 1;
        $acceptable_policy_list[1][0]->matcherProtection = 1;
        $acceptable_policy_list[1][0]->attachmentHint = 1;
        $acceptable_policy_list[1][0]->assertionSchemes = array();
        $acceptable_policy_list[1][0]->assertionSchemes[0] = 'UAFV1TLV';
        $acceptable_policy_list[1][0]->attestationTypes = array(15879);



        return $acceptable_policy_list;
}
function get_disallow_policy(){
        $disallow_policy_set = array();

        return $disallow_policy_set;
}

?>