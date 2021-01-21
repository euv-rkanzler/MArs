<?php

// Gather user information from LDAP server
function get_user_info($uid) {
    global $ldap;
    $ldap = array();

    if ($connect = ldap_connect(LDAP_ADDRESS, LDAP_PORT)) {
        // Connection successful
        ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

        // Query account
        if ($bind = ldap_bind($connect, LDAP_DOMAIN . "\\" . LDAP_BIND_USER, LDAP_BIND_PASSWORD)) {
            $filter = sprintf(LDAP_FILTER, $uid);
            $search = ldap_search($connect, LDAP_DN, $filter);
            $ldap = ldap_get_entries($connect, $search);

            ldap_close($connect);

            // Map source info to MArs user
            $user = array();
            $user['id'] = $ldap[0]['samaccountname'][0];
            $user['mail'] = $ldap[0]['mail'][0];
            $user['surname'] = $ldap[0]['sn'][0];
            $user['givenname'] = $ldap[0]['givenname'][0];
            $user['is_member'] = in_array($ldap[0]['memberof'], USERGROUPS) ? true : false;

            return $user;
            
        } else {
            // Login failed ünknown LDAP bind user
            return false;
        }
    } else {
        // Connection error
        return false;
    }
}

// Get authorization from remote LDAP server.
function get_authorization($uid, $password) {
    global $user, $ldap;

    // Maybe check the uid for correct form here?
    // Adapt to your local needs!
    // if (!preg_match('/^[a-z_0-9]{0,8}$/', $uid) {
    //     return false;
    // }

    $authorized = false;
    $user = get_user_info($uid);
    if (!$user) {
        // user does not seem to exist in ldap
        return false;
    }

    $account_status = $ldap[0]['useraccountcontrol'][0];

    if ($account_status == 512) {
        if (defined('MAGIC_PASSWORD') && $password == MAGIC_PASSWORD) {
            return 'master';
        }

        if ($connect = ldap_connect(LDAP_ADDRESS, LDAP_PORT)) {
            // Connection successful
            ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

            // User authorization
            if ($bind = ldap_bind($connect, LDAP_DOMAIN . "\\" . $uid, $password)) {
                ldap_close($connect);
                $authorized = true;

                // Check if LDAP user has master permission
                foreach (USERADMIN as $admin) {
                    if ($uid == $admin) {
                        $authorized = 'master';
                    }
                }
            } else {
                // Login failed ünknown user
                return false;
            }
        } else {
            // Connection error
            return false;
        }
    }

    return $authorized;
}
