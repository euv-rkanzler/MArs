<?php
// ====================
// Settings for MArs
// ====================

// ====================
// Include likely customized files
// ====================

require_once 'auth-ldap.php';
require_once 'mail.php';

// ====================
// Database settings
// ====================

define('DB_HOST', 'MyDbHost');
define('DB_NAME', 'MyDbName');
define('DB_TABLE', 'MyDbTable');
define('DB_USER', 'MyDbUser');
define('DB_PASS', 'MyDbPass');

// ====================
// LDAP settings
// ====================

define('LDAP_ADDRESS', 'ldap://localhost');
define('LDAP_BIND_USER', 'bind-user');
define('LDAP_BIND_PASSWORD', 'bind-password');
define('LDAP_PORT', '389');
define('LDAP_DOMAIN', 'company');
define('LDAP_DN', 'dc=company,dc=local');
define('LDAP_FILTER', "(&(objectCategory=person)(sAMAccountName=%s))");

// ====================
// Settings for seat booking.
// ====================

// Closing days for which bookings are disabled (e.g. weekend, public holidays).
define('CLOSED', [
    'Sat', 'Sun',
    '2020-05-31',
    '2020-06-01',
    '2020-06-11',
]);

// TODO: is this actually used anywhere?
// Delete bookings older than $MAX_AGE days.
define('MAX_AGE', 28);

// Allow bookings for the next MAX_DAYS days.
define('MAX_DAYS', 14);

// Allow bookings for current day until HH:MM
define('DAILY_DEADLINE', '10:00');

// Areas with longnames and seat limits per user membership and day
define('AREAS', [
    'area1' => [
        'name' => 'Area One',
        'limit' => [
            'member' => 80,
            'extern' => 20
        ],
    ],
    'area2' => [
        'name' => 'Area Two',
        'limit' => [
            'member' => 80,
            'extern' => 20
        ],
    ],
]);

// Maximum number of open bookings per user, depending on membership
define('PERSONAL_LIMIT', [
    'member' => 3,
    'extern' => 1,
]);

// Booking can be restricted to certain groups of users.
// E.g. you could use this array in auth.php to derive if a user is a member or not.
define('USERGROUPS', [
]);

// LDAP users with master permission.
define('USERADMIN', [
	'admin1',
	'admin2'
]);

// ====================
// Debug and test
// ====================

// If defined, MAGIC_PASSWORD is used as a master password in auth.php.
// The master password allows viewing and changing bookings of any user
// and can give access to additional functionality like reports.
define('MAGIC_PASSWORD', 'mysecretpassword');

// Enable test.
define('TEST', false);

// Enable debug output.
define('DEBUG', false);

// Test users.
define('TEST_USERS', [
    'testuser1',
    'testuser2',
    'testuser2',
]);

// User notified in the trace function.
// Useful for debugging live systems.
define('TRACE_USER', '');

// ====================
// Mail
// ====================

define('MAIL_TRANSPORT', 'sendmail'); // sendmail or smtp
define('SMTP_SERVER', 'localhost');
define('SMTP_PORT', 25);
define('SMTP_USER', 'smtp-user');
define('SMTP_PASSWORD', 'smtp-password');
define('FROM_MAIL', ['user@example.org' => 'Demo Sender']);
define('STAFF_TO_MAIL', 'staff@example.org');

// ====================
// Misc
// ====================

// Optional text displayed below booking form.
define('HINTS', "");

