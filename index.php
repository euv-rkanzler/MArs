<?php
/*
 * Seat booking for libraries
 *
 * (C) 2020 UB Mannheim
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Note: TODO comments mark missing and incomplete code.
 */

// Read configuration
$scriptdir = dirname(__FILE__);
$localdir = '/local';
$confdir = $scriptdir . $localdir;
if (!is_dir($confdir)) {
    $localdir = '/local-template';
    $confdir = $scriptdir . $localdir;
}
require_once "$confdir/config.php";

// Command line parameter for staff mail (e.g. via cron)
global $argv;
if ($argv[1] == "mail-staff") {
    send_staff_mail();
    exit;
}

function alert($text)
{
    print("<script>alert('$text');</script>");
}

function trace($text)
{
    global $uid;
    if ($uid == TRACE_USER) {
        alert($text);
    }
}

// Get parameter from web (GET, POST) or command line (environment).
function get_parameter($name, $default = '')
{
    $parameter = $default;
    if (isset($_REQUEST[$name])) {
        // Value from GET or POST (web).
        $parameter = $_REQUEST[$name];
    } elseif (isset($_SERVER[$name])) {
        // Value from environment (command line).
        $parameter = $_SERVER[$name];
    }
    return htmlspecialchars($parameter);
}

// Get handle for database access.
function get_database()
{
    $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($error = $db->connect_errno) {
        die("Failed to connect to database, $error\n");
    }
    return $db;
}

// Dump all bookings.
function dump_database()
{
    $db = get_database();
    $table = DB_TABLE;
    $result = $db->query("SELECT date,text,name FROM $table ORDER BY date,name");
    print("<table><tr><th>date</th><th>pl</th><th>uid</th></tr>");
    while ($reservation = $result->fetch_assoc()) {
        $date = $reservation['date'];
        $text = AREAS[$reservation['text']]['name'];
        $uid = $reservation['name'];
        print("<tr><td>$date</td><td>$text</td><td>$uid</td></tr>");
    }
    print("</table>");
    $result->free();
    $db->close();
}

function mail_database($user)
{
    global $url_tstamp;
    if (!function_exists('sendmail')) {
        return;
    }
    $db = get_database();
    $table = DB_TABLE;
    $result = $db->query("SELECT date,text FROM $table where name='" . $user['id'] . "' ORDER BY date");
    $mailtext = "";
    $today = date('Y-m-d', time());
    if ($url_tstamp) {
        $today = date('Y-m-d', $url_tstamp);
    }
    while ($reservation = $result->fetch_assoc()) {
        $date = $reservation['date'];
        if ($date < $today) {
            // Don't show old bookings.
            continue;
        }
        // Convert date representation.
        $date = date('d.m.Y', strtotime($date));
        // Translate short into long location name.
        $text = AREAS[$reservation['text']]['name'];
        $mailtext .= "$date $text\n";
    }
    $result->free();
    $db->close();
    sendmail($user, $mailtext);
}

// Drop existing table with all bookings and create a new empty one.
function init_database()
{
    $db = get_database();
    $table = DB_TABLE;
    $result = $db->query("DROP TABLE $table");
    $result = $db->query("CREATE TABLE `$table` (
        `id` INT NOT NULL AUTO_INCREMENT,
        `name` VARCHAR(16) NOT NULL,
        `member` BOOLEAN DEFAULT 1 NOT NULL,
        `text` VARCHAR(8) NOT NULL,
        `date` DATE NOT NULL,
        CONSTRAINT unique_reservation UNIQUE (date, name),
        PRIMARY KEY(`id`)
    )");
    $db->close();
}

// Add up to 10 random bookings for testing.
function preset_database()
{
    global $url_tstamp;
    $db = get_database();
    $table = DB_TABLE;
    $now = time();
    if ($url_tstamp) {
        $now = $url_tstamp;
    }
    for ($i = 0; $i < 10; $i++) {
        $uid = TEST_USERS[rand(0, count(TEST_USERS) - 1)];
        // TODO: Fixme. (What is meant to be fixed here?)
        $text = array_rand(AREAS);
        $date = date('Y-m-d', $now + 24 * 60 * 60 * rand(0 - MAX_AGE, 7));
        // TODO: Optionally update and insert external users, too.
        $result = $db->query("INSERT INTO $table (name, text, date) VALUES ('$uid','$text','$date')");
    }
    $db->close();
}

// Add, modify or delete bookings in the database.
function update_database($uid, $is_member, $date, $oldvalue, $value)
{
    global $url_tstamp;
    $db = get_database();
    $table = DB_TABLE;
    $comment = "";
    $no_reservation = 'no';
    $success_text = '<div class="row">
                        <div class="col s12">
                            <div class="card-panel light-green">
                                <span class="white-text">Aktion erfolgreich</span>
                            </div>
                        </div>
                    </div>';
    $failure_text = '<div class="row">
                        <div class="col s12">
                            <div class="card-panel pink lighten-1">
                                <span class="white-text">Aktion nicht erfolgreich</span>
                            </div>
                        </div>
                    </div>';
    if ($value == $no_reservation) {
        // Delete booking.
        $result = $db->query("DELETE FROM $table WHERE name='$uid' AND date='$date'");
        $success = $result ? $success_text : $failure_text;
        $comment = DEBUG ? "gelöscht: $oldvalue, $success" : $success;
    } else {
        // Limit bookings.
        $member = $is_member ? 1 : 0;
        $result = $db->query("SELECT COUNT(*) FROM $table WHERE date='$date' AND text='$value' AND member=$member");
        $count = $result ? $result->fetch_row()[0] : 0;
        $group = $is_member ? "member" : "extern";
        $limit = AREAS[$value]['limit'][$group];
        $today = date('Y-m-d', time());
        if ($url_tstamp) {
            $today = date('Y-m-d', $url_tstamp);
        }
        $result = $db->query("SELECT COUNT(*) FROM $table WHERE date>='$today' AND name='$uid'");
        $personal_bookings = $result ? $result->fetch_row()[0] : 999;
        if ($count >= $limit) {
            $comment ='<div class="row">
                            <div class="col s12">
                                <div class="card-panel pink lighten-1">
                                    <span class="white-text">Bibliotheksbereich ausgebucht</span>
                                </div>
                            </div>
                        </div>';
        } elseif ($oldvalue == $no_reservation) {
            // New bookings.
            if ($personal_bookings >= PERSONAL_LIMIT[$group]) {
                $comment = '<div class="row">
                                <div class="col s12">
                                    <div class="card-panel pink lighten-1">
                                        <span class="white-text">Persönliches Buchungslimit erreicht</span>
                                    </div>
                                </div>
                            </div>';
            } else {
                $result = $db->query("INSERT INTO $table (name, member, text, date) VALUES ('$uid',$member,'$value','$date')");
                $success = $result ? $success_text : $failure_text;
                $comment = DEBUG ? "reserviert: $value, $success" : $success;
            }
        } else {
            // Modified booking.
            if ($personal_bookings > PERSONAL_LIMIT[$group]) {
                $comment = '<div class="row">
                                <div class="col s12">
                                    <div class="card-panel pink lighten-1">
                                        <span class="white-text">Persönliches Buchungslimit erreicht</span>
                                    </div>
                                </div>
                            </div>';
            } else {
                $result = $db->query("DELETE FROM $table WHERE name='$uid' AND date='$date'");
                $result = $db->query("INSERT INTO $table (name, member, text, date) VALUES ('$uid',$member,'$value','$date')");
                $success = $result ? $success_text : $failure_text;
                $comment = DEBUG ? "aktualisiert: $oldvalue -> $value, $success" : $success;
            }
        }
    }
    $db->close();
    return $comment;
}

// Show stored bookings in a web form which allows modifications.
function show_database($uid, $lastuid, $is_member)
{
    global $url_tstamp, $user;
    $db = get_database();
    $table = DB_TABLE;
    $result = $db->query("SELECT date, text FROM $table WHERE name = '$uid' ORDER BY date");
    $reservations = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();
    //echo 'row=' . htmlentities($row);

    // Get current time.
    $now = time();
    if ($url_tstamp) {
        $now = $url_tstamp;
    }

    // First day which can be booked (time rounded to start of day).
    // Accept bookings for current day until HH:MM.
    $deadline    = explode(':', DAILY_DEADLINE);
    $deadminutes = ($deadline[0] * 60.0 + $deadline[1] * 1.0);
    // add (1 day - deadline) to now() and round to next or current day
    $start = $now + (((24 * 60) - $deadminutes) * 60);
    $start = strtotime(date('Y-m-d', $start));

    // Round current time to start of day.
    $now = strtotime(date('Y-m-d', $now));

    // Last day which may be booked (time rounded to start of day).
    $last = $now + 24 * 60 * 60 * MAX_DAYS;

    // First day which will be shown.
    $first = $now;

    print('<div class=\"z-depth-1 grey lighten-4 row\" style=\"display: inline-block; padding: 32px 48px 0px 48px; border: 1px solid #EEE;\">');

    // Get the first reserved day from the booking list.
    $i = 0;

    for ($time = $first; $time < $last; $time = strtotime("+1 day", $time)) {
        $disabled = '';
        $day = date('Y-m-d', $time);
        $text = 'no';
        if ($time < $start) {
            $disabled = ' disabled="disabled"';
        }

        $label = date('d.m.', $time);
        $label = "<label class=\"day\">$label</label>";

        $resday = '';
        while ($i < count($reservations) && ($resday = $reservations[$i]['date']) < $day) {
            $i++;
        }

        if ($i < count($reservations)) {
            $text = $reservations[$i]['text'];
        }
        if ($resday != $day) {
            $text = 'no';
        }

        // Skip days which cannot be booked.
        $weekday = date('D', $time);

        // Automated date formatting based on browsers locale
        $fmt = datefmt_create(locale::acceptFromHttp($_SERVER['HTTP_ACCEPT_LANGUAGE']), IntlDateFormatter::FULL, IntlDateFormatter::NONE, 'Europe/Berlin', IntlDateFormatter::GREGORIAN, 'EE dd.MM.');
        $weekday_formatted = datefmt_format($fmt, $time);

        $label = "<label class=\"col s3 black-text day\">$weekday_formatted</label>";
        $closed = false;
        foreach (CLOSED as $condition) {
            $closed = ($weekday == $condition || $day == $condition);
            if ($closed) {
                print("<div class=\"closed row\">$label geschlossen / closed</div>");
                break;
            }
        }
        if ($closed) {
            continue;
        }

        $name = "choice-$day";
        $requested = get_parameter($name, 'no');
        $comment = '';
        if ($time < $start) {
            $comment = DEBUG ? 'nicht änderbar' : '';
        } elseif ($uid != $lastuid) {
            // Initial call with the current user id.
            $comment = DEBUG ? 'änderbar' : '';
        } elseif ($text == $requested) {
            $comment = DEBUG ? 'unverändert' : '';
        } else {
            $comment = update_database($uid, $is_member, $day, $text, $requested);
            $text = $requested;
        }

        $line = '';
        foreach (AREAS as $area => $values) {
            // Get reservation count
            $member = $is_member ? 1 : 0;
            $result = $db->query("SELECT COUNT(*) FROM $table WHERE date='$day' AND text='$area' AND member=$member");
            $count = $result ? $result->fetch_row()[0] : 0;
            $result->free();
            $group = $is_member ? "member" : "extern";
            $limit = AREAS[$area]['limit'][$group];
            $remain = $limit - $count;
            $remain_color = ($remain == 0) ? " red" : " light-green";
            
            $id = "$area-$day";
            $checked = ($text == $area) ? ' checked' : '';
            $line .="<label class=\"col s9 offset-s3 m3 black-text\">
                        <input name=\"$name\" id=\"$id\" type=\"radio\" value=\"$area\"$checked$disabled />
                        <span>" . $values['name'] . "</span>
                        <span class='new badge $remain_color' data-badge-caption=''>$remain</span>
                    </label>"; 

        }
        $id = "no-$day";
        $checked = ($text == 'no') ? ' checked' : '';
        $line .= "<label class=\"col offset-s3 s9 m3 black-text\">
                    <input name=\"$name\" id=\"$id\" type=\"radio\" value=\"no\"$checked$disabled />
                    <span>Keine Buchung</span>
                </label>"; 

        if ($comment != '') {
            $comment = " $comment";
        }
        print("<div class=\"open row\">$label$line$comment</div>\n");
    }
    print('</div>');

    $today = date('Y-m-d', $now);
    $result = $db->query("SELECT COUNT(*) FROM $table WHERE date>='$today' AND name='$uid'");
    $personal_bookings = $result ? $result->fetch_row()[0] : 999;
    $db->close();
    $group = $user['is_member'] ? "member" : "extern";
    $open_bookings = PERSONAL_LIMIT[$group] - $personal_bookings;
    if ($open_bookings < 0) {
        $open_bookings = 0;
    }
    print("<p>Noch $open_bookings von " . PERSONAL_LIMIT[$group] . " Buchungen möglich.</p>");

}

// Daily report for a location.
function day_report($location = false)
{
    global $url_tstamp;
    $now = time();
    if ($url_tstamp) {
        $now = $url_tstamp;
    }
    $today = date('Y-m-d', $now);

    $db = get_database();
    $table = DB_TABLE;

    if (!$location) {
        // Summary of daily bookings per location.
        $result = $db->query("SELECT date, text, SUM(member) AS internal, SUM(NOT member) AS external FROM $table GROUP BY date, text");
        $reservations = $result->fetch_all(MYSQLI_ASSOC);
        $result->free();
        $db->close();

        print("<h2>MARS Buchungsübersicht</h2>\n");
        print("<table><tr><th>Datum</th><th>Bibliotheksbereich</th><th>Gesamt</th><th>Mitglieder</th><th>Externe</th></tr>");
        foreach ($reservations as $booking) {
            $date = $booking['date'];
            $location = $booking['text'];
            $count_ext = $booking['external'];
            $count_member = $booking['internal'];
            $count_total = $count_ext + $count_member;
            $longname = AREAS[$location]['name'];
            print("<tr><td>$date</td><td>$longname</td><td>$count_total</td><td>$count_member</td><td>$count_ext</td></tr>");
        }
        print("</table>");
        return;
    }

    $result = $db->query("SELECT date, member, text, name FROM $table WHERE date = '$today' AND text = '$location' ORDER BY date");
    $reservations = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();
    $db->close();

    $date = $today;
    $longname = AREAS[$location]['name'];
    print("<h2>MARS Tagesbericht $date $longname</h2>\n");
    print("<table><tr><th>Nr.</th><th>Datum</th><th>Bibliotheksbereich</th><th>Uni-ID</th><th>Name</th></tr>");

    $nr = 0;

    print("<tr><td>members</td></tr>");

    // Get all full names and sort them.
    $names = array();
    foreach ($reservations as $booking) {
        if (!$booking['member']) continue;
        $name = $booking['name'];
        $visitor = get_user_info($name);
        if (!$visitor) {
            // user does not seem to exist
            $fullname = "[Unbekannter Nutzer]";
        } else {
            $fullname = $visitor['surname'] . ", " . $visitor['givenname'];
        }
        $names[$fullname] = $name;
    }
    ksort($names);

    // Generate report.
    foreach ($names as $fullname => $name) {
        $nr++;
        print("<tr><td>$nr</td><td>$date</td><td>$longname</td><td>$name</td><td>$fullname</td></tr>");
    }

    print("<tr><td>external users</td></tr>");

    // Get all full names and sort them.
    $names = array();
    foreach ($reservations as $booking) {
        if ($booking['member']) continue;
        $name = $booking['name'];
        $visitor = get_user_info($name);
        if (!$visitor) {
            // user does not seem to exist
            $fullname = "[Unbekannter Nutzer]";
        } else {
            $fullname = $visitor['surname'] . ", " . $visitor['givenname'];
        }
        $names[$fullname] = $name;
    }
    ksort($names);

    // Generate report.
    foreach ($names as $fullname => $name) {
        $nr++;
        print("<tr><td>$nr</td><td>$date</td><td>$longname</td><td>$name</td><td>$fullname</td></tr>");
    }
    print("</pre>\n");
}

// Get form values from input (normally POST) if available.
$task = get_parameter('task');
// TODO: $email eventuell entfernen.
$email = get_parameter('email');
$uid = get_parameter('uid');
$lastuid = get_parameter('lastuid');
$password = get_parameter('password');

// Is there a username with valid password?
$authorized = false;

// Initiate user. User info is gathered in auth.php
global $user;
$user = array(
    'id' => '',
    'surname' => '',
    'givenname' => '',
    'gender' => '',
    'mail' => '',
    'is_member' => '',
    //'fullname' => '',
    //'usergroup' => '',
    //'groups' => array(),
);


?>
<!DOCTYPE html>
<html lang="de">
<head>
<title>UB Sitzplatzbuchung</title>
<!--Import Google Icon Font-->
<link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
<!--Import materialize.css-->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css">
<link rel="stylesheet" type="text/css" href="mars.css" media="all">
</head>
<body>
<br/>
<div class="container">
<div class="row center">
<form class="col s12" id="reservation" method="post">
<?php
if ($uid != '') {
    $authorized = get_authorization($uid, htmlspecialchars_decode($password));
}


// Should admin commands be allowed?
$master = ($authorized === 'master');

// Use fake timestamp for testing.
// strtotime understands different datetime formats, but use of ISO 8601 is recommended.
$url_tstamp;
if ($master) {
    $url_tstamp = strtotime(get_parameter('date'));
}


if ($master && $task == 'dump') {
    dump_database();
} elseif ($master && $task == 'init') {
    init_database();
    print('<pre>');
    dump_database();
    print('</pre>');
} elseif ($master && $task == 'phpinfo') {
    phpinfo();
} elseif ($master && $task == 'preset') {
    preset_database();
    print('<pre>');
    dump_database();
    print('</pre>');
} elseif ($master && preg_match('/-report$/', $task)) {
    $param = explode('-', $task);
    if (count($param) == 2) {
        $task_area = $param[0];
        if (array_key_exists($task_area, AREAS)) {
            day_report($task_area);
        } elseif ($task_area == "day") {
            day_report();
        }
    }
} elseif ($authorized) {
    // Show some information for the current uid.
    $usertext = $user['surname'] . ", " . $user['givenname'];
    if (TEST || $master) {
        foreach ($user as $key => $value) {
            $usertext .= "<br/>$key: $value";
        }
    }
    print("<p>$usertext</p>");
    print("<h3>Meine Sitzplatzbuchungen / My seat bookings</h3>");
    // Show all bookings.
    show_database($uid, $lastuid, $user['is_member']);
    if ($email != '') {
        // Send user bookings per e-mail.
        mail_database($user);
    }
} elseif ($uid != '') {
    if ($password == '') {
        print('<p>Bitte ergänzen Sie Ihre Anmeldedaten um Ihr Passwort.</p>');
    } else {
        print('<p>Die Anmeldedaten sind ungültig. Bitte prüfen Sie Uni-ID und Passwort.</p>');
    }
} 
//<button type="reset">Eingaben zurücksetzen</button>

    if ($authorized) {
        if ($task == '') {
?>
<button class="waves-effect waves-light btn submit" type="submit">Eingaben absenden</button>
<br/>
<label>
    <input type="checkbox" class="filled-in" name="email" id="email" checked="checked" <?=$email?>/>
    <span>Informieren Sie mich bitte per E-Mail über meine aktuellen Sitzplatzbuchungen. / Please inform me by e-mail about my current bookings.</span>
</label>
<?php 
        }
?>
<input id="uid" name="uid" type="hidden" value="<?=$uid?>"/>
<input id="lastuid" name="lastuid" type="hidden" value="<?=$authorized ? $uid : ''?>"/>
<input id="password" name="password" type="hidden" value="<?=$password?>"/>
<br/>
<div class='row'>
    <a class="waves-effect waves-light btn logout" href="./index.php">Abmelden / Logout<i class="material-icons right">logout</i></a>
</div>
<?php
    } else {
?>
        <div class="z-depth-1 grey lighten-4 row" style="display: inline-block; padding: 32px 48px 0px 48px; border: 1px solid #EEE;">
            <!-- <div class="row">
                <p>Benutzerdaten / personal data<p>
            </div> -->
            <div class='row'>
                <div class='input-field col s6'>
                    <input class="validate" id="uid" name="uid" data-length="10" type="text" required="required" value="<?=$uid?>"/>
                    <label for="uid">Uni-ID:*</label>
                </div>
                <div class='input-field col s6'>
                    <input id="lastuid" name="lastuid" type="hidden" value="<?=$authorized ? $uid : ''?>"/>
                    <input class="validate" id="password" name="password" required="required" type="password" value="<?=$password?>"/>
                    <label for="password">Passwort:*</label>
                </div>
            </div>  
            <div class="row">
                <button class="waves-effect waves-light btn submit col s6 offset-s3" type="submit">Anmelden<i class="material-icons right">login</i></button>
            </div>
        </div>
        <!-- <div class="row">
            <p>Die <a href="/datenschutzerklaerung/" target="_blank">Informationen zum Datenschutz</a> wurden mir zur Verfügung gestellt.<br/>
            The <a href="/en/privacy-policy/" target="_blank">privacy information</a> was provided to me.</p>
        </div> -->
<?php
    }
    if ($master) {
?>
<h3>Admin-Funktionen</h3>
<p>
<ul>
<li><a href="?task=dump" target="_blank">Alle Buchungen ausgeben</a>
<li><a href="?task=day-report" target="_blank">Buchungsübersicht</a>
<?php
foreach (AREAS as $key => $values) {
    print("<li><a href='?task=$key-report' target='_blank'>Tagesplanung " . $values['name'] . "</a>");
}
?>
</ul>
</p>
<?php
    }
?>
<?=HINTS?>
<?php

// Include JS
print('<script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>');

if (file_exists("$confdir/local.js")) {
    print("<script type='text/javascript' src='.$localdir/local.js'></script>");
}
?>
</form>
</div> <!-- row-center -->
</div> <!-- container -->
</body>
</html>
