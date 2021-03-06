<?php

// Mail implementation using Swift Mailer.
// See documentation: https://swiftmailer.symfony.com/docs/introduction.html
require_once __DIR__ . '/../vendor/autoload.php';

function sendmail($user, $text) {

    $to = $user['mail'];
    if ($to == '') {
        alert("Keine E-Mail-Adresse für " . $user['id'] . " gefunden");
        return;
    }

    $text = "Sehr geehrte/r " . $user['givenname'] . " " . $user['surname'] . ",\n\n" . $text;
    $text = "Diese Reservierungen sind für die Benutzerkennung " . $user['id'] . " vorgemerkt:\n\nDatum      Bibliotheksbereich\n" . $text;

    // Sendmail for transport.
    if (MAIL_TRANSPORT == 'sendmail') {
        $transport = new Swift_SendmailTransport('/usr/sbin/sendmail -bs');
    }

    // SMTP for transport.
    if (MAIL_TRANSPORT == 'smtp') {
        $transport = (new Swift_SmtpTransport(SMTP_SERVER, SMTP_PORT))
            ->setUsername(SMTP_USER)
            ->setPassword(SMTP_PASSWORD);
    }

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    // Create a message
    $message = (new Swift_Message('Sitzplatzreservierung'))
        ->setFrom(FROM_MAIL)
        ->setTo($to)
        ->setBody($text)
    ;

    // Send the message
    $result = $mailer->send($message);
}

function send_staff_mail() {
    $today = date('Y-m-d');
    $db = get_database();
    $table = DB_TABLE;

    $transport = new Swift_SendmailTransport('/usr/sbin/sendmail -bs');
    $mailer = new Swift_Mailer($transport);

    $subject = "Reservierungen für $today";
    $text = "Sehr geehrte Damen und Herren,\n\n";
    $text .= "anbei finden Sie die heutigen Sitzplatzreservierungen.\n\n";
    $text .= "Mit freundlichen Grüßen,\nIhre Universitätsbibliothek";

    $message = (new Swift_Message($subject))
        ->setFrom(FROM_MAIL)
        ->setTo(STAFF_TO_MAIL)
        ->setBody($text)
    ;

    foreach (AREAS as $location => $values) {
        $longname = $values['name'];
        $result = $db->query("SELECT name FROM $table WHERE date = '$today' AND text = '$location'");
        $reservations = $result->fetch_all();
        $result->free();
        $report = "Tagesliste für $longname am $today\n\n";

        if (count($reservations) > 0) {
            $names = array();
            foreach ($reservations as $row) {
                $visitor = get_user_info($row[0]);
                if (!$visitor) {
                    // ldap does not know this uid anymore
                    $fullname = "[Unknown user]";
                } else {
                    $fullname = $visitor['surname'] . ", " . $visitor['givenname'];
                }
                $names[] = $fullname;
            }
            sort($names);
            foreach ($names as $nr => $name) {
                $report .= ++$nr . " - " . $name . "\n";
            }
        } else {
            $report .= "Keine Buchungen vorhanden.\n";
        }

        $message->attach(
            Swift_Attachment::newInstance($report, "$today\_$location.txt", "plain/text")
        );
    }
    $db->close();
    $result = $mailer->send($message);
}
