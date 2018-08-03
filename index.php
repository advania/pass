<?php

ini_set('display_errors', 'On');
ini_set('error_reporting', '-1');

$allowed_password_creators = [
	'127.0.0.1',
	'::1'
];

header('Content-Type: text/html; charset=utf-8');
header('X-Accel-Buffering: no');
header('Cache-Control: no-cache, must-revalidate');
header('Access-Control-allow-origin: https://pass.meh.is/');
header('Access-Control-Allow-Methods: GET, POST');
header('Content-Security-Policy: default-src \'none\'; form-action \'self\'; frame-ancestors \'none\'; block-all-mixed-content; sandbox allow-forms; base-uri \'none\';');
header('Expect-CT: max-age=3600, enforce');
header('Expect-Staple: max-age3600; includeSubDomains;');
header('Referrer-Policy: no-referrer');
header('Strict-Transport-security: max-age=63072000; includeSubDomains; preload');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: deny');
header('X-XSS-Protection: 1; mode=block');

$uuid_regex = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/';

$dbh = new \PDO('pgsql:dbname=passwords user=password_frontend');
$dbh->exec('set session characteristics as transaction isolation level serializable');

if ($_SERVER['REQUEST_METHOD'] == 'POST')
{
	if (array_key_exists('id', $_POST) && preg_match($uuid_regex, $_POST['id']) === 1)
	{
		$get_data = $dbh->prepare('select * from get_password(:pass_id)');
		$get_data->bindParam(':pass_id', $_POST['id']);
		$get_data->execute();

		$pass = $get_data->fetchColumn();

		if (strlen($pass) === 0)
			die(sprintf("Requested password ID %s not found<br />\nMaybe someone took it before you did?<br>\n\n", $_POST['id']));
		else
			die(sprintf('Returned password:<br /><hr />%s', htmlspecialchars($pass)));
	}
	else if (array_key_exists('id', $_POST)) // failed the regex check
	{
		die(sprintf("Provided uuid %s not valid<br>\n\n", htmlspecialchars($_POST['id'])));
	}
	else if (array_key_exists('secret', $_POST))
	{
		if (in_array($_SERVER['REMOTE_ADDR'], $allowed_password_creators) === false)
			die('You are not authorized for creation of secrets in this system');

		// creating a secret, returning a uuid
		require('uuid.php');

		$insert_data = $dbh->prepare('select * from create_password(:pass_id, :pass_data)');

		while (true)
		{
			$dbh->beginTransaction();
			$uuid = gen_uuid(); // guaranteed to be pseudorandom, but duplicates can happen
			$insert_data->bindParam(':pass_id', $uuid);
			$insert_data->bindParam(':pass_data', $_POST['secret']);

			try
			{
				$insert_data->execute();
				printf("Send your user the link: <a href=\"/?id=%s\">https://pass.meh.is/?id=%s</a><br>\n", $uuid, $uuid);
			}
			catch (\PDOException $e)
			{
				$dbh->rollback();

				if ($e->errorInfo[0] === '40001') /* transaction serialization failure, retry */
					continue;

				throw $e;
			}

			$dbh->commit();
			die('Success!');
		}
	}
}
else if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['id']) && preg_match($uuid_regex, $_GET['id']) === 1)
{
	?>
	<h1>Get password</h1>
	<p>
		You are here using a password link, click the below button when you are sure
		you are ready to receive your super secret password.
	</p>
	<p>
		Please remember that we will only show it to you ONCE and never again, so if
		you click the below button and close this window, you will need to get a new
		password.
	</p>
	<form method="POST">
		<input type="hidden" name="id" value="<?php echo htmlspecialchars($_GET['id']); ?>">
		<input type="submit" value="I am ready, give me the password!">
	</form>
	<?php
	die();
}

// else show create form

?>

<h1>Send a password that a user can only open once</h1>
<p>
	You are here to create a password link from a password, just fill in the form
	and click when ready.
</p>
<form method="POST">
	<input type="password" name="secret" value="" autocomplete="off"><br>
	<input type="submit" value="Submit this password!">
</form>
