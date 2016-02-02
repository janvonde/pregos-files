<?php
/*
 * Copyright 2016 Jan Vonde
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



// return page URL
function curPageURL() {
        $pageURL = 'http';
        if (isset($_SERVER["HTTPS"]) && $_SERVER['HTTPS'] == "on") { $pageURL .= "s"; }
        $pageURL .= "://";
        if ($_SERVER["SERVER_PORT"] != "80") {
                $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];
        } else {
                $pageURL .= $_SERVER["SERVER_NAME"].$_SERVER["REQUEST_URI"];
        }
        return $pageURL;
}



// send email notification
function sendEmailNotification($file,$mailto) {

	include "config.inc.php";

	$to = $mailto;
        $subject = 'Download: ' . $file;
        $headers = "From: " . $conf['mailfrom'] . "\r\nReply-To: "  . $conf['mailreplyto'];
        $headers .= "\r\nMIME-Version: 1.0";
        $headers .= "\r\nContent-Type: text/plain; charset=UTF-8";
//        $headers .= "\r\nContent-Transfer-Encoding: quoted-printable";


        //define the body of the message.
        ob_start(); 


        echo "Folgender Download fand statt: $file\n\n";

        foreach($_GET as $key => $value){

		echo "\n";
                echo "    Datum:           " . date("d.M Y G:i:s") . "\n";
                echo "    IP-Adresse:      " . $_SERVER['HTTP_X_FORWARDED_FOR'] . "\n";
                echo "    Provider:        " . gethostbyaddr($_SERVER['HTTP_X_FORWARDED_FOR']) . "\n";
		echo "    Useragent:       " . $_SERVER['HTTP_USER_AGENT'] . "\n";
		if(isset($_SERVER['HTTP_REFERER']) AND $_SERVER['HTTP_REFERER'] != "") {
	                echo "    Referer:         " . $_SERVER['HTTP_REFERER'] . "\n";
		}
                echo "\n    Location:        http://www.infosniper.net/index.php?ip_address=" . $_SERVER['HTTP_X_FORWARDED_FOR'] . "\n\n";
        }


        //copy current buffer contents into $message variable and delete current output buffer
        $message = ob_get_clean();
        $mail_sent = @mail( $to, $subject, $message, $headers );
}



// download file...
function downloadFile($randname) {
	include "config.inc.php";

	$db = new PDO('sqlite:f2.sqlite');

	$stmt = $db->prepare("SELECT owner,filename FROM files WHERE randname = :randname;");
	$stmt->bindValue(':randname', $randname);
	$stmt->execute();
	$result = $stmt->fetch();
	$filename = $result['filename'];
	$owner = $result['owner'];

	$stmt = $db->prepare("SELECT email FROM user WHERE username = :username;");
	$stmt->bindValue(':username', $owner);
	$stmt->execute();
	$result = $stmt->fetch();
	$mailto = $result['email'];
	

        $path = $conf['datadir'] . "/" . $randname;

 	$mm_type = "application/octet-stream";
        header("Pragma: public");
        header("Expires: 0");
        header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
        header("Cache-Control: public");
        header("Content-Description: File Transfer");
        header("Content-Type: " . $mm_type);
        header("Content-Length: " .(string)(filesize($path)) );
        header('Content-Disposition: attachment; filename="'.$filename.'"');
        header("Content-Transfer-Encoding: binary\n");

	readfile($path);

	sendEmailNotification($filename,$mailto);
}



// check if given password is valid
function checkPassword($randname,$password) {
	$db = new PDO('sqlite:f2.sqlite');

	$stmt = $db->prepare("SELECT password FROM files WHERE randname = :randname;");
	$stmt->bindValue(':randname', $randname);
	$stmt->execute();
	$result = $stmt->fetch();
	$dbpass = $result['password'];

	if (password_verify($password, $dbpass)) {
		$return = TRUE;
	}
	else {
		$return = FALSE;
	}

	return $return;
}



// check if login data is valid
function checkLogin($username,$password) {
	$db = new PDO('sqlite:f2.sqlite');

	$stmt = $db->prepare("SELECT password FROM user WHERE username = :username;");
	$stmt->bindValue(':username', $username);
	$stmt->execute();
	$result = $stmt->fetch();
	$dbpass = $result['password'];

	if (password_verify($password, $dbpass)) {
		$return = TRUE;
	}
	else {
		$return = FALSE;
	}

	return $return;
}



// generate random name
function genRandName() {
	$validChars = "abcdefghijklmnopqrstuvwxyz1234567890";
	$name = "";

	for ($i = 0; $i < 20; $i++) {
		$name .= $validChars[mt_rand(0,35)];
	}

	return $name;
}



// check if new desired download name already exists
function checkRandName($randname) {

	// default value
	$return = TRUE;

	// get possible values from database
	$db = new PDO('sqlite:f2.sqlite');
	$stmt = $db->prepare("SELECT DISTINCT randname FROM files;");
	$stmt->execute();
	$result = $stmt->fetchAll();

	// check
	if ($result != "") {
		foreach ($result as $dbrn) {
			if ($dbrn['randname'] == $randname) {
				$return = FALSE;
			}
		}
	}
	return $return;
}



// do what the function is called
function createDatabaseIfNotExists()  {
	if (! is_file('f2.sqlite')) {
		$db = new PDO('sqlite:f2.sqlite');
		
		$db->exec("CREATE TABLE files ( id INTEGER PRIMARY KEY,
		                                      filename VARCHAR(255), 
		                                      randname VARCHAR(50),
		                                      password VARCHAR(255),
		                                      validuntil datetime,
		                                      owner VARCHAR(50));");
		
		$db->exec("CREATE TABLE user ( id INTEGER PRIMARY KEY,
		                                      username VARCHAR(50), 
						      password VARCHAR(255),
						      adminuser BOOLEAN NOT NULL DEFAULT 0,
						      email VARCHAR(100));");

		$password = genRandName();

		$db->exec("INSERT INTO user (username,password,adminuser,email) VALUES ('admin','" . password_hash($password, PASSWORD_BCRYPT) . "',1,'admin@example.com');");

		$_SESSION['message']['type'] = "success";
		$_SESSION['message']['message'] = "Die Datenbank wurde erfolgreich angelegt. Zugangsdaten sind: <ul> <li>User: admin</li><li>Pass: " . $password . "</li></ul><br/><a href=\"upload.php\">Backend</a>";
	}
}



// via http://stackoverflow.com/questions/5855811/how-to-validate-an-email-in-php
function isValidEmail($email) {
	return filter_var($email, FILTER_VALIDATE_EMAIL) && preg_match('/@.+\./', $email);
}



// check if username is uniq
function isUniqUsername($username) {

	// default value
	$return = TRUE;

	// get possible values from database
	$db = new PDO('sqlite:f2.sqlite');
	$stmt = $db->prepare("SELECT DISTINCT username FROM user;");
	$stmt->execute();
	$result = $stmt->fetchAll();

	// check
	if ($result != "") {
		foreach ($result as $dbuser) {
			if ($dbuser['username'] == $username) {
				$return = FALSE;
			}
		}
	}
	return $return;
}



// returns project name with default value
function projectName() {
	include "config.inc.php";

	if (isset($conf['name']) && $conf['name'] != "") {
		$return = $conf['name'];
	}
	else {
		$return = "pregos files";
	}
	return $return;
}



// returns project desc with default value
function projectDesc() {
	include "config.inc.php";

	if (isset($conf['desc']) && $conf['desc'] != "") {
		$return = $conf['desc'];
	}
	else {
		$return = "Share files for a limited time.";
	}
	return $return;
}



function fileMaintenance() {
	include "config.inc.php";

	// get files from database that are too old...
	$db = new PDO("sqlite:f2.sqlite");
	$stmt = $db->prepare("SELECT filename,randname,owner FROM files WHERE validuntil <= DATE('NOW');");
	$stmt->execute();
	$result = $stmt->fetchAll();


	// delete files
	if (!empty($result)) {
		foreach ($result as $file) {
			// delete actual file from filesystem
			unlink($conf['datadir'] . "/" . $file['randname']);


			// delete file entry from database
			$stmt = $db->prepare("DELETE FROM files WHERE randname = :randname;");
			$stmt->bindValue(':randname', $file['randname']);
			$stmt->execute();
		}
	}


	// get files from database that expire in 2 days...
	$db = new PDO("sqlite:f2.sqlite");
	$stmt = $db->prepare("SELECT filename,randname,validuntil,owner FROM files WHERE validuntil BETWEEN DATE('NOW') AND DATE('NOW', '+2 days');");
	$stmt->execute();
	$result = $stmt->fetchAll();


	// send email to owner with expiring information...	
	if (!empty($result)) {
		foreach ($result as $file) {
			$stmt = $db->prepare("SELECT email from user where username = :username;");
			$stmt->bindValue(':username', $file['owner']);
			$stmt->execute();
			$owner = $stmt->fetch();


			// send email notification	
			$to = $owner['email'];
		        $subject = 'File will expire: ' . $file['filename'];
		        $headers = "From: " . $conf['mailfrom'] . "\r\nReply-To: "  . $conf['mailreplyto'];
		        $headers .= "\r\nMIME-Version: 1.0";
		        $headers .= "\r\nContent-Type: text/plain; charset=UTF-8";
		        $headers .= "\r\nContent-Transfer-Encoding: quoted-printable";
		
		
		        //define the body of the message.
		        ob_start(); 
		
			echo "Cheers,\n\n";
			echo "the following file expired will expire soon and will be deleted:\n\n";
			echo "  * Filename:    " . $file['filename'] . "\n";
			echo "  * Expire date: " . $file['validuntil'] . "\n";
			echo "  * URL:         " . dirname(curPageUrl()) . "/" . $file['randname'] . "\n\n\n\n\n";
			echo "Have a nice day! :-) ";
		
		
		        //copy current buffer contents into $message variable and delete current output buffer
		        $message = ob_get_clean();
			$mail_sent = @mail( $to, $subject, $message, $headers );
		}
	}
}



function getFaIcon($filename) {

        // default value 
        $faIconClass = "fa-file-o";

        // file extension
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // mapping from extension to font-awesome icon class
        if ($ext == "php" OR $ext == "sh") {
                $faIconClass = "fa-file-code-o";
        }
        elseif ($ext == "mov" OR $ext == "mp4") {
                $faIconClass = "fa-file-video-o ";
        }
        elseif ($ext == "wav" OR $ext == "mp3") {
                $faIconClass = "fa-file-video-o ";
        }
        elseif ($ext == "rar" OR $ext == "zip") {
                $faIconClass = "fa-file-archive-o ";
        }
        elseif ($ext == "jpg" OR $ext == "jpeg" OR $ext == "png" OR $ext == "gif") {
                $faIconClass = "fa-file-image-o ";
        }
        elseif ($ext == "ppt" OR $ext == "pptx") {
                $faIconClass = "fa-file-powerpoint-o ";
        }
        elseif ($ext == "doc" OR $ext == "docx") {
                $faIconClass = "fa-file-word-o ";
        }
        elseif ($ext == "xls" OR $ext == "xlsx") {
                $faIconClass = "fa-file-excel-o ";
        }
        elseif ($ext == "txt" OR $ext == "xml") {
                $faIconClass = "fa-file-text-o ";
        }
        elseif ($ext == "pdf") {
                $faIconClass = "fa-file-pdf-o ";
        }

        // return value
        return $faIconClass;
}



// via http://php.net/manual/en/function.filesize.php
function human_filesize($bytes, $decimals = 2) {
	$sz = 'BKMGTP';
	$factor = floor((strlen($bytes) - 1) / 3);
	return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor];
}

?>
