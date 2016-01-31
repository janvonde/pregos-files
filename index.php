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

error_reporting(-1);

session_start();

include "inc/config.inc.php";
include "inc/functions.inc.php";

createDatabaseIfNotExists();


// download file if password was given
if (isset($_POST['downloadfile']) && $_POST['downloadfile'] != "" && isset($_POST['password']) && $_POST['password'] != "") {
	if (checkPassword($_POST['downloadfile'],$_POST['password']) == TRUE) {
		downloadFile($_POST['downloadfile']);
		exit;
	}
	else {
		$_SESSION['message']['type'] = "danger";
		$_SESSION['message']['message'] = "The specified Password was wrong.";
		header('Location: ' . dirname(curPageUrl()) . "/" . $_POST['downloadfile']);
		exit;
	}
}


// delete old files and send expiration mails
if (isset($_GET['fileMaintenance']) && $_GET['fileMaintenance'] == "true") {
	fileMaintenance();
	exit;
}


$db = new PDO('sqlite:f2.sqlite');

// parse current URL
$parsedUrl = parse_url(curPageURL());

// split path by /
$boom = explode("/", $parsedUrl['path']);

// get filename and check for password
if ($boom[1] != '') {
	// get randname from array
	$randname = $boom[1];


	// get filename from database
	$stmt = $db->prepare("SELECT filename,password FROM files WHERE randname = :randname;");
	$stmt->bindValue(':randname', $randname);
	$stmt->execute();
	$result = $stmt->fetch();
	$filename = $result['filename'];


	// check if a password is needed...
	$password = "";
	if ($result['password'] != "") {
		$password = $result['password'];
	}


	// download if possible... ;-)
	if ($filename != "" && $password == "") {
		downloadFile($randname);
		exit;
	}
}

// error message if the requested file is unknown
if ($boom[1] != '' && $boom[1] != 'index.php' && $password == "") {
	$_SESSION['message']['type'] = "danger";
	$_SESSION['message']['message'] = "The file is not known or expired: '" . $boom[1];
}


header('Content-Type: text/html;charset=utf-8');
?>
<!DOCTYPE html>
<html>

<head>
  <title><?php echo projectName(); ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href='http://fonts.googleapis.com/css?family=Roboto+Condensed' rel='stylesheet' type='text/css'>
  <script src="//code.jquery.com/jquery-1.12.0.min.js"></script>
  <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha256-KXn5puMvxCw+dAYznun+drMdG1IFl3agK0p/pqT9KAo= sha512-2e8qq0ETcfWRI4HJBzQiA3UoyFk6tbNyG+qSaIBZLyW9Xf3sWZHN/lxe9fTh1U45DpPf07yj94KsUHHWe4Yk1A==" crossorigin="anonymous"></script>
  <link href="https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css" rel="stylesheet" integrity="sha256-Whc+9091keLVBxbyK4U697hqB4bcED+6LC64E9GuJkk= sha512-9PPlANXApnRCz1LMx2LPWwRfOKkWjQvH98q2lkxEG6/r6YVoQ+F48btbiuOpDsWHjpZrCfcGrPoVenVl69V09A==" crossorigin="anonymous">
  <link rel="shortcut icon" href="favicon.ico" type="image/x-icon"/>

  <style type="text/css">
    .alert-messages {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 10;
    }
  </style>
</head>

<body>

<nav class="navbar navbar-default">
  <div class="container-fluid">
    <div class="navbar-header">
      <button aria-expanded="false" type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbarId">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>      
      <a class="navbar-brand" href="/"><?php echo $_SERVER['HTTP_HOST']; ?></a>
    </div>
    <div aria-expanded="false" class="collapse navbar-collapse" id="navbarId">
      <ul class="nav navbar-nav navbar-right">
        <li><a href="upload.php">Login</a></li>
      </ul>
    </div>
  </div>
</nav>

<div class="container-fluid">
<div class="row">
  <div class="col-md-3"> </div>
    <div class="col-md-6">
<?php
// show error or success messages
if(isset($_SESSION['message']['type']) && $_SESSION['message']['type'] != "") {
        echo "    <div class=\"alert-messages\">";
	echo "      <div class=\"alert alert-" . $_SESSION['message']['type'] . "\">";
	echo "        <h4>";
	if ($_SESSION['message']['type'] == "danger") { echo "Error"; }
	if ($_SESSION['message']['type'] == "success") { echo "Success"; }
	echo "        </h4>";
	echo "        <p>" . $_SESSION['message']['message'] . "</p>"; 
	echo "      </div>";
	echo "    </div>";

	unset($_SESSION['message']['type']);
	unset($_SESSION['message']['message']);
}
?>
      <h1><?php echo projectName(); ?></h1>
      <div class="well">
<?php

// show password form if needed
if (isset($filename) && $password != "")  {
?>
	<form enctype="multipart/form-data" method="post" action="/index.php" name="form1" id="form1" class="form-horizontal" autocomplete="off">
          <input type="text" style="display:none" />
          <input type="password" style="display:none" />
          <input type="hidden" name="downloadfile" value="<?php echo $randname; ?>" />
            <fieldset>
              <legend>Password for <?php echo $filename; ?></legend>
              <div class="form-group">
                <label for="inputPassword" class="col-lg-4 control-label">Password</label>
                <div class="col-lg-8">
                  <input type="password" name="password" id="inputPassword" class="form-control" />
                </div>
              </div>
              <div class="form-group">
                <div class="col-lg-8 col-lg-offset-4">
                  <button type="submit" class="btn btn-primary" id="submit">Download</button>
                </div>
              </div>
            </fieldset>
          </form>
<?php
}


// show info text by default
else {
	echo projectDesc();
}
?>
      </div>
    </div>
    <div class="col-md-3"> </div>
  </div>
  </div>
</body>

</html>
