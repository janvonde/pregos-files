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

// redirect to index.php if database doesn't exist as the info with username
// and password is only shown there
if (!is_file('f2.sqlite')) {
	header('Location: index.php');
}


// check login
// https://www.jonasjohn.de/snippets/php/auth.htm
$loginSuccessful = false;
if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])){
	$Username = $_SERVER['PHP_AUTH_USER'];
	$Password = $_SERVER['PHP_AUTH_PW'];
 
	if (checkLogin($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW']) == TRUE) {
		$loginSuccessful = true;
	}
}

if (!$loginSuccessful){
    header('WWW-Authenticate: Basic realm="' . projectName() . '" - Upload"');
    header('HTTP/1.0 401 Unauthorized');
 
    print "Login failed!\n";
}
else {


$db = new PDO('sqlite:f2.sqlite');



// if user is admin set flag....
$stmt = $db->prepare('SELECT adminuser FROM user WHERE username = :username;');
$stmt->bindValue(':username',$_SERVER['PHP_AUTH_USER']);
$stmt->execute();
$result = $stmt->fetch();

$iamadmin = 0;
if ($result['adminuser'] == 1) {
	$iamadmin = 1;
}




// check for various actions given on the upload page
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
	if (isset($_GET['deletefile'])) {
                // if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

                // give error message if the file that shall be deleted doesn't exist.
		if (! file_exists($conf['datadir'] . "/" . $_GET['deletefile'])) {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "The file you try to delete doesn't exist.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// everything is ok
		else {
			// get randname from $_GET
			$randname = $_GET['deletefile'];


			// get filename from database
			$stmt = $db->prepare("SELECT filename FROM files WHERE randname = :randname;");
			$stmt->bindValue(':randname', $randname);
			$stmt->execute();
			$result = $stmt->fetch();
			$filename = $result['filename'];


			// delete actual file from filesystem
			unlink($conf['datadir'] . "/" . $randname);


			// delete file entry from database
			$stmt = $db->prepare("DELETE FROM files WHERE randname = :randname;");
			$stmt->bindValue(':randname', $randname);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully deleted: '" . $filename;


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}


	if (isset($_GET['plusfile'])) {
                // if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// everything is ok
		else {
			// get randname from $_GET
			$randname = $_GET['plusfile'];


			// get validuntil from database
			$stmt = $db->prepare("SELECT filename,validuntil FROM files WHERE randname = :randname;");
			$stmt->bindValue(':randname', $randname);
			$stmt->execute();
			$result = $stmt->fetch();
			$validuntil = $result['validuntil'];
			$filename = $result['filename'];


			// calculate new valid until, hardcoded +30 days for the time beeing...
			if ($validuntil == 'unlimited') {
				$newvaliduntil = date("Y-m-d H:i:s", strtotime('+ 30 days'));
			}
			else {
				$newvaliduntil = date("Y-m-d H:i:s", strtotime(date("Y-m-d", strtotime($validuntil)) . '+ 30 days'));
			}
			

			// update database
			$stmt = $db->prepare("UPDATE files SET validuntil = :newvaliduntil WHERE randname = :randname;");
			$stmt->bindValue(':newvaliduntil', $newvaliduntil);
			$stmt->bindValue(':randname', $randname);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully extended the runtime of the file '" . $filename . "' plus 30 days.";


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}


	if (isset($_GET['unlimitedfile'])) {
                // if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// everything is ok
		else {
			// get randname from $_GET
			$randname = $_GET['unlimitedfile'];


			// get filename from database
			$stmt = $db->prepare("SELECT filename FROM files WHERE randname = :randname;");
			$stmt->bindValue(':randname', $randname);
			$stmt->execute();
			$result = $stmt->fetch();
			$filename = $result['filename'];


			// update database
			$stmt = $db->prepare("UPDATE files SET validuntil = 'unlimited' WHERE randname = :randname;");
			$stmt->bindValue(':randname', $randname);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully set the runtime of the file '" . $filename . "' to unlimited.";


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}


	if (isset($_GET['deleteuser'])) {
                // if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// everything is ok
		else {
			// get username from $_GET
			$username = $_GET['deleteuser'];


			// delete user from database
			$stmt = $db->prepare("DELETE FROM user WHERE username = :username;");
			$stmt->bindValue(':username', $username);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully deleted the user account: '" . $username;


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}


	if (isset($_GET['makeadminuser'])) {
                // if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// everything is ok
		else {
			// get username from $_GET
			$username = $_GET['makeadminuser'];


			// set admin flag in database
			$stmt = $db->prepare("UPDATE user SET adminuser = 1  WHERE username = :username;");
			$stmt->bindValue(':username', $username);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully granted admin rights to '" . $username;


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}


	if (isset($_GET['rmadminuser'])) {
                // if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// everything is ok
		else {
			// get username from $_GET
			$username = $_GET['rmadminuser'];


			// remove admin flag in database
			$stmt = $db->prepare("UPDATE user SET adminuser = 0  WHERE username = :username;");
			$stmt->bindValue(':username', $username);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully revoked admin rights from '" . $username;


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}
	if (isset($_GET['getUploadProgress'])) {
		$progress_name = ini_get("session.upload_progress.prefix")."fileUpload";
 
		if(isset($_SESSION[$progress_name])) {
			echo json_encode($_SESSION[$progress_name]);
		}
		exit;
	}
}


// check for POST in case of upload or new user
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	// only go on if uploadfile is set
	if (isset($_POST['uploadfile'])) {
		// if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// if something is empty send back
                if (!isset($_FILES['file']['name']) OR $_FILES['file']['name'] == "" OR !(isset($_POST['owner']))) {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "Please insert all mandatory information.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// TODO: CANCEL UPLOAD HERE
		if (isset($_POST[''])) {
			$key = ini_get("session.upload_progress.prefix")."fileUpload";
			$_SESSION[$key]["cancel_upload"] = TRUE;
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully canceled the file upload.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
		}


                // everything is ok
		else {
			// get name for url
			if (isset($_POST['ownname']) && $_POST['ownname'] != "") {
				// make sure only some chars are included if own name is given
				$randname =  preg_replace('/[^A-Za-z0-9\-]/', '', $_POST['ownname']);
			}
			else {
				// otherwise generate random string
				$randname = genRandName();
			}


			// check if chosen randname is uniq
			if (checkRandName($randname) == FALSE) {
				$_SESSION['message']['type'] = "danger";
				$_SESSION['message']['message'] = "The chosen or the random generated download name already exists.";
				header('Location: ' . basename($_SERVER['HTTP_REFERER']));
				exit;
			}


			// original filename
			$filename = $_FILES['file']['name'];


			// password if set
			$password = NULL;
			if (isset($_POST['password']) && !empty($_POST['password'])) {
				$password = password_hash($_POST['password'], PASSWORD_BCRYPT);
			}


			// owner
			$owner = $_POST['owner'];


			// valid until today + 30 days
			$validuntil = date("Y-m-d, H:i:s", strtotime('+30 days'));


                        // move file to datadir with .file extension
                        move_uploaded_file($_FILES['file']['tmp_name'], $conf['datadir'] . "/" . $randname);


			// only add to database if file exists in the filesystem
			if (is_file($conf['datadir'] . "/" . $randname)) {
	                        $stmt = $db->prepare("INSERT INTO files (id,filename,randname,password,validuntil,owner) VALUES (NULL, :filename, :randname, :password, :validuntil, :owner);");
				$stmt->bindValue(':filename', $filename);
				$stmt->bindValue(':randname', $randname);
				$stmt->bindValue(':password', $password);
				$stmt->bindValue(':validuntil', $validuntil);
				$stmt->bindValue(':owner', $owner);
				$stmt->execute();
	
	
				// user feedback
				$_SESSION['message']['type'] = "success";
				$_SESSION['message']['message'] = "Successfully uploaded file '" . $filename;
			}
			else {
				// user feedback
				$_SESSION['message']['type'] = "danger";
				$_SESSION['message']['message'] = "An error occcured during the upload of '" . $filename;
			}


			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}


	if (isset($_POST['newuser'])) {
		// if sending page is not upload.php send back
		if (basename($_SERVER['HTTP_REFERER']) != "upload.php") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "This action can not be requested from this site.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		// if something is empty send back
                if (!isset($_POST['username']) OR $_POST['username'] == "" OR !isset($_POST['password']) OR $_POST['password'] == "" OR !isset($_POST['email']) OR $_POST['email'] == "") {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "Please insert all mandatory information.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		if (! isValidEmail($_POST['email'])) {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "The given email address is not valid.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}

		if (! isUniqUsername($_POST['username'])) {
			$_SESSION['message']['type'] = "danger";
			$_SESSION['message']['message'] = "The username already exists.";
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}


                // everything is ok
		else {
			// data
			$username = $_POST['username'];
			$password = password_hash($_POST['password'], PASSWORD_BCRYPT);
			$email = $_POST['email'];


			// put info into database
                        $stmt = $db->prepare("INSERT INTO user (username,password,email) VALUES (:username, :password, :email);");
			$stmt->bindValue(':username', $username);
			$stmt->bindValue(':password', $password);
			$stmt->bindValue(':email', $email);
			$stmt->execute();


			// user feedback
			$_SESSION['message']['type'] = "success";
			$_SESSION['message']['message'] = "Successfully created user '" . $username;



			// send back to refering site
			header('Location: ' . basename($_SERVER['HTTP_REFERER']));
			exit;
		}
	}
}
else {



header('Content-Type: text/html;charset=utf-8');
?>
<!DOCTYPE html>
<html>

<head>
  <title><?php echo projectName(); ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href='//fonts.googleapis.com/css?family=Roboto+Condensed' rel='stylesheet' type='text/css'>
  <script src="//code.jquery.com/jquery-1.12.0.min.js"></script>
  <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha256-KXn5puMvxCw+dAYznun+drMdG1IFl3agK0p/pqT9KAo= sha512-2e8qq0ETcfWRI4HJBzQiA3UoyFk6tbNyG+qSaIBZLyW9Xf3sWZHN/lxe9fTh1U45DpPf07yj94KsUHHWe4Yk1A==" crossorigin="anonymous"></script>
  <link href="//maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css" rel="stylesheet" integrity="sha256-Whc+9091keLVBxbyK4U697hqB4bcED+6LC64E9GuJkk= sha512-9PPlANXApnRCz1LMx2LPWwRfOKkWjQvH98q2lkxEG6/r6YVoQ+F48btbiuOpDsWHjpZrCfcGrPoVenVl69V09A==" crossorigin="anonymous">
  <link href="//maxcdn.bootstrapcdn.com/font-awesome/4.5.0/css/font-awesome.min.css" rel="stylesheet" integrity="sha256-3dkvEK0WLHRJ7/Csr0BZjAWxERc5WH7bdeUya2aXxdU= sha512-+L4yy6FRcDGbXJ9mPG8MT/3UCDzwR9gPeyFNMCtInsol++5m3bk2bXWKdZjvybmohrAsn3Ua5x8gfLnbE1YkOg==" crossorigin="anonymous">
  <link rel="shortcut icon" href="favicon.ico" type="image/x-icon"/>

<style type="text/css">
.alert-messages {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 10;
}
.fa {
  padding-right: 5px;

}
</style>

</head>

<body>

<nav class="navbar navbar-default">
  <div class="container-fluid">
    <div class="navbar-header">
      <a class="navbar-brand" href="/"><?php echo $_SERVER['HTTP_HOST']; ?></a>
    </div>
    <!--ul class="nav navbar-nav navbar-right">
      <li><a href="upload.php?logout">Logout</a></li>
    </ul-->
  </div>
</nav>


<div class="container-fluid">
<div class="row">
  <div class="col-md-3"></div>
  <div class="col-md-6">

    <h1><?php echo projectName(); ?> Backend</h1>

<?php
// show error or success messages
if(isset($_SESSION['message']['type']) && $_SESSION['message']['type'] != "") {
        echo "    <div class=\"alert-messages\">";
	echo "      <div class=\"alert alert-dismissible alert-" . $_SESSION['message']['type'] . "\">";
	echo "        <button type=\"button\" class=\"close\" data-dismiss=\"alert\">&times;</button>";
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

    <!-- Nav tabs -->
    <ul class="nav nav-tabs" role="tablist">
      <li role="presentation" class="active"><a href="#home" aria-controls="home" role="tab" data-toggle="tab" style="outline: 0;">Home</a></li>
<?php
if ($iamadmin == 1) {
	echo "
		<li role=\"presentation\"><a href=\"#users\" aria-controls=\"users\" role=\"tab\" data-toggle=\"tab\" style=\"outline: 0;\">Users</a></li>\n
		<li role=\"presentation\"><a href=\"#files\" aria-controls=\"files\" role=\"tab\" data-toggle=\"tab\" style=\"outline: 0;\">Files</a></li>";
}
?>
      <li role="presentation"><a href="#info" aria-controls="info" role="tab" data-toggle="tab" style="outline: 0;">Info</a></li>
    </ul>

    <div class="tab-content">
    <div role="tabpanel" class="tab-pane active" style="border-left: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; padding: 10px;" id="home">
    <div class="panel panel-default">
      <div class="panel-heading">Upload</div>
        <div class="panel-body">
	  <form enctype="multipart/form-data" method="post" action="upload.php" name="form1" id="form1" class="form-horizontal" autocomplete="off">
            <input type="text" style="display:none" />
            <input type="password" style="display:none" />
            <input type="hidden" name="uploadfile" value="true" />
	    <input type="hidden" name="owner" value="<?php echo $_SERVER['PHP_AUTH_USER'];?>">
            <input type="hidden" name="<?php echo ini_get("session.upload_progress.name"); ?>" value="fileUpload">
            <fieldset>
              <div class="form-group">
                <label for="inputFile" class="col-lg-3 control-label">File</label>
                <div class="col-lg-9">
                  <input name="file" type="file" id="inputFile" />
                </div>
              </div>
              <div class="form-group">
                <label for="inputFilePassword" class="col-lg-3 control-label">Password <i class="fa fa-info-circle" data-toggle="tooltip" data-placement="top" title="Optional setting"></i></label>
                <div class="col-lg-9">
                  <input name="password" type="password" id="inputFilePassword" class="form-control" />
                </div>
              </div>
              <div class="form-group">
                <label for="inputOwnname" class="col-lg-3 control-label">Download name <i class="fa fa-info-circle" data-toggle="tooltip" data-placement="top" title="Optional setting"></i></label>
                <div class="col-lg-9">
                  <input name="ownname" type="text" id="inputOwnname" class="form-control"/>
                </div>
              </div>
              <div class="form-group">
                <div class="col-lg-3 col-lg-offset-3">
                  <!--button type="submit" class="btn btn-default" id="cancelfileupload">Abbrechen</button-->
                  <button type="submit" class="btn btn-primary" id="filesubmit" onClick="showProgressbar();">Upload</button>
                </div>
		<div class="col-lg-5 progressbarclass" style="display:none; margin-top:15px;">
                  <div class="progress progress-striped active">
                    <div class="progress-bar" style="width: 0%" id="bootbar"></div>
		  </div>
                </div>
		<div class="col-lg-1 progressbarclass" style="display:none; margin-top:10px;">
                  <p id="fortschritt_txt"></p>
                </div>
              </div>
            </fieldset>
	  </form>



        </div>
      </div>

<?php
$stmt = $db->prepare('SELECT filename,randname,validuntil,password FROM files WHERE owner = :owner ORDER BY validuntil;');
$stmt->bindValue(':owner',$_SERVER['PHP_AUTH_USER']);
$stmt->execute();
$result = $stmt->fetchAll();

if (!empty($result)) {
?>
      <div class="panel panel-default">
        <div class="panel-heading">My files</div>
        <div class="panel-body">
          <table class="table table-striped table-hover">
            <thead>
              <tr>
                <th>File</th>
                <th>Valid until</th>
                <th>&nbsp;</th>
              </tr>
            </thead>
            <tbody>

<?php
	foreach ($result as $file) {
		echo "
              <tr>
                <td> <a href=\"" . dirname(curPageUrl()) . "/" . $file['randname'] . "\" target=\"_blank\">" . $file['filename'] . "</a>";
	
	        if ($file['password'] != '') {
	                echo " &nbsp; <i class=\"fa fa-key\"> </i>";
	        }
	
		echo "</td>
                <td> ";
		  	  if ($file['validuntil'] == 'unlimited') { 
				echo 'unlimited'; 
			  } 
			  else { 
				echo date("Y-m-d", strtotime($file['validuntil']));
			  }
		echo " </td>
                <td style=\"text-align:right\">
                  <a href=\"?deletefile=" . $file['randname'] . "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Delete file\"><i class=\"fa fa-trash-o\"></i></a>
                  <a href=\"?plusfile=" . $file['randname'] . "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Extend plus 30 days\"><i class=\"fa fa-plus-circle\"></i></a>
                  <a href=\"?unlimitedfile=" . $file['randname'] . "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Keep file forever\"><i class=\"fa fa-bookmark-o\"></i></a>
                </td>
              </tr>";
	}
	echo "
            </tbody>
	  </table>
	</div>
      </div>";
}
?>
      </div>
<?php
// show user section only if admin flag is set

if ($iamadmin == 1) {

	$stmt = $db->prepare('SELECT username,email,adminuser FROM user ORDER BY username;');
	$stmt->execute();
	$result = $stmt->fetchAll();
	
	if (!empty($result)) {
?>
      <div role="tabpanel" class="tab-pane" style="border-left: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; padding: 10px;" id="users">
      <div class="panel panel-default">
        <div class="panel-heading">User</div>
        <div class="panel-body">
          <table class="table table-striped table-hover">
            <thead>
              <tr>
                <th>Username</th>
                <th class="hidden-xs">Email</th>
                <th>&nbsp;</th>
              </tr>
            </thead>
            <tbody>

<?php
		foreach ($result as $user) {
			echo "
              <tr>
                <td> " . $user['username'];
		
		        if ($user['adminuser'] == 1) {
		                echo " &nbsp; <i class=\"fa fa-user-secret\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Admin\"></i>";
		        }
		
			echo "</td>
                <td class=\"hidden-xs\"> " . $user['email'] . "</td>";
			echo "
                <td style=\"text-align:right\">";
	
			// An admin user shall not be able to delete itself
			if ($user['username'] != $_SERVER['PHP_AUTH_USER']) {
				echo "
                  <a href=\"?deleteuser=" . $user['username'] . "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Delete user\"><i class=\"fa fa-trash-o\"></i></a>";
			}
	
			// only show link to grant admin rights if user is no admin
			if ($user['adminuser'] == 0) {
				echo "
                  <a href=\"?makeadminuser=" . $user['username'] . "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Grant admin rights\"><i class=\"fa fa-graduation-cap\"></i></a>";
			}
	
			// only show link to remove admin rights if user _has_ admin rights and it's not the logged in user
			if ($user['adminuser'] == 1 && $user['username'] != $_SERVER['PHP_AUTH_USER']) {
				echo "
                  <a href=\"?rmadminuser=" . $user['username'] . "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Revoke admin rights\"><i class=\"fa fa-minus-circle\"></i></a>";
			}
			echo "
                </td>
              </tr>";
		}
		echo "
            </tbody>
          </table>
        </div>
      </div>";
}
?>

      <div class="panel panel-default">
        <div class="panel-heading">Add new user</div>
        <div class="panel-body">
          <form enctype="multipart/form-data" method="post" action="upload.php" name="form3" id="form3" class="form-horizontal" autocomplete="off">
            <input type="text" style="display:none" />
            <input type="password" style="display:none" />
            <input type="hidden" name="newuser" value="true" />
            <fieldset>
              <div class="form-group">
                <label for="inputUsername" class="col-lg-3 control-label">Username</label>
                <div class="col-lg-9">
                  <input type="text" name="username" id="inputUsername" class="form-control"/>
                </div>
              </div>
              <div class="form-group">
                <label for="inputUserPassword" class="col-lg-3 control-label">Password</label>
                <div class="col-lg-9">
                  <input type="password" name="password" id="inputUserPassword" class="form-control"/>
                </div>
              </div>
              <div class="form-group">
                <label for="inputEmail" class="col-lg-3 control-label">Email</label>
                <div class="col-lg-9">
                  <input type="text" name="email" id="inputEmail" class="form-control"/>
                </div>
              </div>
              <div class="form-group">
                <div class="col-lg-9 col-lg-offset-3">
                  <!--button type="reset" class="btn btn-default">Abbrechen</button-->
                  <button type="submit" class="btn btn-primary" id="usersubmit">Add</button>
                </div>
              </div>
            </fieldset>
          </form>
	</div>
      </div>
    </div>

<?php
}
if ($iamadmin == 1) {
$stmt = $db->prepare('SELECT filename,randname,validuntil,password,owner FROM files ORDER BY validuntil;');
$stmt->execute();
$result = $stmt->fetchAll();

if (!empty($result)) {
?>
      <div role="tabpanel" class="tab-pane" style="border-left: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; padding: 10px;" id="files">
      <div class="panel panel-default">
        <div class="panel-heading">All files</div>
        <div class="panel-body">
          <table class="table table-striped table-hover">
            <thead>
              <tr>
                <th>File</th>
                <th>Valid until</th>
                <th>Owner</th>
              </tr>
            </thead>
            <tbody>

<?php
	foreach ($result as $file) {
		echo "
              <tr>
                <td> <a href=\"" . dirname(curPageUrl()) . "/" . $file['randname'] . "\" target=\"_blank\">" . $file['filename'] . "</a>";
	
	        if ($file['password'] != '') {
	                echo " &nbsp; <i class=\"fa fa-key\"> </i>";
	        }
	
		echo "</td>
                <td> ";
		  	  if ($file['validuntil'] == 'unlimited') { 
				echo 'unlimited'; 
			  } 
			  else { 
				echo date("Y-m-d", strtotime($file['validuntil']));
			  }
                echo " </td>
                <td> " . $file['owner'] . "</td>
              </tr>";
	}
	echo "
            </tbody>
	  </table>
	</div>
	</div>
	</div>";
}
}
?>
    <div role="tabpanel" class="tab-pane" style="border-left: 1px solid #dddddd; border-right: 1px solid #dddddd; border-bottom: 1px solid #dddddd; padding: 10px;" id="info">
      <div class="panel panel-default">
        <div class="panel-heading">Info</div>
	<div class="panel-body">


<p>You can find the last source code on <a href="https://github.com/janvonde/pregos-files" target="_blank">Github</a></p>

<p>Some information about important php settings here:</p>
<ul>
<li>upload_max_filesize: <?php echo get_cfg_var("upload_max_filesize"); ?> </li>
<li>memory_limit: <?php echo get_cfg_var("memory_limit"); ?> </li>
<li>post_max_size: <?php echo get_cfg_var("post_max_size"); ?> </li>
<li>max_execution_time: <?php echo get_cfg_var("max_execution_time"); ?> </li>
</ul>

	</div>
      </div>
    </div>
    </div>
    <div class="col-md-3"></div>
  </div>
  </div>


  <!-- Bootstrap -->
  <script type="text/javascript">
    // Tooltips
    $(function () {
      $('[data-toggle="tooltip"]').tooltip()
    })

    // Hide alerts
    window.setTimeout(function() {
      $(".alert-success").fadeTo(500, 0).slideUp(500, function(){
        $(this).remove(); 
        $(".alert-remove").css('display', 'none');
      });
    }, 5000);


$('#myTabs a').click(function (e) {
  e.preventDefault()
  $(this).tab('show')
})


  </script>


  <!-- Progressbar -->
  <script type="text/javascript">
    var intervalID = 0;
  
    function showProgressbar() {
      $(".progressbarclass").css('display', 'block');
    }
  
  
    $(document).ready(function(e) {
      $('#form1').submit(function(e) {
   
        if($('#inputFile').val() == ''){
          e.preventDefault(); //Event abbrechen
          return false;
        }
   
        intervalID = setInterval(function() {
          $.getJSON('upload.php?getUploadProgress', function(data){
   
            if(data) {
              $('#fortschritt_txt').html(Math.round((data.bytes_processed / data.content_length)*100) + '%');
              document.getElementById('bootbar').style.width=(Math.round((data.bytes_processed / data.content_length)*100) + '%');
            }
          });
        }, 1000); //Zeitintervall auf 1s setzen
      });
    });
  </script>

</body>

</html>
<?php
// close else from login successfull
}

// close else from $_POSTt
}
?>
