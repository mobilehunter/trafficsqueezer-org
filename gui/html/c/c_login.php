<html><body><div style="font-family:arial;font-size: 10px;">
<?php
error_reporting(5);
include("c_db_access.php");
session_unset();
session_destroy();
$user = $_POST['username'];
$pass = $_POST['password'];
$_SESSION['host_name'] = "";
$_SESSION['previous_page'] = "";
$_SESSION['language'] = 'en';
$_SESSION['color_lighter'] = "#fcff3c";
$_SESSION['color_light'] = "#fcff3c";
$_SESSION['color_dark'] = "#fcff3c";

$query = "select username, password, language from profile where password='$pass' and username='$user'";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
     while($row = mysql_fetch_array($result))
     {
	    	session_start();
         $_SESSION = array();
         $_SESSION['username'] = $user;
	      $language = $row['language'];
	     	if($language!=NULL) $_SESSION['language'] = $language;
	     	$query2 = "select host_name from basic_config";
			$result2=mysql_query($query2, $db);
   		if(mysql_num_rows($result2) > 0)
   		{
      		while($row2 = mysql_fetch_array($result2))
      		{
  					$_SESSION['host_name'] = $row2['host_name'];
  				}
  			}
     		print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=../home.php\">";
     }
}
else
{
   print "Incorrect login name or password.<br><br>";
   print "Redirecting... &nbsp;  <img src=\"../i/ajax_loader_small2.gif\" /><br>";
   print "<meta HTTP-EQUIV=\"REFRESH\" content=\"3; url=../index.php\">";
}
mysql_close($db);
?>
</div></body></html>