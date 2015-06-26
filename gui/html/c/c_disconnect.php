<html><body>
<div style="color: black;font-family:arial;font-size: 10px;">
<?php
    //start the session
    session_start();
    error_reporting(5);

    //check to make sure the session variable is registered
    if(isset($_SESSION['username']))
    {
           unset($_SESSION['access_device']);
           if($_GET['message']=='error')
           { error(); }
           else
           { print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=../index2.php\">"; }
    }
    else
    {
        session_unset();
        session_destroy();
        print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=../index.php\">";
    }
    
   	function error()
	{
		print "TrafficMaker Daemon is down or disconnected or may be the Daemon port is protected access by a Firewall.<br>Kindly debug the same and re-connect again ! <br><br>";
       	print "Redirecting...   <img src=\"../i/spinner_16.gif\" width=\"16\" height=\"16\" /><br>";
       	print "<meta HTTP-EQUIV=\"REFRESH\" content=\"5; url=../index2.php\">";
	}
?>
</div>
</body></html>