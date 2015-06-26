<?php error_reporting(5); session_start(); session_unset(); session_destroy(); ?>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<?php include('c/c_align.php'); ?>
<link rel="shortcut icon" type="image/x-icon" href="i/favicon.ico">
<?php
$color_light = "#8c9fff"; $color_lighter = "#8c9fff"; $color_dark = "#416182"; $language = "en";
print "<style>";  
print "input.style00 {width:210px;height:18px;background-color:$color_lighter;color:white;border:0;height:22px;font-weight:bold;}";
print "select.style01 {width:210px;height:18px;background-color:$color_lighter;color:white;border:0px;height:19px;padding:2px;}";
print "select.style01 option {background-color:$color_lighter;color:white;border:0px;margin: 0px 0px;padding: 0px;}";
print "</style>";
?>
</head><body style="background-color:#B3C2FF;">
<center>
<table border="0" align="center" width="600" bgcolor="white" cellpadding="5" cellspacing="5" >
<tr><td align="center"><img src="i/logo.png" alt="" ></td></tr>
<tr><td align="center" style="color:#111111;font-family:arial;font-size:16px;"><br>Admin Login<br>
<br><br><form method="POST" action="c/c_login.php">
<table summary="" align="center" >
<tr><td style="color:#111111;font-family:arial;font-size:14px;">Login: <input id="basic_font_style_14px_white" class="style00" type="text" name="username" ></td>
<td width="10" style="color:#111111;font-family:arial;font-size:14px;"> </td>
<td style="color:#111111;font-family:arial;font-size:14px;">Password: <input id="basic_font_style_14px_white" class="style00" type="password" name="password" ></td></tr>
</table>
<br><br>
<input type="submit" style="border: 0px solid #000000; background-color:#000000;width:100px;height:24px;color:white;font-family:arial;font-size:12px;" name="login" value="Login" />
</form></td></tr></table>
</center>
<?php include('c/c_footer.php'); ?>
</body></html>