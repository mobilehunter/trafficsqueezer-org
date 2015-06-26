<table summary="toptitle" width="100%" style="font-family:arial;color:#3B3C3D;font-size:11px;" >
<tr>
<td ><img src="i/top_logo.png" alt="TrafficSqueezer" ></td>
<td align="right" >
<table cellpadding="5">
<tr><td><?php
session_start();
$username = $_SESSION['username'];
$hostname = $_SESSION['hostname'];
print "User: $username";
?></td><td>&nbsp;</td>
<td bgcolor="#D84430"><a href="c/c_logout.php" style="font-family:arial;color:white;font-size:11px;font-weight:bold;text-decoration:none;" >Logout</a></td>
</tr>
</table>


</td>
</tr>
</table>
