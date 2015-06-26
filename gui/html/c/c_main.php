<table style="font-family:arial;color:gray;font-size:12px;" align="center" border="0" cellpadding="0" cellspacing="0" height="0" width="1024px" bgcolor="#ffffff" >
<tr><td bgcolor="#ECF0F3" summary="logo" style="background: #f6f8f9;font-family:arial;color:white;font-size: 12px;">
<?php include('c_toptitle.php'); ?>

</td></tr>
<tr><td>
<table width="1152" border="0"  cellpadding="4" cellspacing="0" >
<tr>
<td width="156" summary="sidebar" style="background: #f6f8f9;"; valign="top" ><?php include('c_sidebar.php'); ?></td>

<?php
if($help=="nohelp")
{ print '<td width="864" summary="main content" valign="top"><br><b>'.$page_title.'</b><br><br>'; include($contentfile); print '</td>'; }
else 
{
	print '<td width="504" summary="main content" valign="top"><br><b>'.$page_title.'</b><br><br>'; include($contentfile); print '</td>';
	print '<td width="8" summary="margin/freespace" valign="top" bgcolor="#d4d4d4"></td>';
	print '<td width="346" style="font-family:arial;color:black;font-size:11px;" summary="helpbox" valign="top" bgcolor="#d4d4d4"><br>'; include($helpfile); print '</td>';
}
?>
</tr>
</table>
</td></tr>
</table>
<?php include('c/c_footer.php'); ?>
</body></html>