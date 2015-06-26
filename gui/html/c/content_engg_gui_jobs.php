<style type="text/css">
table.grid_style {border-width:1px;border-spacing:2px;border-style:ridge;border-color:#B6B6B6;border-collapse:collapse;background-color:white;}
table.grid_style th {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:12px;}
table.grid_style td {border-width:1px;padding:1px;border-style:ridge;border-color:#B6B6B6;background-color:white;font-size:12px;}
#table_top_heading {background-color:gray;font-weight:bold;color:white;text-decoration:none;font-size:12px;}
</style>
<br><table class="grid_style" width="420">
<tr><td id="table_top_heading">&nbsp;&nbsp;ID</td><td id="table_top_heading">&nbsp;&nbsp;Job</td><td id="table_top_heading">&nbsp;&nbsp;Job Result</td></tr>
<?php include("c_db_access.php");
$query = "select id,job,job_result,job_pending from gui_jobs";
$result=mysql_query($query, $db);
if(mysql_num_rows($result) > 0)
{
  while($row = mysql_fetch_array($result))
  {
	 $id = $row['id'];
	 $job = $row['job'];
	 $job_result = $row['job_result'];
	 print "<tr bgcolor=$_light_orange>";
    print "<td >&nbsp;&nbsp;$id</td>";
    print "<td >$job</td>";
    print "<td >$job_result</td>";
    print "</tr>";
  }
}
?>
</table><br>
<form method="POST" action="engg_gui_jobs_bknd.php" ><input type="submit" name="submit_ok" value="Delete Jobs" style="border:0;background-color:#ff5c00;color:white;font-weight:bold;font-size:11px;" /></form>
