<?php
$mons = array(1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr", 5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug", 9 => "Sep", 10 => "Oct", 11 => "Nov", 12 => "Dec");
print "<table><tr>"; 
print "<td><select name=\"day\" style=\"font-family:arial;color:gray;font-size:11px;\">";
for($i=1;$i<=31;$i++) {
  if(date('d')==$i) $selected="selected"; else $selected="";
  print "<option value=\"$i\" $selected>$i</option>";
}
print "</select></td>";
print "<td><select name=\"month\" style=\"font-family:arial;color:gray;font-size:11px;\">";
for($i=1;$i<=12;$i++) {
  if(date('m')==$i) $selected="selected"; else $selected="";
  $mname = $mons[$i];
  print "<option value=\"$i\" $selected>$mname</option>";
}
print "</select></td>";
print "<td><select name=\"year\" style=\"font-family:arial;color:gray;font-size:11px;\">";
for($i=2013;$i<=2016;$i++) {
  if(date('Y')==$i) $selected="selected"; else $selected="";
  print "<option value=\"$i\" $selected>$i</option>";
}
print "</select></td>";
print "</tr></table>";
?>