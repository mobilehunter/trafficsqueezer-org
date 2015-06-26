<?php
function status_box($left, $top, $color)
{
	if($color=="green") $color="#00D400";
	else if($color=="red") $color="#FF6060";
	print "<div style=\"position:absolute;left:".$left.";top:".$top.";border:0;background-color:".$color.";width:12px;height:12px;\" ></div>";
}

function status_box_var($var, $left, $top)
{
	if($var=="1") $color="#00D400"; else $color="#FF6060";
	print "<div style=\"position:absolute;left:".$left.";top:".$top.";border:0;background-color:".$color.";width:12px;height:12px;\" ></div>";
}

function status_box_var_without_pos($var)
{
	if($var=="1") $color="#00D400"; else $color="#FF6060";
	print "<span style=\"border:0;background-color:".$color.";width:12px;height:12px;\" >&nbsp;&nbsp;&nbsp;&nbsp;</span>";
}
?>
