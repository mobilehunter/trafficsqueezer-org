<style type="text/css">
root {display: block;}
#hr_style {height:1px;border-width:0;color:#333333;background-color:gray;}
#main_title {position:absolute;top: 90;left: 160;font-family:verdana;font-size: 16px;font-weight:bold;}
#link_style {color:white;font-family:arial;font-size: 10px;text-decoration: none;}
#link_style_black {color:black;font-family:"arial";font-size: 10px;}
#basic_description {position:absolute;top: 130;left:160;font-family:verdana;color: black;background-color: Wheat;font-size: 10px;width: 780;}
#basic_description_large{position:absolute;top: 130;left: 160;font-family:"verdana";color: black;background-color: Wheat;font-size: 10px;width: 820;}
#users_table {position:absolute;top: 190;left: 170;font-family:"verdana";color: black;font-size: 10px;}
#alert_table {position:absolute;top: 200;left: 200;font-family:"verdana";color: black;font-size: 10px;width: 540;}
#customer_table {position:absolute;top:1;left:4;font-family:arial;color:white;font-size: 10px;width: 900;opacity: 0.86;}
#basic_font_style {color:black;font-family:arial;font-size: 9px;}
#basic_font_style_white {color:white;font-family:arial;font-size: 9px;}
#basic_font_style_6px {color:black;font-family:arial;font-size: 6px;}
#basic_font_style_7px {color:black;font-family:arial;font-size: 7px;}
#basic_font_style_8px {color:black;font-family:arial;font-size: 8px;}
#basic_font_style_8px_white {color: hite;font-family:arial;font-size: 8px;}
#basic_font_style_9px {color:black;font-family:arial;font-size: 9px;}
#basic_font_style_9px_white {color:white;font-family:arial;font-size: 9px;}
#basic_font_style_10px {color:black;font-family:arial;font-size: 10px;}
#basic_font_style_10px_white {color: white;font-family:arial;font-size: 10px;}
#basic_font_style_11px_white {color: white;font-family:arial;font-size: 11px;}
#basic_font_style_10px_gray {color: gray;font-family:arial;font-size: 10px;}
#basic_font_style_12px {color: black;font-family:arial;font-size: 12px;}
#basic_font_style_12px_white {color: white;font-family:arial;font-size: 12px;}
#basic_font_style_12px_gray {color:gray;font-family:arial;font-size: 12px;}
#basic_font_style_14px{color:black;font-family:arial;font-size: 14px;}
#basic_font_style_14px_white {color: white;font-family:arial;font-size: 14px;}
#content {margin: 0 10em;font-family:verdana;}
#logout_option {position: absolute;width:390px;top: 94;left: 630;font-family:arial;color: black;font-size: 10px;text-decoration: none;align:right;}
<?php
	print "#dhtmltooltip{position: absolute;-moz-border-radius:6px;-webkit-border-radius:6px; border-radius:6px;behavior: url(border-radius.htc);left: -286px;width:150px;padding: 3px;background-color:#eeeeee;";
	if(!stristr(strtolower($_SERVER['HTTP_USER_AGENT']), "msie ")) //If not IE ?	
	{ print "background: -webkit-gradient(linear, left top, left bottom, from(#eeeeee), to(#e2e2e2));background: -moz-linear-gradient(top,  #eeeeee,  #e2e2e2);"; }
	print 'visibility: hidden;z-index: 100;color:black;font-family:"arial";font-size: 9px;box-shadow: 0px 0px 3px #111111;-webkit-box-shadow: 0px 0px 3px #111111;-moz-box-shadow: 0px 0px 3px #111111;}';
?>
#dhtmlpointer{position:absolute;left: -300px;z-index: 101;visibility: hidden;}

#side_bar_curved_button{width:140px;-moz-border-radius:5px;-webkit-border-radius:5px; border-radius:5px;behavior: url(border-radius.htc); border: 0px solid #db0019;
<?php
	$color_light = $_SESSION['color_light'];
	$color_dark = $_SESSION['color_dark'];
	print "background-color:$color_dark;";
	if(!stristr(strtolower($_SERVER['HTTP_USER_AGENT']), "msie ")) //If not IE ?
	{ print "background: -webkit-gradient(linear, left top, left bottom, from($color_light), to($color_dark));background: -moz-linear-gradient(top, $color_light,  $color_dark);"; }
?>
height:20px;box-shadow: 1px 1px 3px #111111;-webkit-box-shadow: 1px 1px 3px #111111;-moz-box-shadow: 1px 1px 3px #111111;}

#side_bar_curved_button:hover{-moz-border-radius:5px;-webkit-border-radius:5px; border-radius:5px;behavior: url(border-radius.htc); border: 0px solid #db0019;
<?php
	print "background-color:$color_light;background: -webkit-gradient(linear, left top, left bottom, from($color_dark), to($color_light));background: -moz-linear-gradient(top,$color_dark, $color_light);";
?>
width:140px; height:20px;box-shadow: 1px 1px 3px #0f0f0f;-webkit-box-shadow: 1px 1px 3px #0f0f0f;-moz-box-shadow: 1px 1px 3px #0f0f0f;}
#side_bar_curved_button_text {position:relative;text-align:center;top:4px;font-family:arial;font-size:10px;color:white;font-weight: bold;text-shadow:1px 1px 1px #000;}
#mockup_mode_curved_button{-moz-border-radius:6px;-webkit-border-radius:6px; border-radius:6px; border: 0px solid #db0019; background-color:#db0019; width:280px; height:18px;}
#mockup_mode_curved_button_text {position:relative;top:4px;font-family:arial;font-size:10px;color:white;font-weight: bold;}
#logout_db{-moz-border-radius:6px;-webkit-border-radius:6px; border-radius:6px; border: 0px solid #db0019; background-color:#db0019; width:102px; height:18px;}
#logout_db_text {position:relative;top:2px;font-family:arial;font-size:10px;color:white;font-weight:bold;}
#button_generic_black{-moz-border-radius:6px;-webkit-border-radius:6px; border-radius:6px;behavior: url(border-radius.htc); border: 0px solid #db0019; background-color:#db0019; width:86px; height:28px;}
</style>
