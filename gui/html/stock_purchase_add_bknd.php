<html><?php include('c/c_body_bknd.php'); include("c/c_db_access.php"); error_reporting(5); session_start();
$_amount = $_POST['amount'];
$_details = $_POST['details'];
$_day=$_POST['day'];$_month=$_POST['month']; $_year=$_POST['year'];
$_date = "$_year-$_month-$_day";
$query = "insert into purchase (purdate,amount,details) values ('$_date',$_amount,'$_details')";
//print $query;
mysql_query($query, $db);
mysql_close($db);
print "<meta HTTP-EQUIV=\"REFRESH\" content=\"0; url=stock_purchase.php\">";
?></body></html>