<?php

function get_command_output($id, $query, $db)
{
	$query = "select output from command_output where id=$id ";
	$result=mysql_query($query, $db);
	if(mysql_num_rows($result) > 0)
	{ while($row = mysql_fetch_array($result))
		{
			return $row['output'];
		}
	}
}
?>