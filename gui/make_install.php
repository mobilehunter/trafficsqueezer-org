<?php error_reporting(5);
system("php -f ./make_clean.php");
	
system('service trafficsqueezerd stop');
system('cp ./trafficsqueezerd /usr/sbin/.');
system('chmod 555 /usr/sbin/trafficsqueezerd');
	
system('cp ./etc/init.d/trafficsqueezerd /etc/init.d/.');
system('chmod 775 /etc/init.d/trafficsqueezerd');
system('update-rc.d trafficsqueezerd defaults 97 03');
system('service trafficsqueezerd start');
	
$home_dir = getcwd();

print "Installing TrafficSqueezer GUI in (/var/www/html) Apache default webroot folder ...\n"; ts_execute_squence( "cp -r html/* /var/www/html/. &", $home_dir, $home_dir); print "Done !\n";
print "Setting Appropriate Permissions in (/var/www/html) Apache default webroot folder ...\n"; ts_execute_squence( "chmod 777 /var/www/html/*  -R  &", $home_dir, $home_dir); print "Done !\n";
chdir($home_dir); exit();	

function ts_execute_squence($task, $workdir, $homedir)
{
	chdir($workdir);
	foreach(preg_split("/(\r?\n)/", $task) as $command)
   {
       system($command);
	}
	chdir($homedir);
}

function ts_setup($option, $task, $workdir, $homedir)
{
	chdir($workdir);
	while(1)
	{
		print "\n$option ";
		$ret = fgets(STDIN);
		if($ret=="y\n")
		{
			ts_execute_squence($task, $workdir, $homedir);
			return $ret;
		}
		else if($ret=="n\n")
		{
			print "skipped ... !\n";
			chdir($homedir);
			return $ret;
		}
	}
}

?>
