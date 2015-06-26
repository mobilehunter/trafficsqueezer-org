<?php error_reporting(5);
	system('service trafficsqueezerd stop');
	system('update-rc.d -f trafficsqueezerd remove');
	system('rm -rf /etc/init.d/trafficsqueezerd');
	system('rm -f /usr/sbin/trafficsqueezerd');

	system("rm -rf ./*~");
	system("rm -rf ./saas_gui/db_saas/*~");
	system("rm -rf ./saas_gui/html/*~");
	system("rm -rf ./saas_gui/html/c/*~");
	system("rm -rf ./saas_gui/html/php/*~");
	system("rm -rf ./etc/init.d/*~");
	system("rm -rf ../*~");
?>
