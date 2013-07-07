<?php
/**
 * @package ip-based-login
 * @version 1.0
 */
/*
Plugin Name: IP Based Login
Plugin URI: http://wordpress.org/extend/plugins/ip-based-login/
Description: IP Based Login is a plugin which allows you to directly login from an allowed IP. You can create ranges and define the IP range which can get access to a particular user. So if you want to allow someone to login but you do not want to share the login details just add their IP using IP Based Login.
Version: 1.0
Author: Brijesh Kothari
Author URI: http://www.wpinspired.com/
License: GPLv3 or later
*/

/*
Copyright (C) 2013  Brijesh Kothari (email : admin@wpinspired.com)
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

if(!function_exists('add_action')){
	echo 'You are not allowed to access this page directly.';
	exit;
}

define('ipbl_version', '1.0');

// Ok so we are now ready to go
register_activation_hook( __FILE__, 'ip_based_login_activation');

function ip_based_login_activation(){

global $wpdb;

$sql = "
--
-- Table structure for table `".$wpdb->prefix."ip_based_login`
--

CREATE TABLE IF NOT EXISTS `".$wpdb->prefix."ip_based_login` (
  `rid` int(10) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `start` int(10) NOT NULL,
  `end` int(10) NOT NULL,
  `date` int(10) NOT NULL,
  PRIMARY KEY (`rid`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;";

$wpdb->query($sql);

add_option('ipbl_version', ipbl_version);

}

function triger_login(){
	
	global $wpdb;
	
	$logged_ip = getip();
	$query = "SELECT * FROM ".$wpdb->prefix."ip_based_login WHERE ".ip2long($logged_ip)." BETWEEN `start` AND `end`";
	$result = selectquery($query);
	$username = $result['username'];
	
	if(!is_user_logged_in() && !empty($username)){

		// What is the user id ?
		$user = get_userdatabylogin($username);
		$user_id = $user->ID;
				
		// Lets login
		wp_set_current_user($user_id, $username);
		wp_set_auth_cookie($user_id);
		do_action('wp_login', $username);
	}
}

add_action('init', 'triger_login');
add_action('admin_menu', 'ip_based_login_admin_menu');

function getip(){
	if(isset($_SERVER["REMOTE_ADDR"])){
		return $_SERVER["REMOTE_ADDR"];
	}elseif(isset($_SERVER["HTTP_X_FORWARDED_FOR"])){
		return $_SERVER["HTTP_X_FORWARDED_FOR"];
	}elseif(isset($_SERVER["HTTP_CLIENT_IP"])){
		return $_SERVER["HTTP_CLIENT_IP"];
	}
}

function selectquery($query){
	global $wpdb;
	
	$result = $wpdb->get_results($query, 'ARRAY_A');
	return current($result);
}

function ip_based_login_admin_menu() {
	global $wp_version;

	// Modern WP?
	if (version_compare($wp_version, '3.0', '>=')) {
	    add_options_page('IP Based Login', 'IP Based Login', 'manage_options', 'ip-based-login', 'ip_based_login_option_page');
	    return;
	}

	// Older WPMU?
	if (function_exists("get_current_site")) {
	    add_submenu_page('wpmu-admin.php', 'IP Based Login', 'IP Based Login', 9, 'ip-based-login', 'ip_based_login_option_page');
	    return;
	}

	// Older WP
	add_options_page('IP Based Login', 'IP Based Login', 9, 'ip-based-login', 'ip_based_login_option_page');
}

function sanitize_variables($variables = array()){
	
	if(is_array($variables)){
		foreach($variables as $k => $v){
			$variables[$k] = trim($v);
			$variables[$k] = escapeshellcmd($v);
			$variables[$k] = mysql_real_escape_string($v);
		}
	}else{
		$variables = mysql_real_escape_string(escapeshellcmd(trim($variables)));
	}
	
	return $variables;
}

function valid_ip($ip){

	if(!ip2long($ip)){
		return false;
	}	
	return true;
}

function report_error($error = array()){

	if(empty($error)){
		return true;
	}
	
	$error_string = '<b>Please fix the below errors :</b> <br />';
	
	foreach($error as $ek => $ev){
		$error_string .= '* '.$ev.'<br />';
	}
	
	echo '<div id="message" class="updated"><p>'
					. __($error_string, 'ip-based-login')
					. '</p></div>';
}

function ip_based_login_option_page(){

	global $wpdb;
	
	if(!current_user_can('manage_options')){
		wp_die('Sorry, but you do not have permissions to change settings.');
	}

	/* Make sure post was from this page */
	if(count($_POST) > 0){
		check_admin_referer('ip-based-login-options');
	}
	
	if(isset($_GET['delid'])){
		
		$delid = (int) sanitize_variables($_GET['delid']);
		
		$wpdb->query("DELETE FROM ".$wpdb->prefix."ip_based_login WHERE `rid` = '".$delid."'");
		echo '<div id="message" class="updated fade"><p>'
			. __('IP range has been deleted successfully', 'ip-based-login')
			. '</p></div>';	
	}
	
	if(isset($_POST['add_iprange'])){
		global $ip_based_login_options;

		$ip_based_login_options['username'] = $_POST['username'];
		$ip_based_login_options['start'] = $_POST['start_ip'];
		$ip_based_login_options['end'] = $_POST['end_ip'];

		$ip_based_login_options = sanitize_variables($ip_based_login_options);
		
		$user = get_user_by('login', $ip_based_login_options['username']);
		
		if(empty($user)){
			$error[] = 'The username does not exist.';
		}
		
		if(!valid_ip($ip_based_login_options['start'])){
			$error[] = 'Please provide a valid start IP';
		}
		
		if(!valid_ip($ip_based_login_options['end'])){
			$error[] = 'Please provide a valid end IP';			
		}
		
		if(ip2long($ip_based_login_options['start']) > ip2long($ip_based_login_options['end'])){
			$error[] = 'The end IP cannot be smaller than the start IP';			
		}
		
		if(empty($error)){
			
			$options['username'] = $ip_based_login_options['username'];
			$options['start'] = ip2long($ip_based_login_options['start']);
			$options['end'] = ip2long($ip_based_login_options['end']);
			$options['date'] = date('Ymd');
			
			$wpdb->insert($wpdb->prefix.'ip_based_login', $options);
			
			if(!empty($wpdb->insert_id)){
				echo '<div id="message" class="updated fade"><p>'
					. __('IP range added successfully', 'ip-based-login')
					. '</p></div>';
			}else{
				echo '<div id="message" class="updated fade"><p>'
					. __('There were some errors while adding IP range', 'ip-based-login')
					. '</p></div>';			
			}
			
		}else{
			report_error($error);
		}
	}
	
	$ipranges = $wpdb->get_results("SELECT * FROM ".$wpdb->prefix."ip_based_login;", 'ARRAY_A');
	
	?>
	<div class="wrap">
	  <h2><?php echo __('IP Based Login Settings','ip-based-login'); ?></h2>
	  <form action="options-general.php?page=ip-based-login" method="post">
		<?php wp_nonce_field('ip-based-login-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php echo __('Username','ip-based-login'); ?></th>
			<td>
			  <input type="text" size="25" value="<?php echo((isset($_POST['username']) ? $_POST['username'] : '')); ?>" name="username" /> <?php echo __('Username to be logged in as when accessed from the below IP range','ip-based-login'); ?> <br />
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Start IP','ip-based-login'); ?></th>
			<td>
			  <input type="text" size="25" value="<?php echo((isset($_POST['start_ip']) ? $_POST['start_ip'] : '')); ?>" name="start_ip" /> <?php echo __('Start IP of the range','ip-based-login'); ?> <br />
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('End IP','ip-based-login'); ?></th>
			<td>
			  <input type="text" size="25" value="<?php echo((isset($_POST['end_ip']) ? $_POST['end_ip'] : '')); ?>" name="end_ip" /> <?php echo __('End IP of the range','ip-based-login'); ?> <br />
			</td>
		  </tr>
		</table><br />
		<input name="add_iprange" class="button action" value="<?php echo __('Add IP range','ip-based-login'); ?>" type="submit" />		
	  </form>
	</div>	
	<?php
	
	if(!empty($ipranges)){
		?>
		<br /><br />
		<table class="wp-list-table widefat fixed users">
			<tr>
				<th scope="row" valign="top"><?php echo __('Username','ip-based-login'); ?></th>
				<th scope="row" valign="top"><?php echo __('Start IP','ip-based-login'); ?></th>
				<th scope="row" valign="top"><?php echo __('End IP','ip-based-login'); ?></th>
				<th scope="row" valign="top"><?php echo __('Options','ip-based-login'); ?></th>
			</tr>
			<?php
				
				foreach($ipranges as $ik => $iv){
					echo '
					<tr>
						<td>
							'.$iv['username'].'
						</td>
						<td>
							'.long2ip($iv['start']).'
						</td>
						<td>
							'.long2ip($iv['end']).'
						</td>
						<td>
							<a class="submitdelete" href="options-general.php?page=ip-based-login&delid='.$iv['rid'].'" onclick="return confirm(\'Are you sure you want to delete this IP range ?\')">Delete</a>
						</td>
					</tr>';
				}
			?>
		</table>
		<?php
	}
}	

// Sorry to see you going
register_deactivation_hook( __FILE__, 'ip_based_login_deactivation');

function ip_based_login_deactivation(){

global $wpdb;

$sql = "DROP TABLE ".$wpdb->prefix."ip_based_login;";
$wpdb->query($sql);

delete_option('ipbl_version'); 

}
?>
