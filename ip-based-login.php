<?php
/**
 * @package ip-based-login
 * @version 1.3.8
 */
/*
Plugin Name: IP Based Login
Plugin URI: http://wordpress.org/extend/plugins/ip-based-login/
Description: IP Based Login is a plugin which allows you to directly login from an allowed IP. You can create ranges and define the IP range which can get access to a particular user. So if you want to allow someone to login but you do not want to share the login details just add their IP using IP Based Login.
Version: 1.3.8
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

define('ipbl_version', '1.3.8');

// This function adds a link in admin toolbar
function ipbl_admin_bar() {
	global $wp_admin_bar;
	$siteurl = get_option('siteurl');

	$wp_admin_bar->add_node(array(
		'id'    => 'ipbl-link',
		'title' => 'Logged in by IP Based Login ('.getip().')',
		'href'  => 'http://www.wpinspired.com/ip-based-login'
	));

	$wp_admin_bar->add_node(array(
		'id'    => 'ipbl-logoff-15',
		'title' => 'Disable auto login for 15 minutes',
		'parent' => 'ipbl-link',
		'href'  => $siteurl.'/wp-admin/options-general.php?page=ip-based-login&no_login=15'
	));

	$wp_admin_bar->add_node(array(
		'id'    => 'ipbl-logoff-30',
		'title' => 'Disable auto login for 30 minutes',
		'parent' => 'ipbl-link',
		'href'  => $siteurl.'/wp-admin/options-general.php?page=ip-based-login&no_login=30'
	));

	$wp_admin_bar->add_node(array(
		'id'    => 'ipbl-logoff-60',
		'title' => 'Disable auto login for 1 hour',
		'parent' => 'ipbl-link',
		'href'  => $siteurl.'/wp-admin/options-general.php?page=ip-based-login&no_login=60'
	));

}

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
  `start` bigint(20) NOT NULL,
  `end` bigint(20) NOT NULL,
  `status` tinyint(2) NOT NULL DEFAULT '1',
  `date` int(10) NOT NULL,
  PRIMARY KEY (`rid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;";

$wpdb->query($sql);

add_option('ipbl_version', ipbl_version);

}

add_action( 'plugins_loaded', 'ip_based_login_update_check' );

function ip_based_login_update_check(){

global $wpdb;
	// Check if the user wants to set no_login
	if(!empty($_REQUEST['no_login'])){

	    $current_user = wp_get_current_user();
		$no_login = sanitize_variables($_REQUEST['no_login']);
		$expire_cookie = $no_login * 60;
		setcookie('ipbl_'.$current_user->user_login, 'no_login', time()+$expire_cookie, '/');
		wp_logout();
		wp_redirect(home_url());
		exit; 
	}

	$sql = array();
	$current_version = get_option('ipbl_version');

	if($current_version < 1.3){
		$sql[] = "ALTER TABLE `".$wpdb->prefix."ip_based_login` CHANGE `start` `start` BIGINT( 20 ) NOT NULL ;";
		$sql[] = "ALTER TABLE `".$wpdb->prefix."ip_based_login` CHANGE `end` `end` BIGINT( 20 ) NOT NULL ;";
		$sql[] = "ALTER TABLE `".$wpdb->prefix."ip_based_login` ADD `status` TINYINT( 2 ) NOT NULL DEFAULT '1' AFTER `end` ;";
	}

	if($current_version < ipbl_version){
		foreach($sql as $sk => $sv){
			$wpdb->query($sv);
		}

		update_option('ipbl_version', ipbl_version);
	}

}

function triger_login(){
	
	global $wpdb;
	
	$logged_ip = getip();
	$query = "SELECT * FROM ".$wpdb->prefix."ip_based_login WHERE ".ip2long($logged_ip)." BETWEEN `start` AND `end` AND `status` = 1";
	$result = selectquery($query);
	$username = $result['username'];
	
	if(!is_user_logged_in() && !empty($username) && empty($_COOKIE['ipbl_'.$username])){

		// What is the user id ?
		$user = get_userdatabylogin($username);
		$user_id = $user->ID;
				
		// Lets login
		wp_set_current_user($user_id, $username);
		wp_set_auth_cookie($user_id);
		do_action('wp_login', $username, $user);
	}
	
	// Did we login the user ?
	if(!empty($username)){
		add_action('wp_before_admin_bar_render', 'ipbl_admin_bar');
	}
}

add_action('init', 'triger_login');

// Add settings link on plugin page
function ipbl_settings_link($links) { 
  $settings_link = '<a href="options-general.php?page=ip-based-login">Settings</a>'; 
  array_unshift($links, $settings_link); 
  return $links; 
}
 
$plugin = plugin_basename(__FILE__); 
add_filter("plugin_action_links_$plugin", 'ipbl_settings_link' );

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

function is_checked($post){

	if(!empty($_POST[$post])){
		return true;
	}	
	return false;
}

function report_error($error = array()){

	if(empty($error)){
		return true;
	}
	
	$error_string = '<b>Please fix the below errors :</b> <br />';
	
	foreach($error as $ek => $ev){
		$error_string .= '* '.$ev.'<br />';
	}
	
	echo '<div id="message" class="error"><p>'
					. __($error_string, 'ip-based-login')
					. '</p></div>';
}

function ipbl_objectToArray($d){
  if(is_object($d)){
    $d = get_object_vars($d);
  }
  
  if(is_array($d)){
    return array_map(__FUNCTION__, $d); // recursive
  }elseif(is_object($d)){
    return ipbl_objectToArray($d);
  }else{
    return $d;
  }
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
	
	if(isset($_GET['users_dropdown'])){		
		$users_dropdown = (int) sanitize_variables($_GET['users_dropdown']);
		if(!empty($users_dropdown)){
			update_option('ipbl_dropdown', '1');
		}else{
			update_option('ipbl_dropdown', '');			
		}
	}
	
	if(isset($_GET['delid'])){
		
		$delid = (int) sanitize_variables($_GET['delid']);
		
		$wpdb->query("DELETE FROM ".$wpdb->prefix."ip_based_login WHERE `rid` = '".$delid."'");
		echo '<div id="message" class="updated fade"><p>'
			. __('IP range has been deleted successfully', 'ip-based-login')
			. '</p></div>';	
	}
	
	if(isset($_GET['statusid'])){
		
		$statusid = (int) sanitize_variables($_GET['statusid']);
		$setstatus = sanitize_variables($_GET['setstatus']);
		$_setstatus = ($setstatus == 'disable' ? 0 : 1);
		
		$wpdb->query("UPDATE ".$wpdb->prefix."ip_based_login SET `status` = '".$_setstatus."' WHERE `rid` = '".$statusid."'");
		echo '<div id="message" class="updated fade"><p>'
			. __('IP range has been '.$setstatus.'d successfully', 'ip-based-login')
			. '</p></div>';	
	}
	
	if(isset($_POST['add_iprange'])){
		global $ip_based_login_options;

		$ip_based_login_options['username'] = trim($_POST['username']);
		$ip_based_login_options['start'] = trim($_POST['start_ip']);
		$ip_based_login_options['end'] = trim($_POST['end_ip']);

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
		
		// This is to check if there is any other range exists with the same Start or End IP
		$ip_exists_query = "SELECT * FROM ".$wpdb->prefix."ip_based_login WHERE 
		`start` BETWEEN '".ip2long($ip_based_login_options['start'])."' AND '".ip2long($ip_based_login_options['end'])."'
		OR `end` BETWEEN '".ip2long($ip_based_login_options['start'])."' AND '".ip2long($ip_based_login_options['end'])."';";
		$ip_exists = $wpdb->get_results($ip_exists_query);
		//print_r($ip_exists);
		
		if(!empty($ip_exists)){
			$error[] = 'The Start IP or End IP submitted conflicts with an existing IP range!';
		}
		
		// This is to check if there is any other range exists with the same Start IP
		$start_ip_exists_query = "SELECT * FROM ".$wpdb->prefix."ip_based_login WHERE 
		'".ip2long($ip_based_login_options['start'])."' BETWEEN `start` AND `end`;";
		$start_ip_exists = $wpdb->get_results($start_ip_exists_query);
		//print_r($start_ip_exists);
		
		if(!empty($start_ip_exists)){
			$error[] = 'The Start IP is present in an existing range!';
		}
		
		// This is to check if there is any other range exists with the same End IP
		$end_ip_exists_query = "SELECT * FROM ".$wpdb->prefix."ip_based_login WHERE 
		'".ip2long($ip_based_login_options['end'])."' BETWEEN `start` AND `end`;";
		$end_ip_exists = $wpdb->get_results($end_ip_exists_query);
		//print_r($end_ip_exists);
		
		if(!empty($end_ip_exists)){
			$error[] = 'The End IP is present in an existing range!';
		}
		
		if(ip2long($ip_based_login_options['start']) > ip2long($ip_based_login_options['end'])){
			$error[] = 'The end IP cannot be smaller than the start IP';			
		}
		
		if(empty($error)){
			
			$options['username'] = $ip_based_login_options['username'];
			$options['start'] = ip2long($ip_based_login_options['start']);
			$options['end'] = ip2long($ip_based_login_options['end']);
			$options['status'] = (is_checked('status') ? 1 : 0);
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
	
	// A list of all users
	$_users = get_users();
	$users_dropdown = get_option('ipbl_dropdown');
	
	$show_popup = 0;
	$donate_popup = get_option('ipbl_donate_popup');
	if(!empty($donate_popup)){
		if($donate_popup <= date('Ymd', strtotime('-1 month'))){
			$show_popup = 1;
			update_option('ipbl_donate_popup', date('Ymd'));
		}
	}else{
		$show_popup = 1;
		update_option('ipbl_donate_popup', date('Ymd'));
	}
	
	echo '<script>
	var donate_popup = '.$show_popup.';
	if(donate_popup == 1){
		if(confirm("Donate $5 for IP Based Login to support the development")){
			window.location.href =  "http://www.wpinspired.com/ip-based-login";
		}
	}
	</script>';
	
	?>
	<div class="wrap">
	  <h2><?php echo __('IP Based Login Settings','ip-based-login'); ?></h2>
	  <form action="options-general.php?page=ip-based-login" method="post">
		<?php wp_nonce_field('ip-based-login-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><label for="username"><?php echo __('Username','ip-based-login'); ?></label></th>
			<td>
            	<?php
				
					if(!empty($users_dropdown)){
						echo '<select name="username">';
						
						foreach($_users as $uk => $uv){
							$_users[$uk] = ipbl_objectToArray($uv);
							echo '<option value="'.$_users[$uk]['data']['user_login'].'" '.($ip_based_login_options['username'] == $_users[$uk]['data']['user_login'] ? 'selected="selected"' : '').'>'.$_users[$uk]['data']['user_login'].'</option>';
						}
						
						echo '</select>&nbsp;&nbsp;';
					}else{
						echo '<input type="text" size="25" value="'.((isset($_POST['username']) ? trim($_POST['username']) : '')).'" name="username" id="username" />';
					}
					
				?>
                
			  <?php echo __('Username to be logged in as when accessed from the below IP range','ip-based-login'); ?> <br />
				<?php
				
					if(empty($users_dropdown)){
						echo __('<a class="submitdelete" href="options-general.php?page=ip-based-login&users_dropdown=1">Show the list of users in a drop down</a>','ip-based-login');
					}else{						
						echo __('<a class="submitdelete" href="options-general.php?page=ip-based-login&users_dropdown=0">Don\'t show the list of users in a drop down</a>','ip-based-login');
					}
					
                ?> <br />
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><label for="start_ip"><?php echo __('Start IP','ip-based-login'); ?></label></th>
			<td>
			  <input type="text" size="25" value="<?php echo((isset($_POST['start_ip']) ? trim($_POST['start_ip']) : '')); ?>" name="start_ip" id="start_ip" /> <?php echo __('Start IP of the range','ip-based-login'); ?> <br />
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><label for="end_ip"><?php echo __('End IP','ip-based-login'); ?></label></th>
			<td>
			  <input type="text" size="25" value="<?php echo((isset($_POST['end_ip']) ? trim($_POST['end_ip']) : '')); ?>" name="end_ip" id="end_ip" /> <?php echo __('End IP of the range','ip-based-login'); ?> <br />
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Active','ip-based-login'); ?></th>
			<td>
			  <input type="checkbox" <?php if(!isset($_POST['add_iprange']) || is_checked('status')) echo 'checked="checked"'; ?> name="status" /> <?php echo __('Select the checkbox to set this range as active','ip-based-login'); ?> <br />
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
					$status_button = (!empty($iv['status']) ? 'disable' : 'enable');
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
							<a class="submitdelete" href="options-general.php?page=ip-based-login&delid='.$iv['rid'].'" onclick="return confirm(\'Are you sure you want to delete this IP range ?\')">Delete</a>&nbsp;&nbsp;
							<a class="submitdelete" href="options-general.php?page=ip-based-login&statusid='.$iv['rid'].'&setstatus='.$status_button.'" onclick="return confirm(\'Are you sure you want to '.$status_button.' this IP range ?\')">'.ucfirst($status_button).'</a>
						</td>
					</tr>';
				}
			?>
		</table>
		<?php
	}
	
	echo '<br /><br /><br /><br /><hr />
	IP Based Login v'.ipbl_version.' is developed by <a href="http://wpinspired.com" target="_blank">WP Inspired</a>. 
	You can report any bugs <a href="http://wordpress.org/support/plugin/ip-based-login" target="_blank">here</a>. 
	You can provide any valuable feedback <a href="http://www.wpinspired.com/contact-us/" target="_blank">here</a>.
	<a href="http://www.wpinspired.com/ip-based-login" target="_blank">Donate</a>';
}	

// Sorry to see you going
register_uninstall_hook( __FILE__, 'ip_based_login_deactivation');

function ip_based_login_deactivation(){

global $wpdb;

$sql = "DROP TABLE ".$wpdb->prefix."ip_based_login;";
$wpdb->query($sql);

delete_option('ipbl_version');
delete_option('ipbl_dropdown');
delete_option('ipbl_donate_popup');

}
?>
