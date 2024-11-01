<?php
/*
Plugin Name: XMLRPC Attacks Blocker
Description: multipie ways to help block xmlrpc attacks.
Plugin URI: http://wpdevplus.com
Author: Yehuda Hassine
Author URI: http://wpdevplus.com
Version: 1.0
License: GPL2
*/
class axab {
    private $htaccess, $home_path;
    private $prefix = 'axab';
    private $marker = 'XMLRPC Attacks Blocker';
    private $error;
    private static $instance = null;


   public static function get_instance() {
     if( null == self::$instance ) {
       self::$instance = new self;
     }
     return self::$instance;
   } 

  
    function __construct() {
        include_once(ABSPATH . 'wp-admin/includes/file.php');
        $this->home_path = get_home_path();
        $this->htaccess= $this->home_path .'.htaccess';

        if (!$this->pre() ) {
            add_action( "admin_init", array( $this, 'self_deactivate') );
            add_action('admin_notices', function() {
                if ( isset( $this->error ) )
                    echo '<div class="error"><p>Activation ERROR: ' . $this->error . '</p></div>';
            });            
        } else {
            register_activation_hook( __FILE__, array( $this, 'activate' ) );
        }

        register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );

        add_action( 'admin_menu', array( $this, 'add_menu' ) );
    
        add_action( "admin_enqueue_scripts", array( $this, 'enqueue_scripts' ) );
        add_action ("admin_head", array( $this, 'admin_head_scripts') );

        $options = $this->get_options();
        // fire when xmlrpc login error
        if ( isset($options['block_login_error']) ) {
            add_filter( 'xmlrpc_login_error', array( $this, 'xmlrpc_login_error'), 10,2);
        }
        // disable xmlrpc
        if ( isset($options['disable_xmlrpc']) ) {
            add_filter( 'xmlrpc_enabled', function() { return false; } );
        }

        if (isset($options['enable_xmlrpc_user'])) {
            add_filter( 'authenticate', array( $this, 'authenticate'), 10, 3 );
        }

        //disable builtin function
        if (isset( $options['disable_builtin_methods']) ) {
            add_filter( 'xmlrpc_methods', array( $this, 'disable_methods') );
        }
    }

    function authenticate( $null, $username, $password) {
        $options = $this->get_options();
        if( basename($_SERVER['PHP_SELF']) == 'xmlrpc.php' && isset($options['enable_xmlrpc_user']) ) {
            $xmlrpc_user = $options['xmlrpc_user'];
            if ($username != $xmlrpc_user) {
                return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username.'));
            }
        }
    }

    function activate() {
		ob_start();	
        $args = array(
            'disable_xmlrpc' => 0,
            'block_login_error' => 1,
            'disable_builtin_methods' => 1
            );

        add_option( "{$this->prefix}_options", $args);   
        $this->copy_xmlrpc_methods();     
        add_option( "{$this->prefix}_errors" , array() );

        $rules = PHP_EOL . "# BEGIN $this->marker" . PHP_EOL . "order allow,deny" . PHP_EOL . "allow from all" . PHP_EOL . "# END $this->marker";
        if ( !is_writable($this->home_path) ) {
            $this->error = 'There was an error writing to your htaccess file,<br>Please check permission.';
        }

        if ( !file_exists( $this->htaccess ) ) {
            file_put_contents( $this->htaccess, $rules);
        } else {

            $content = file_get_contents( $this->htaccess );
            $exist = preg_match_all("/# BEGIN " . $this->marker . ".*# END " . $this->marker . "/s", $content, $matches);
  
            if ( $exist == 0 ) {
                file_put_contents( $this->htaccess, $rules, FILE_APPEND | LOCK_EX );
            }
        }      
        
    }

    function pre( $wp = '4.0', $php = '5.2' ) {
        global $wp_version;
        if ( version_compare( PHP_VERSION, $php, '<' ) )
            $flag = 'PHP';
        elseif ( version_compare( $wp_version, $wp, '<' ) )
            $flag = 'WordPress';
        else
            return true;

        $version = 'PHP' == $flag ? $php : $wp;
        $this->error = 'The <strong>' . $this->marker .'</strong> plugin requires '.$flag.'  version '.$version.' or greater.';
        return false;
    }    

    function deactivate() {
        update_option( "{$this->prefix}_errors", array() );
    }
                                           
    function self_deactivate() {
    	if ( is_admin() && isset( $this->error ) ) {
    		deactivate_plugins( plugin_basename( __FILE__ ) );
    		if ( isset( $_GET['activate'] ) ) {
    			unset( $_GET['activate'] );
    		}
    	}
    }

    function add_menu() {
        $options = $this->get_options();
        add_menu_page( $this->marker, $this->marker, 'administrator', $this->prefix, array( $this, 'page' ) );
        if ( isset( $options['debug']) ) {
            add_submenu_page( $this->prefix, 'Debug', 'Debug', 'administrator', "{$this->prefix}_debug", array( $this, 'debug' ) );
        }
        add_action( 'admin_init', array( $this, 'register_settings' ) );
    }

    function enqueue_scripts() {
        wp_enqueue_script( "{$this->prefix}_script", plugins_url( 'js/script.js', __FILE__ ), array( 'jquery'), false, false );
        wp_enqueue_script( "{$this->prefix}_chosen_js", plugins_url( 'js/chosen.jquery.min.js', __FILE__ ), array( 'jquery'), false, false );

        wp_enqueue_style( "{$this->prefix}_style", plugins_url( 'css/style.css', __FILE__ ) );
        wp_enqueue_style( "{$this->prefix}_chosen_style", plugins_url( 'css/chosen.min.css', __FILE__ ) );
    }    

    function admin_head_scripts() {
        $options = $this->get_options();
        echo '<script type="text/javascript">';
        echo 'jQuery(document).ready(function($) {';
        if ( isset( $options['enable_xmlrpc_user'] ) ) {
            echo "$('.chosen-container').show();";
        } else {
            echo "$('.chosen-container').hide();";
        }

        if ( isset( $options['disable_builtin_methods'] ) ) {
            echo "$('.method').show();";
        } else {
            echo "$('.method').hide();";
        }

        echo "  $('.xmlrpc_user_checkbox').click(function() {
                    $('.chosen-container').toggle();
                });";

        echo "  $('.disable_methods').click(function() {
                    $('.method').toggle();
                });

            });";  
        echo '</script>';
    }

    function register_settings() {
        register_setting( "{$this->prefix}-group", "{$this->prefix}_options" );
    }

    function debug() {
        $errors = $this->get_errors();
        echo '<div class="wrap">';
        echo '<h2>Debug Log</h2>';
        echo '<table class="widefat">';
        foreach ($errors as $key => $error) {
            echo "$error<br>";
        }
        echo '</table>';
        echo '</div>';
    }

    function page() {?>
        <div class="wrap">
        <h2><?php echo $this->marker; ?></h2>

        <form method="post" action="options.php">
            <?php 
            settings_fields( "{$this->prefix}-group" );
            do_settings_sections( "{$this->prefix}-group" );
            $options = $this->get_options(); 
            submit_button();
            ?>
            <table class="form-table">
                <tr valign="top">
                <th scope="row">Log errors and access.</th>
                    <td><input type="checkbox" name="<?php echo $this->prefix; ?>_options[debug]" value="1" <?php if (isset($options['debug'])) checked( $options['debug'], 1 ); ?>  /></td>
                </tr>

                <tr valign="top">
                <th scope="row">Disable xmlrpc.</th>
                    <td><input type="checkbox" name="<?php echo $this->prefix; ?>_options[disable_xmlrpc]" value="1" <?php if (isset($options['disable_xmlrpc'])) checked( $options['disable_xmlrpc'], 1 ); ?>  /></td>
                </tr>
                 
                <tr valign="top">
                <th scope="row">Block login errors ip's in htaccess.</th>
                    <td><input type="checkbox" name="<?php echo $this->prefix; ?>_options[block_login_error]" value="1" <?php if (isset($options['block_login_error'])) checked( $options['block_login_error'], 1 ); ?>  /></td>
                </tr>

                <tr valign="top">
                <th scope="row">Enable xmlrpc for a specific user.</th>
                    <td><input type="checkbox" name="<?php echo $this->prefix; ?>_options[enable_xmlrpc_user]" class="xmlrpc_user_checkbox" value="1" <?php if (isset($options['enable_xmlrpc_user'])) checked( $options['enable_xmlrpc_user'], 1 ); ?>  /></td>
                </tr>

                <tr valign="top" class="xmlrpc_selectbox">
                    <th scope="row">
                        <select class="chosen-select" name="<?php echo $this->prefix; ?>_options[xmlrpc_user]">
                            <?php 
                                $users = get_users( array( 'fields' => array( 'display_name' ) ) );
                                foreach ( $users as $user ) {
                                    $dn = esc_html( $user->display_name );
                                    $op = isset($options['xmlrpc_user']) ? selected( $options['xmlrpc_user'], $dn ) : '';
                                    echo "<option value=\"$dn\" " . $op . ">$dn</option>";
                                }
                            ?>
                        </select>                        
                    </th>
                </tr>                    

                <tr valign="top">
                <th scope="row">disable xmlrpc built in functions.</th>
                    <td><input type="checkbox" class="disable_methods" name="<?php echo $this->prefix; ?>_options[disable_builtin_methods]" value="1" <?php if (isset($options['disable_builtin_methods'])) checked( $options['disable_builtin_methods'], 1 ); ?>  /></td>
                </tr>
                <?php
                $methods = $options['builtin_methods'];

                foreach ($methods as $key => $value) { 
                    $option = "{$this->prefix}_options[builtin_methods][$key]";
                    echo '<tr class="method"><td><label>' . $key . '</label></td>';
                    echo '<td>
                    <input type="hidden" name="' . $option . '" value="0" />
                    <input type="checkbox" name="' . $option . '" value="1"' . checked( $value, 1, false ) . ' />
                    </td></tr>';
                } ?>
            </table>
            
            <?php submit_button(); ?>

        </form>
        </div>
        <?php
    }

    function xmlrpc_login_error($error, $user) {
        $ip = $this->get_ip();
        if ( !$this->block_htaccess( $ip ) ) {
            $this->logerror( __FUNCTION__ . 'returned false, please check permission.' );
        } 
        return $error;
    }

    function disable_methods( $methods ) {
        $options = $this->get_options();
        if ( isset( $options['disable_builtin_methods']) ) {
            foreach ($options['builtin_methods'] as $key => $value) {
                if ($value == 0) {
                    unset( $methods[$key] );
                } 
            }
            return $methods;
        }
        return $methods;
    }

    function copy_xmlrpc_methods() {
        include_once(ABSPATH . WPINC . '/class-IXR.php');
        include_once(ABSPATH . WPINC . '/class-wp-xmlrpc-server.php');
        $wp_xmlrpc_server = new wp_xmlrpc_server;
        $methods = array();
        foreach ($wp_xmlrpc_server->methods as $key => $value) {
            $methods[$key] = 1;
        }
        $options = $this->get_options();
        $options['builtin_methods'] = $methods;
        update_option( "{$this->prefix}_options",  $options);
    }    

    function logerror( $error ) {
        $options = $this->get_options();
        if ( isset( $options['debug'] ) ) {
            $errors = $this->get_errors();
            $errors[] = current_time( 'mysql' ) . ': ' . $error;
            update_option( "{$this->prefix}_errors", $errors );
        }
    }
     
    function get_ip() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }
     
    function block_htaccess( $ip ) {
        $file = $this->htaccess;

        $content = file_get_contents( $file );
        $rule = "deny from $ip";

        $match = "/(?<=# BEGIN $this->marker)(.*)(?=allow from all)/s";

        if ( !preg_match_all($match , $content, $matches) ) {
            $this->logerror( 'There was a problem with preg_match_all to extrect your htaccess rules.');
            return false;
        }

        $replace = $matches[0][0] . PHP_EOL . $rule . PHP_EOL;
        $new = preg_replace($match, $replace, $content);

        if ( $new !== null ) {
            if ( file_put_contents( $file , $new) !== false ) {
                $this->logerror( "Blocked access attempt from $ip.");
                return true;
            } else {
                $this>logerror( 'The was an error saving htaccess file.');
                return false;
            }

        } else {
            $this->logerror( 'There was a problem with preg_replace.');
            return false;
        }
    }

    function get_options() {
        return get_option( "{$this->prefix}_options" );
    }

    function get_errors() {
        return get_option( "{$this->prefix}_errors" );
    } 

}


$axab = axab::get_instance();


?>