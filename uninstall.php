<?php
//if uninstall not called from WordPress exit
if ( !defined( 'WP_UNINSTALL_PLUGIN' ) ) 
    exit();

$content = file_get_contents( $this->htaccess );
$match = "/# BEGIN " . $this->marker . ".*# END " . $this->marker . "/s";
@$new = preg_replace( $match, "", $content);
if ($new !== null) {
	file_put_contents( $this->htaccess, $new);
}

delete_option( "{$this->prefix}_options" );
delete_option( "{$this->prefix}_errors" );