<?php
/**
 * Uninstall routine for Formidable Forms State & ZIP Code Blocker
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete all options created by the plugin
delete_option('ffb_approved_states');
delete_option('ffb_approved_zip_codes');
delete_option('ffb_block_non_us');
delete_option('ffb_rate_limit_requests');
delete_option('ffb_rate_limit_time');
delete_option('ffb_api_key');
delete_option('ffb_blocked_ips');

// Clear any session data that might have been set
if (session_id()) {
    session_destroy();
}
