<?php
/**
 * AQM Formidable Forms Spam Blocker - handle_save_settings method
 * 
 * This file contains only the handle_save_settings method.
 * Copy and paste this directly into the FormidableFormsBlocker class.
 */

/**
 * Process settings form submission via admin-post.php
 */
public function handle_save_settings() {
    // Verify capabilities
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized access');
    }
    
    // Verify nonce
    if (!isset($_POST['ffb_nonce']) || !wp_verify_nonce($_POST['ffb_nonce'], 'ffb_save_settings')) {
        wp_die('Security check failed. Please refresh the page and try again.');
    }
    
    // Get redirect URL
    $redirect_url = isset($_POST['redirect_to']) ? esc_url_raw($_POST['redirect_to']) : admin_url('admin.php?page=ff-spam-blocker');
    
    // Save settings
    // Save API key
    if (isset($_POST['ffb_api_key'])) {
        $api_key = sanitize_text_field($_POST['ffb_api_key']);
        update_option('ffb_api_key', $api_key);
    }
    
    // Save approved countries
    if (isset($_POST['ffb_approved_countries'])) {
        $countries = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_countries']));
        $countries = array_map('trim', $countries);
        $countries = array_filter($countries);
        update_option('ffb_approved_countries', $countries);
    } else {
        update_option('ffb_approved_countries', array());
    }
    
    // Save approved states
    if (isset($_POST['ffb_approved_states'])) {
        $states = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_states']));
        $states = array_map('trim', $states);
        $states = array_filter($states);
        update_option('ffb_approved_states', $states);
    } else {
        update_option('ffb_approved_states', array());
    }
    
    // Save approved ZIP codes
    if (isset($_POST['ffb_approved_zip_codes'])) {
        $zip_codes = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_zip_codes']));
        $zip_codes = array_map('trim', $zip_codes);
        $zip_codes = array_filter($zip_codes);
        update_option('ffb_approved_zip_codes', $zip_codes);
    } else {
        update_option('ffb_approved_zip_codes', array());
    }
    
    // Save blocked message
    if (isset($_POST['ffb_blocked_message'])) {
        update_option('ffb_blocked_message', wp_kses_post($_POST['ffb_blocked_message']));
    }
    
    // Save IP whitelist
    if (isset($_POST['ffb_ip_whitelist'])) {
        $whitelist = explode("\n", $_POST['ffb_ip_whitelist']);
        $whitelist = array_map('trim', $whitelist);
        $whitelist = array_filter($whitelist);
        update_option('ffb_ip_whitelist', $whitelist);
    }
    
    // Save all forms selection
    update_option('ffb_block_all_forms', isset($_POST['ffb_block_all_forms']) ? '1' : '0');
    
    // Save specific forms
    if (isset($_POST['ffb_specific_forms'])) {
        update_option('ffb_specific_forms', $_POST['ffb_specific_forms']);
    } else {
        update_option('ffb_specific_forms', array());
    }
    
    // Save debug mode
    update_option('ffb_debug_mode', isset($_POST['ffb_debug_mode']) ? '1' : '0');
    
    // Save disable geolocation
    update_option('ffb_disable_geolocation', isset($_POST['ffb_disable_geolocation']) ? '1' : '0');
    
    // Save log access attempts
    update_option('ffb_log_access', isset($_POST['ffb_log_access']) ? '1' : '0');
    
    // Log settings update
    error_log('FFB Debug: Settings updated via admin-post.php');
    
    // Set transient to show success message
    set_transient('ffb_settings_saved', true, 30);
    
    // Redirect back to settings page
    wp_redirect($redirect_url);
    exit;
}
