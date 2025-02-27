<?php
/**
 * Plugin Name: AQM Formidable Forms Spam Blocker
 * Plugin URI: https://aqmarketing.com
 * Description: Block form submissions from specific countries, states, and zip codes.
 * Version: 1.7.0
 * Author: AQMarketing
 * Author URI: https://aqmarketing.com
 * Text Domain: aqm-formidable-spam-blocker
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

// Include the updater class
require_once plugin_dir_path(__FILE__) . 'plugin-updater.php';

// Initialize the updater
function aqm_form_security_updater() {
    // Only run in admin
    if (!is_admin()) {
        return;
    }
    
    $updater = new AQM_Plugin_Updater(
        __FILE__,
        'JustCasey76',
        'aqm-plugins'
    );
}
add_action('init', 'aqm_form_security_updater');

class FormidableFormsBlocker {
    private $approved_states;
    private $approved_zip_codes = ['10001', '90001', '73301']; // Add allowed ZIPs here
    private $api_key = ''; // API key for ipapi.com - set in admin settings
    private $rate_limit_time = 10; // Time frame in seconds
    private $rate_limit_requests = 3; // Max requests per IP in timeframe
    private $blocked_ips = []; // IPs to block for testing
    private $log_enabled = true; // Whether to log access attempts
    private $hide_forms = true; // Whether to hide forms for blocked IPs

    public function __construct() {
        // Load settings from options
        $this->approved_states = get_option('ffb_approved_states', ['CA', 'NY', 'TX']);
        if (!is_array($this->approved_states)) {
            $this->approved_states = explode(',', $this->approved_states);
            $this->approved_states = array_map('trim', $this->approved_states);
        }
        
        $saved_zip_codes = get_option('ffb_approved_zip_codes', $this->approved_zip_codes);
        if (!is_array($saved_zip_codes)) {
            $saved_zip_codes = explode(',', $saved_zip_codes);
            $saved_zip_codes = array_map('trim', $saved_zip_codes);
        }
        $this->approved_zip_codes = $saved_zip_codes;
        
        $this->api_key = get_option('ffb_api_key', $this->api_key);
        $this->rate_limit_time = get_option('ffb_rate_limit_time', $this->rate_limit_time);
        $this->rate_limit_requests = get_option('ffb_rate_limit_requests', $this->rate_limit_requests);
        $this->log_enabled = get_option('ffb_log_enabled', $this->log_enabled);
        $this->hide_forms = get_option('ffb_hide_forms', true);
        
        // Load blocked IPs for testing
        $blocked_ips = get_option('ffb_blocked_ips', []);
        if (!is_array($blocked_ips)) {
            $blocked_ips = explode(',', $blocked_ips);
            $blocked_ips = array_map('trim', $blocked_ips);
        }
        $this->blocked_ips = $blocked_ips;
        
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_filter('frm_validate_entry', [$this, 'validate_form_submission'], 10, 2);
        add_action('init', [$this, 'start_session']);
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('the_content', [$this, 'hide_forms_for_disallowed_ips']);
        
        // Add AJAX handler for API key testing
        add_action('wp_ajax_ffb_test_api_key', [$this, 'ajax_test_api_key']);
        
        // Add AJAX handlers for IP management
        add_action('wp_ajax_ffb_search_ip', [$this, 'ajax_search_ip']);
        add_action('wp_ajax_ffb_delete_ip', [$this, 'ajax_delete_ip']);
        add_action('wp_ajax_ffb_clear_cache', [$this, 'ajax_clear_cache']);
    }

    public function enqueue_scripts() {
        wp_enqueue_script('ffb-geo-blocker', plugin_dir_url(__FILE__) . 'geo-blocker.js', ['jquery'], '1.7.0', true);
        wp_enqueue_style('ffb-styles', plugin_dir_url(__FILE__) . 'style.css', [], '1.7.0');
        
        // Make sure approved states are properly formatted
        $approved_states = $this->approved_states;
        if (!is_array($approved_states)) {
            $approved_states = explode(',', $approved_states);
        }
        
        // Clean up each state code
        $approved_states = array_map(function($state) {
            return trim(strtoupper($state));
        }, $approved_states);
        
        // Debug log
        error_log('FFB: Passing approved states to JS: ' . implode(',', $approved_states));
        
        wp_localize_script('ffb-geo-blocker', 'ffbGeoBlocker', [
            'api_url' => 'https://api.ipapi.com/api/',
            'api_key' => get_option('ffb_api_key', $this->api_key),
            'approved_states' => $approved_states,
            'approved_zip_codes' => $this->approved_zip_codes,
            'block_non_us' => get_option('ffb_block_non_us', '1') === '1'
        ]);
    }

    public function start_session() {
        if (!session_id()) {
            session_start();
        }
    }

    public function validate_form_submission($errors, $values) {
        $user_ip = $_SERVER['REMOTE_ADDR'];
        $form_id = isset($values['form_id']) ? $values['form_id'] : '';
        
        // Check if IP is in the blocked list for testing
        if (in_array($user_ip, $this->blocked_ips)) {
            $errors['general'] = 'Your IP address is currently blocked for testing purposes.';
            $this->log_access_attempt($user_ip, 'blocked', 'Testing block', $form_id);
            return $errors;
        }
        
        // Rate limiting check
        if (!$this->check_rate_limit($user_ip)) {
            $errors['general'] = 'Too many submissions. Please try again later.';
            $this->log_access_attempt($user_ip, 'rate_limit', 'Rate limit exceeded', $form_id);
            return $errors;
        }
        
        // Get geo data from IP
        $geo_data = $this->get_geo_data();
        
        // Check for API errors
        if (!$geo_data) {
            error_log('IPAPI Error: Unable to retrieve geo data');
            // Allow submission if we can't get geo data
            $this->log_access_attempt($user_ip, 'allowed', 'API error: Unable to retrieve geo data', $form_id);
            return $errors;
        }
        
        // Check if we should block non-US IPs
        if (get_option('ffb_block_non_us', '1') === '1') {
            if ($geo_data && isset($geo_data['country_code']) && $geo_data['country_code'] !== 'US') {
                $errors['general'] = 'Only users from the United States can submit this form.';
                $this->log_access_attempt($user_ip, 'blocked', 'Non-US IP: ' . $geo_data['country_code'], $form_id);
                return $errors;
            }
        }
        
        // Check state - only if we have approved states configured
        if (!empty($this->approved_states)) {
            // Make sure approved_states is an array of trimmed values
            $approved_states = array_map('trim', $this->approved_states);
            
            if ($geo_data && (isset($geo_data['region']) || isset($geo_data['region_code']))) {
                $region_code = trim($geo_data['region'] ?? $geo_data['region_code']);
                
                // Debug log
                error_log('Checking state: ' . $region_code . ' against approved states: ' . implode(',', $approved_states));
                
                if (!in_array($region_code, $approved_states)) {
                    $errors['general'] = 'Submissions are only allowed from specific states.';
                    $this->log_access_attempt($user_ip, 'blocked', 'Disallowed state: ' . $region_code, $form_id);
                    return $errors;
                }
            }
        }

        // Check ZIP code if provided in the form - only if we have approved ZIP codes configured
        if (!empty($this->approved_zip_codes)) {
            // Look for common field names that might contain ZIP codes
            $zip_field_names = ['zip', 'zipcode', 'zip_code', 'postal', 'postal_code', 'postcode'];
            $zip_code = null;
            
            foreach ($zip_field_names as $field_name) {
                if (isset($values[$field_name]) && !empty($values[$field_name])) {
                    $zip_code = $values[$field_name];
                    break;
                }
            }
            
            // If we found a ZIP code, validate it
            if ($zip_code) {
                // Clean the ZIP code (remove spaces, dashes, etc.)
                $zip_code = preg_replace('/[^0-9]/', '', $zip_code);
                
                // Get just the first 5 digits for US ZIP codes
                if (strlen($zip_code) > 5) {
                    $zip_code = substr($zip_code, 0, 5);
                }
                
                if (!in_array($zip_code, $this->approved_zip_codes)) {
                    $errors['zip'] = 'Submissions are only allowed from specific ZIP codes.';
                    $this->log_access_attempt($user_ip, 'blocked', 'Disallowed ZIP code: ' . $zip_code, $form_id);
                    return $errors;
                }
            }
        }

        // If we got here, the submission is allowed
        $this->log_access_attempt($user_ip, 'allowed', 'Submission allowed', $form_id);
        return $errors;
    }

    private function check_rate_limit($ip) {
        if (!isset($_SESSION['rate_limit'][$ip])) {
            $_SESSION['rate_limit'][$ip] = [
                'count' => 1,
                'time' => time()
            ];
            return true;
        }

        $rate_data = $_SESSION['rate_limit'][$ip];
        $time_diff = time() - $rate_data['time'];

        if ($time_diff > $this->rate_limit_time) {
            // Reset if outside time window
            $_SESSION['rate_limit'][$ip] = [
                'count' => 1,
                'time' => time()
            ];
            return true;
        }

        if ($rate_data['count'] >= $this->rate_limit_requests) {
            return false; // Rate limit exceeded
        }

        // Increment count
        $_SESSION['rate_limit'][$ip]['count']++;
        return true;
    }

    private function log_access_attempt($ip, $status, $reason, $form_id = '') {
        if (!$this->log_enabled) {
            return;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'ffb_access_log';
        
        // Get geo data for the IP
        $geo_data = $this->get_geo_data();
        
        $country = isset($geo_data['country_name']) ? $geo_data['country_name'] : '';
        $region = isset($geo_data['region']) ? $geo_data['region'] : '';
        $region_code = isset($geo_data['region_code']) ? $geo_data['region_code'] : '';
        $zip = isset($geo_data['zip']) ? $geo_data['zip'] : '';
        
        $wpdb->insert($table_name, [
            'time' => current_time('mysql'),
            'ip_address' => $ip,
            'country' => $country,
            'region' => $region_code ? $region_code : $region,
            'zip_code' => $zip,
            'form_id' => $form_id,
            'status' => $status,
            'reason' => $reason
        ]);
    }

    public function hide_forms_for_disallowed_ips($content) {
        $user_ip = $_SERVER['REMOTE_ADDR'];
        
        // If hide_forms is disabled, don't modify the content
        if (!$this->hide_forms) {
            return $content;
        }
        
        // Check if IP is in the blocked list for testing
        if (in_array($user_ip, $this->blocked_ips)) {
            // Replace any Formidable Forms with a message
            $content = preg_replace('/\[formidable.*?\]/', '<p class="ffb-blocked-message">Your IP address is currently blocked for testing purposes.</p>', $content);
            return $content;
        }
        
        $geo_data = $this->get_geo_data();
        
        // DEBUG: Log geo data for troubleshooting
        error_log('FFB Debug - IP: ' . $user_ip);
        error_log('FFB Debug - Geo Data: ' . print_r($geo_data, true));
        error_log('FFB Debug - Approved States: ' . print_r($this->approved_states, true));
        
        // Check if we should block non-US IPs
        if (get_option('ffb_block_non_us', '1') === '1') {
            if ($geo_data && isset($geo_data['country_code']) && $geo_data['country_code'] !== 'US') {
                // Replace any Formidable Forms with a message
                $content = preg_replace('/\[formidable.*?\]/', '<p class="ffb-blocked-message">Forms are not available in your country.</p>', $content);
                return $content;
            }
        }
        
        // Only check state if we have approved states configured
        if (!empty($this->approved_states) && $geo_data && (isset($geo_data['region']) || isset($geo_data['region_code']))) {
            // DEBUG: Log state comparison
            error_log('FFB Debug - User Region: ' . ($geo_data['region'] ?? $geo_data['region_code']));
            error_log('FFB Debug - Region in approved states: ' . (in_array($geo_data['region'] ?? $geo_data['region_code'], $this->approved_states) ? 'YES' : 'NO'));
            
            if (!in_array($geo_data['region'] ?? $geo_data['region_code'], $this->approved_states)) {
                // Replace any Formidable Forms with a message
                $content = preg_replace('/\[formidable.*?\]/', '<p class="ffb-blocked-message">Forms are not available in your state.</p>', $content);
                return $content;
            }
        }
        
        // Check ZIP code if we have approved ZIP codes configured
        if (!empty($this->approved_zip_codes) && $geo_data && isset($geo_data['zip'])) {
            $postal_code = preg_replace('/[^0-9]/', '', $geo_data['zip']);
            
            // Get just the first 5 digits for US ZIP codes
            if (strlen($postal_code) > 5) {
                $postal_code = substr($postal_code, 0, 5);
            }
            
            // DEBUG: Log ZIP code comparison
            error_log('FFB Debug - User Postal Code: ' . $postal_code);
            error_log('FFB Debug - Postal in approved codes: ' . (in_array($postal_code, $this->approved_zip_codes) ? 'YES' : 'NO'));
            
            if (!in_array($postal_code, $this->approved_zip_codes)) {
                // Replace any Formidable Forms with a message
                $content = preg_replace('/\[formidable.*?\]/', '<p class="ffb-blocked-message">Forms are not available in your ZIP code.</p>', $content);
                return $content;
            }
        }

        return $content;
    }

    public function admin_menu() {
        // Add main menu
        add_menu_page(
            'AQM Form Security', 
            'AQM Form Security', 
            'manage_options', 
            'ffb-settings', 
            [$this, 'settings_page'], 
            'dashicons-shield',
            30
        );
        
        // Add submenus
        add_submenu_page(
            'ffb-settings',
            'AQM Form Security Settings',
            'Settings',
            'manage_options',
            'ffb-settings'
        );
        
        add_submenu_page(
            'ffb-settings',
            'AQM Form Security Log', 
            'Access Log', 
            'manage_options', 
            'ffb-access-log', 
            [$this, 'access_log_page']
        );
    }

    public function register_settings() {
        register_setting('ffb_settings_group', 'ffb_approved_states', [
            'sanitize_callback' => [$this, 'sanitize_comma_list']
        ]);
        register_setting('ffb_settings_group', 'ffb_approved_zip_codes', [
            'sanitize_callback' => [$this, 'sanitize_comma_list']
        ]);
        register_setting('ffb_settings_group', 'ffb_block_non_us');
        register_setting('ffb_settings_group', 'ffb_rate_limit_requests');
        register_setting('ffb_settings_group', 'ffb_rate_limit_time');
        register_setting('ffb_settings_group', 'ffb_api_key', [
            'sanitize_callback' => [$this, 'validate_api_key']
        ]);
        register_setting('ffb_settings_group', 'ffb_blocked_ips', [
            'sanitize_callback' => [$this, 'sanitize_comma_list']
        ]);
        register_setting('ffb_settings_group', 'ffb_log_enabled');
        register_setting('ffb_settings_group', 'ffb_hide_forms');
    }
    
    /**
     * Sanitize a comma-separated list into an array of trimmed values
     */
    public function sanitize_comma_list($input) {
        if (empty($input)) {
            return [];
        }
        
        if (is_array($input)) {
            return array_map('trim', $input);
        }
        
        $values = explode(',', $input);
        return array_map('trim', $values);
    }
    
    /**
     * Validate the API key by making a test request
     */
    public function validate_api_key($key) {
        // Always return the key without validation
        return $key;
    }

    /**
     * Check API key subscription status
     * 
     * @param string $api_key The API key to check
     * @return array Status information with 'valid', 'plan', and 'message' keys
     */
    public function check_api_subscription($api_key) {
        // Always return valid result without actual validation
        return [
            'valid' => true,
            'plan' => 'business_pro_or_higher',
            'message' => 'API key validation has been disabled'
        ];
    }

    /**
     * AJAX handler for testing API key and subscription status
     */
    public function ajax_test_api_key() {
        // Check nonce
        check_ajax_referer('ffb_ajax_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
            return;
        }
        
        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';
        
        if (empty($api_key)) {
            wp_send_json_error(['message' => 'API key is required']);
            return;
        }
        
        // Test the API key with a known IP (Google's DNS)
        $test_ip = '8.8.8.8';
        $geo_data = wp_remote_get("https://api.ipapi.com/api/{$test_ip}?access_key={$api_key}");
        
        if (is_wp_error($geo_data)) {
            $error_message = 'API Error: ' . $geo_data->get_error_message();
            set_transient('ffb_api_key_error', $error_message, 60);
            wp_send_json_error(['message' => $error_message]);
            return;
        }
        
        $http_code = wp_remote_retrieve_response_code($geo_data);
        $body = wp_remote_retrieve_body($geo_data);
        $geo_data = json_decode($body, true);
        
        // Check if JSON decode failed
        if ($geo_data === null) {
            $error_message = 'Invalid response from API. Please check your API key.';
            set_transient('ffb_api_key_error', $error_message, 60);
            wp_send_json_error(['message' => $error_message, 'raw_response' => $body]);
            return;
        }
        
        // Check for API error messages
        if (isset($geo_data['success']) && $geo_data['success'] === false) {
            $error_info = isset($geo_data['error']['info']) ? $geo_data['error']['info'] : 'Unknown API error';
            $error_code = isset($geo_data['error']['code']) ? $geo_data['error']['code'] : 'Unknown';
            $error_type = isset($geo_data['error']['type']) ? $geo_data['error']['type'] : 'Unknown';
            
            $error_message = "API Error: {$error_info} (Code: {$error_code}, Type: {$error_type})";
            set_transient('ffb_api_key_error', $error_message, 60);
            wp_send_json_error(['message' => $error_message, 'error_details' => $geo_data['error']]);
            return;
        }
        
        // Check if we have location data
        if (!isset($geo_data['country_code']) || !isset($geo_data['region'])) {
            $error_message = 'API key is valid but did not return location data. Please check your account limits.';
            set_transient('ffb_api_key_error', $error_message, 60);
            wp_send_json_error(['message' => $error_message, 'response' => $geo_data]);
            return;
        }
        
        // API key is valid
        $success_message = 'API key is valid! Test IP: ' . $test_ip . ', Location: ' . $geo_data['country_name'] . ', ' . $geo_data['region'];
        set_transient('ffb_api_key_success', $success_message, 60);
        wp_send_json_success(['message' => $success_message]);
    }

    /**
     * AJAX handler for IP search
     */
    public function ajax_search_ip() {
        // Check nonce
        check_ajax_referer('ffb_ajax_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
            return;
        }
        
        $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
        
        if (empty($ip)) {
            wp_send_json_error(['message' => 'IP address is required']);
            return;
        }
        
        // Search for the IP in the cache
        $geo_data = $this->search_ip_cache($ip);
        
        if ($geo_data) {
            wp_send_json_success([
                'message' => 'IP found in cache',
                'data' => $geo_data
            ]);
        } else {
            // Try to fetch from API
            $geo_data = $this->get_geo_data($ip);
            
            if ($geo_data) {
                wp_send_json_success([
                    'message' => 'IP data fetched from API',
                    'data' => $geo_data
                ]);
            } else {
                wp_send_json_error(['message' => 'Unable to retrieve data for this IP']);
            }
        }
    }
    
    /**
     * AJAX handler for deleting an IP from cache
     */
    public function ajax_delete_ip() {
        // Check nonce
        check_ajax_referer('ffb_ajax_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
            return;
        }
        
        $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
        
        if (empty($ip)) {
            wp_send_json_error(['message' => 'IP address is required']);
            return;
        }
        
        $result = $this->delete_ip_from_cache($ip);
        
        if ($result) {
            wp_send_json_success(['message' => 'IP removed from cache']);
        } else {
            wp_send_json_error(['message' => 'IP not found in cache']);
        }
    }
    
    /**
     * AJAX handler for clearing the entire IP cache
     */
    public function ajax_clear_cache() {
        // Check nonce
        check_ajax_referer('ffb_ajax_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
            return;
        }
        
        $result = $this->clear_ip_cache();
        
        if ($result) {
            wp_send_json_success(['message' => 'IP cache cleared']);
        } else {
            wp_send_json_error(['message' => 'Failed to clear IP cache']);
        }
    }

    /**
     * Test function to check API response format for a specific IP
     */
    public function check_api_response_format() {
        $user_ip = $_SERVER['REMOTE_ADDR'];
        $api_key = get_option('ffb_api_key', $this->api_key);
        
        error_log('IPAPI Test - User IP: ' . $user_ip);
        error_log('IPAPI Test - API Key: ' . (empty($api_key) ? 'Empty' : 'Present (not shown for security)'));
        
        // Log the API URL we're calling
        $api_url = "https://api.ipapi.com/api/{$user_ip}?access_key={$api_key}";
        error_log('IPAPI Test - API URL: ' . preg_replace('/access_key=([^&]+)/', 'access_key=HIDDEN', $api_url));
        
        // Make a direct API call to see the raw response
        $geo_data = wp_remote_get($api_url);
        
        if (is_wp_error($geo_data)) {
            error_log('IPAPI Error: ' . $geo_data->get_error_message());
            return false;
        }
        
        // Log the HTTP response code
        $http_code = wp_remote_retrieve_response_code($geo_data);
        error_log('IPAPI Test - HTTP Response Code: ' . $http_code);
        
        $body = wp_remote_retrieve_body($geo_data);
        error_log('IPAPI Test - Raw Response: ' . $body);
        
        $geo_data = json_decode($body, true);
        
        // Check if JSON decode failed
        if ($geo_data === null) {
            error_log('IPAPI Test - JSON Decode Failed. Raw response: ' . $body);
            return false;
        }
        
        // Log the complete API response
        error_log('IPAPI Complete Response for IP ' . $user_ip . ': ' . print_r($geo_data, true));
        
        // Check for API error messages
        if (isset($geo_data['success']) && $geo_data['success'] === false) {
            error_log('IPAPI Error - Code: ' . ($geo_data['error']['code'] ?? 'Unknown'));
            error_log('IPAPI Error - Type: ' . ($geo_data['error']['type'] ?? 'Unknown'));
            error_log('IPAPI Error - Info: ' . ($geo_data['error']['info'] ?? 'Unknown'));
        }
        
        // Check specifically for region/state information
        if (isset($geo_data['region_code'])) {
            error_log('IPAPI Region Code: ' . $geo_data['region_code']);
        }
        
        if (isset($geo_data['region_name'])) {
            error_log('IPAPI Region Name: ' . $geo_data['region_name']);
        }
        
        if (isset($geo_data['region'])) {
            error_log('IPAPI Region: ' . $geo_data['region']);
        }
        
        // Check for ZIP/postal code
        if (isset($geo_data['zip'])) {
            error_log('IPAPI ZIP Code: ' . $geo_data['zip']);
        }
        
        if (isset($geo_data['postal'])) {
            error_log('IPAPI Postal Code: ' . $geo_data['postal']);
        }
        
        // Create a standardized response for display
        $standardized_data = [
            'country' => isset($geo_data['country_name']) ? $geo_data['country_name'] . ' (' . $geo_data['country_code'] . ')' : 'Not available (N/A)',
            'region' => isset($geo_data['region_name']) ? $geo_data['region_name'] : (isset($geo_data['region']) ? $geo_data['region'] : 'Not available'),
            'region_code' => isset($geo_data['region_code']) ? $geo_data['region_code'] : 'Not available',
            'zip' => isset($geo_data['zip']) ? $geo_data['zip'] : (isset($geo_data['postal']) ? $geo_data['postal'] : 'Not available')
        ];
        
        return $standardized_data;
    }

    public function settings_page() {
        // Handle the case where approved_zip_codes is stored in the object but not in options
        $zip_codes = get_option('ffb_approved_zip_codes', $this->approved_zip_codes);
        if (!is_array($zip_codes)) {
            $zip_codes = explode(',', $zip_codes);
            $zip_codes = array_map('trim', $zip_codes);
        }
        
        // Get admin's current IP
        $admin_ip = $_SERVER['REMOTE_ADDR'];
        $is_admin_ip_blocked = in_array($admin_ip, $this->blocked_ips);
        
        // Handle form submission for blocking/unblocking admin IP
        if (isset($_POST['ffb_toggle_admin_ip']) && check_admin_referer('ffb_toggle_admin_ip_nonce')) {
            $block_admin_ip = isset($_POST['ffb_block_admin_ip']) ? true : false;
            
            if ($block_admin_ip && !$is_admin_ip_blocked) {
                // Add admin IP to blocked list
                $this->blocked_ips[] = $admin_ip;
                update_option('ffb_blocked_ips', implode(',', $this->blocked_ips));
                $is_admin_ip_blocked = true;
                // Log the admin IP block for testing
                $this->log_access_attempt($admin_ip, 'admin_action', 'Admin IP added to block list for testing', '');
                echo '<div class="notice notice-success"><p>Your IP address has been added to the blocked list for testing.</p></div>';
            } elseif (!$block_admin_ip && $is_admin_ip_blocked) {
                // Remove admin IP from blocked list
                $this->blocked_ips = array_diff($this->blocked_ips, [$admin_ip]);
                update_option('ffb_blocked_ips', implode(',', $this->blocked_ips));
                $is_admin_ip_blocked = false;
                // Log the admin IP unblock
                $this->log_access_attempt($admin_ip, 'admin_action', 'Admin IP removed from block list', '');
                echo '<div class="notice notice-success"><p>Your IP address has been removed from the blocked list.</p></div>';
            }
        }
        ?>
        <style>
            .description.error {
                color: #dc3232;
                font-weight: bold;
                margin-top: 5px;
            }
            .description.success {
                color: #46b450;
                font-weight: bold;
                margin-top: 5px;
            }
            .api-key-container {
                display: flex;
                align-items: center;
            }
        </style>
        <div class="wrap ffb-settings-page">
            <h1>AQM Form Security Settings</h1>
            <p>Configure which states and ZIP codes are allowed to submit Formidable Forms on your site.</p>
            
            <!-- Admin IP Testing Section -->
            <div class="postbox">
                <div class="inside">
                    <h2>Test Blocking with Your IP</h2>
                    <p>Your current IP address is: <strong><?php echo esc_html($admin_ip); ?></strong></p>
                    <form method="post" action="">
                        <?php wp_nonce_field('ffb_toggle_admin_ip_nonce'); ?>
                        <label>
                            <input type="checkbox" name="ffb_block_admin_ip" <?php checked($is_admin_ip_blocked); ?> />
                            Block my IP address for testing purposes
                        </label>
                        <p class="description">
                            This allows you to test how the form blocking appears to blocked users. 
                            <?php if ($is_admin_ip_blocked): ?>
                                <strong>Warning: Your IP is currently blocked. You will not be able to submit any Formidable Forms.</strong>
                            <?php endif; ?>
                        </p>
                        <p>
                            <input type="submit" name="ffb_toggle_admin_ip" class="button button-secondary" value="Update IP Block Status" />
                        </p>
                    </form>
                    
                    <!-- API Response Test Button -->
                    <h3>API Response Format Test</h3>
                    <p>Use this to check how the API is identifying your location:</p>
                    <form method="post" action="">
                        <?php wp_nonce_field('ffb_api_test_nonce'); ?>
                        <p>
                            <input type="submit" name="ffb_test_api_response" class="button button-secondary" value="Test API Response Format" />
                        </p>
                    </form>
                    <?php
                    // Handle API test button click
                    if (isset($_POST['ffb_test_api_response']) && check_admin_referer('ffb_api_test_nonce')) {
                        $api_response = $this->check_api_response_format();
                        if ($api_response) {
                            echo '<div class="notice notice-info"><p>API test completed. Check your server error log for detailed information.</p>';
                            echo '<p>Your location according to the API:</p>';
                            echo '<ul>';
                            echo '<li><strong>Country:</strong> ' . (isset($api_response['country']) ? esc_html($api_response['country']) : 'Not available') . '</li>';
                            echo '<li><strong>Region:</strong> ' . (isset($api_response['region']) ? esc_html($api_response['region']) : 'Not available') . '</li>';
                            echo '<li><strong>Region Code:</strong> ' . (isset($api_response['region_code']) ? esc_html($api_response['region_code']) : 'Not available') . '</li>';
                            echo '<li><strong>ZIP/Postal Code:</strong> ' . (isset($api_response['zip']) ? esc_html($api_response['zip']) : 'Not available') . '</li>';
                            echo '</ul>';
                            echo '</div>';
                        } else {
                            echo '<div class="notice notice-error"><p>API test failed. Check your server error log for more information.</p></div>';
                        }
                    }
                    ?>
                </div>
            </div>
            
            <form method="post" action="options.php">
                <?php settings_fields('ffb_settings_group'); ?>
                <?php do_settings_sections('ffb-settings'); ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Approved States</th>
                        <td>
                            <?php 
                                $approved_states = get_option('ffb_approved_states', ['CA', 'NY', 'TX']);
                                if (!is_array($approved_states)) {
                                    $approved_states = explode(',', $approved_states);
                                    $approved_states = array_map('trim', $approved_states);
                                }
                            ?>
                            <input type="text" name="ffb_approved_states" value="<?php echo esc_attr(implode(',', $approved_states)); ?>" />
                            <p class="description">Enter comma-separated state codes (e.g., NY,CA,TX) to allow form submissions from these states.</p>
                            <p class="description"><strong>Note:</strong> After changing approved states, please clear the IP cache below to ensure changes take effect immediately.</p>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Approved ZIP Codes</th>
                        <td>
                            <input type="text" name="ffb_approved_zip_codes" value="<?php echo esc_attr(implode(',', $zip_codes)); ?>" />
                            <p class="description">Enter comma-separated ZIP codes that are allowed to submit forms</p>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Block Non-US IPs</th>
                        <td>
                            <input type="checkbox" name="ffb_block_non_us" value="1" <?php checked(get_option('ffb_block_non_us', '1'), '1'); ?> />
                            <span>Block form submissions from outside the United States</span>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Rate Limiting</th>
                        <td>
                            <label>
                                <input type="number" name="ffb_rate_limit_requests" value="<?php echo esc_attr(get_option('ffb_rate_limit_requests', $this->rate_limit_requests)); ?>" min="1" max="100" style="width: 60px;" />
                                submissions per
                                <input type="number" name="ffb_rate_limit_time" value="<?php echo esc_attr(get_option('ffb_rate_limit_time', $this->rate_limit_time)); ?>" min="1" max="3600" style="width: 60px;" />
                                seconds per IP address
                            </label>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Blocked IPs</th>
                        <td>
                            <?php
                            $blocked_ips = get_option('ffb_blocked_ips', []);
                            if (is_array($blocked_ips)) {
                                $blocked_ips_value = implode(',', $blocked_ips);
                            } else {
                                $blocked_ips_value = $blocked_ips;
                            }
                            ?>
                            <input type="text" name="ffb_blocked_ips" value="<?php echo esc_attr($blocked_ips_value); ?>" />
                            <p class="description">Enter comma-separated IP addresses to block for testing</p>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Log Access Attempts</th>
                        <td>
                            <input type="checkbox" name="ffb_log_enabled" value="1" <?php checked(get_option('ffb_log_enabled', $this->log_enabled), '1'); ?> />
                            <span>Log all access attempts to the database</span>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">Hide Forms for Blocked IPs</th>
                        <td>
                            <input type="checkbox" name="ffb_hide_forms" value="1" <?php checked(get_option('ffb_hide_forms', true), '1'); ?> />
                            <span>Hide forms from users with blocked IPs instead of showing an error message</span>
                        </td>
                    </tr>
                </table>
                
                <h2>API Settings</h2>
                <p>This plugin uses the ipapi.com service to determine user location. You can replace the default API key with your own.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">API Key</th>
                        <td>
                            <?php 
                            $api_key = get_option('ffb_api_key', $this->api_key);
                            $masked_key = substr($api_key, 0, 4) . str_repeat('•', strlen($api_key) - 8) . substr($api_key, -4);
                            ?>
                            <div class="api-key-container" style="position: relative;">
                                <input type="password" id="ffb_api_key" name="ffb_api_key" value="<?php echo esc_attr($api_key); ?>" style="width: 300px;" />
                                <button type="button" id="toggle_api_key" class="button button-secondary" style="margin-left: 10px;">Show</button>
                                <button type="button" id="test_api_key" class="button button-secondary" style="margin-left: 10px;">Test API Key</button>
                            </div>
                            <p class="description">Get your API key from <a href="https://ipapi.com/" target="_blank">ipapi.com</a></p>
                            <?php if (get_transient('ffb_api_key_error')): ?>
                                <p class="description error"><?php echo get_transient('ffb_api_key_error'); ?></p>
                            <?php elseif (get_transient('ffb_api_key_success')): ?>
                                <p class="description success"><?php echo get_transient('ffb_api_key_success'); ?></p>
                            <?php endif; ?>
                            <script>
                            jQuery(document).ready(function($) {
                                $('#toggle_api_key').click(function() {
                                    var apiKeyField = $('#ffb_api_key');
                                    if (apiKeyField.attr('type') === 'password') {
                                        apiKeyField.attr('type', 'text');
                                        $(this).text('Hide');
                                    } else {
                                        apiKeyField.attr('type', 'password');
                                        $(this).text('Show');
                                    }
                                });
                                
                                $('#test_api_key').click(function() {
                                    var apiKey = $('#ffb_api_key').val();
                                    var resultContainer = $('.api-key-container').siblings('.description').last();
                                    
                                    // Show loading indicator
                                    if (resultContainer.hasClass('error') || resultContainer.hasClass('success')) {
                                        resultContainer.removeClass('error success').text('Testing API key...');
                                    } else {
                                        $('<p class="description">Testing API key...</p>').insertAfter($('.api-key-container').siblings('.description').last());
                                        resultContainer = $('.api-key-container').siblings('.description').last();
                                    }
                                    
                                    $.ajax({
                                        type: 'POST',
                                        url: '<?php echo admin_url('admin-ajax.php'); ?>',
                                        data: {
                                            action: 'ffb_test_api_key',
                                            api_key: apiKey,
                                            nonce: '<?php echo wp_create_nonce('ffb_test_api_key'); ?>'
                                        },
                                        success: function(response) {
                                            if (response.success) {
                                                resultContainer.removeClass('error').addClass('success')
                                                    .html('API key is valid! <strong>Plan: ' + response.data.plan + '</strong><br>' + response.data.message);
                                            } else {
                                                resultContainer.removeClass('success').addClass('error')
                                                    .text('API key error: ' + (response.data && response.data.error ? response.data.error : 'Unknown error'));
                                            }
                                        },
                                        error: function(xhr, status, error) {
                                            resultContainer.removeClass('success').addClass('error')
                                                .text('Error testing API key: ' + error);
                                        }
                                    });
                                });
                            });
                            </script>
                        </td>
                    </tr>
                </table>
                
                <h2>IP Cache Management</h2>
                <p>Manage the IP geolocation cache to reduce API calls.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">Cache Statistics</th>
                        <td>
                            <?php
                            $cached_data = get_option('ffb_ip_cache', []);
                            $cache_count = count($cached_data);
                            ?>
                            <div class="ffb-cache-stats">
                                <span class="ffb-cache-count"><?php echo $cache_count; ?></span>
                                <span class="ffb-cache-label">IP addresses currently cached</span>
                                <p>Caching IP geolocation data reduces API calls and improves form submission speed.</p>
                                <button type="button" id="ffb_clear_cache" class="button button-secondary">Clear All Cached IPs</button>
                            </div>
                            <script>
                            jQuery(document).ready(function($) {
                                $('#ffb_clear_cache').click(function() {
                                    if (confirm('Are you sure you want to clear all cached IP data? This will force the plugin to make new API calls for each IP.')) {
                                        $.ajax({
                                            type: 'POST',
                                            url: '<?php echo admin_url('admin-ajax.php'); ?>',
                                            data: {
                                                action: 'ffb_clear_cache',
                                                nonce: '<?php echo wp_create_nonce('ffb_ajax_nonce'); ?>'
                                            },
                                            success: function(response) {
                                                if (response.success) {
                                                    alert('IP cache cleared');
                                                    location.reload();
                                                } else {
                                                    alert('Error: ' + response.data.message);
                                                }
                                            }
                                        });
                                    }
                                });
                            });
                            </script>
                        </td>
                    </tr>
                </table>
                
                <h2>IP Search</h2>
                <p>Search for an IP address to view its geolocation data.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">IP Address</th>
                        <td>
                            <input type="text" id="ffb_ip_search" name="ffb_ip_search" value="" style="width: 300px;" />
                            <button type="button" id="ffb_search_ip" class="button button-secondary" style="margin-left: 10px;">Search</button>
                            <div id="ffb_ip_search_results"></div>
                            <script>
                            jQuery(document).ready(function($) {
                                $('#ffb_search_ip').click(function() {
                                    var ip = $('#ffb_ip_search').val();
                                    var resultContainer = $('#ffb_ip_search_results');
                                    
                                    // Show loading indicator
                                    resultContainer.html('<p>Loading...</p>');
                                    
                                    $.ajax({
                                        type: 'POST',
                                        url: '<?php echo admin_url('admin-ajax.php'); ?>',
                                        data: {
                                            action: 'ffb_search_ip',
                                            ip: ip,
                                            nonce: '<?php echo wp_create_nonce('ffb_ajax_nonce'); ?>'
                                        },
                                        success: function(response) {
                                            if (response.success) {
                                                var data = response.data;
                                                var html = '<div style="margin-top: 15px; padding: 15px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 3px;">';
                                                html += '<h3>IP Information: ' + ip + '</h3>';
                                                html += '<table class="widefat" style="margin-bottom: 15px;">';
                                                html += '<tr><td><strong>Country:</strong></td><td>' + (data.data.country_name || 'N/A') + ' (' + (data.data.country_code || 'N/A') + ')</td></tr>';
                                                html += '<tr><td><strong>Region:</strong></td><td>' + (data.data.region || 'N/A') + '</td></tr>';
                                                html += '<tr><td><strong>City:</strong></td><td>' + (data.data.city || 'N/A') + '</td></tr>';
                                                html += '<tr><td><strong>ZIP:</strong></td><td>' + (data.data.zip || 'N/A') + '</td></tr>';
                                                html += '<tr><td><strong>Latitude:</strong></td><td>' + (data.data.latitude || 'N/A') + '</td></tr>';
                                                html += '<tr><td><strong>Longitude:</strong></td><td>' + (data.data.longitude || 'N/A') + '</td></tr>';
                                                html += '</table>';
                                                
                                                // Add buttons for actions
                                                html += '<button type="button" class="button button-secondary ffb-delete-ip" data-ip="' + ip + '">Remove from Cache</button>';
                                                html += '<button type="button" class="button button-primary ffb-allow-ip" data-ip="' + ip + '" style="margin-left: 10px;">Allow this IP</button>';
                                                html += '<button type="button" class="button button-secondary ffb-block-ip" data-ip="' + ip + '" style="margin-left: 10px; background: #d63638; color: white; border-color: #d63638;">Block this IP</button>';
                                                html += '</div>';
                                                
                                                resultContainer.html(html);
                                                
                                                // Add event handlers for the buttons
                                                $('.ffb-delete-ip').click(function() {
                                                    var ip = $(this).data('ip');
                                                    if (confirm('Are you sure you want to remove this IP from the cache?')) {
                                                        $.ajax({
                                                            type: 'POST',
                                                            url: '<?php echo admin_url('admin-ajax.php'); ?>',
                                                            data: {
                                                                action: 'ffb_delete_ip',
                                                                ip: ip,
                                                                nonce: '<?php echo wp_create_nonce('ffb_ajax_nonce'); ?>'
                                                            },
                                                            success: function(response) {
                                                                if (response.success) {
                                                                    alert('IP removed from cache');
                                                                    $('#ffb_ip_search_results').html('');
                                                                } else {
                                                                    alert('Error: ' + response.data.message);
                                                                }
                                                            }
                                                        });
                                                    }
                                                });
                                                
                                                $('.ffb-block-ip').click(function() {
                                                    var ip = $(this).data('ip');
                                                    var blockedIps = $('#ffb_blocked_ips').val();
                                                    var blockedIpsArray = blockedIps ? blockedIps.split(',').map(function(item) { return item.trim(); }) : [];
                                                    
                                                    // Add the IP to blocked IPs if it's not already there
                                                    if (blockedIpsArray.indexOf(ip) === -1) {
                                                        blockedIpsArray.push(ip);
                                                        $('#ffb_blocked_ips').val(blockedIpsArray.join(', '));
                                                        alert('IP added to blocked list. Remember to save your settings!');
                                                    } else {
                                                        alert('This IP is already in the blocked list.');
                                                    }
                                                });
                                                
                                                $('.ffb-allow-ip').click(function() {
                                                    var ip = $(this).data('ip');
                                                    var blockedIps = $('#ffb_blocked_ips').val();
                                                    var blockedIpsArray = blockedIps.split(',').map(function(item) { return item.trim(); });
                                                    
                                                    // Remove the IP from blocked IPs if it's there
                                                    var index = blockedIpsArray.indexOf(ip);
                                                    if (index !== -1) {
                                                        blockedIpsArray.splice(index, 1);
                                                        $('#ffb_blocked_ips').val(blockedIpsArray.join(','));
                                                        alert('IP removed from blocked list. Remember to save your settings!');
                                                    } else {
                                                        alert('This IP is not in the blocked list.');
                                                    }
                                                });
                                            } else {
                                                resultContainer.html('<p>Error: ' + response.data.message + '</p>');
                                            }
                                        },
                                        error: function(xhr, status, error) {
                                            resultContainer.html('<p>Error: ' + error + '</p>');
                                        }
                                    });
                                });
                            });
                            </script>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button('Save Settings'); ?>
            </form>
        </div>
        <?php
    }

    public function access_log_page() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ffb_access_log';
        
        // Process bulk actions
        if (isset($_POST['clear_logs']) && check_admin_referer('ffb_clear_logs_nonce')) {
            $wpdb->query("TRUNCATE TABLE $table_name");
            echo '<div class="notice notice-success"><p>Access logs have been cleared.</p></div>';
        }
        
        // Get total count for pagination
        $total_items = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
        
        // Pagination settings
        $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($current_page - 1) * $per_page;
        
        // Filtering
        $where = '';
        $filter_status = isset($_GET['status']) ? sanitize_text_field($_GET['status']) : '';
        if ($filter_status) {
            $where .= $wpdb->prepare(" WHERE status = %s", $filter_status);
        }
        
        // Get log entries with pagination and filtering
        $query = "SELECT * FROM $table_name $where ORDER BY time DESC LIMIT $offset, $per_page";
        $results = $wpdb->get_results($query);
        
        // Get unique statuses for filter dropdown
        $statuses = $wpdb->get_col("SELECT DISTINCT status FROM $table_name");
        ?>
        <div class="wrap">
            <h1>AQM Form Security Access Log</h1>
            <p>View all access attempts to your site. This log shows which IPs were blocked or allowed, and why.</p>
            
            <!-- Filtering options -->
            <div class="tablenav top">
                <div class="alignleft actions">
                    <form method="get">
                        <input type="hidden" name="page" value="ffb-access-log">
                        <select name="status">
                            <option value="">All Statuses</option>
                            <?php foreach ($statuses as $status): ?>
                                <option value="<?php echo esc_attr($status); ?>" <?php selected($filter_status, $status); ?>>
                                    <?php echo esc_html(ucfirst($status)); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <input type="submit" class="button" value="Filter">
                    </form>
                </div>
                
                <!-- Clear logs button -->
                <div class="alignright">
                    <form method="post">
                        <?php wp_nonce_field('ffb_clear_logs_nonce'); ?>
                        <input type="submit" name="clear_logs" class="button button-secondary" value="Clear All Logs" onclick="return confirm('Are you sure you want to clear all logs? This cannot be undone.');">
                    </form>
                </div>
                <br class="clear">
            </div>
            
            <!-- Log table -->
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th>Region</th>
                        <th>ZIP Code</th>
                        <th>Form ID</th>
                        <th>Status</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($results)): ?>
                        <tr>
                            <td colspan="8">No log entries found.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($results as $result): ?>
                            <tr>
                                <td><?php echo esc_html($result->time); ?></td>
                                <td><?php echo esc_html($result->ip_address); ?></td>
                                <td><?php echo esc_html($result->country); ?></td>
                                <td><?php echo esc_html($result->region); ?></td>
                                <td><?php echo esc_html($result->zip_code); ?></td>
                                <td><?php echo esc_html($result->form_id); ?></td>
                                <td>
                                    <span class="ffb-status ffb-status-<?php echo esc_attr($result->status); ?>">
                                        <?php echo esc_html(ucfirst($result->status)); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html($result->reason); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            
            <!-- Pagination -->
            <?php if ($total_items > $per_page): ?>
                <div class="tablenav bottom">
                    <div class="tablenav-pages">
                        <span class="displaying-num"><?php echo esc_html($total_items); ?> items</span>
                        <span class="pagination-links">
                            <?php
                            $total_pages = ceil($total_items / $per_page);
                            
                            // First page link
                            if ($current_page > 1) {
                                echo '<a class="first-page button" href="' . esc_url(add_query_arg('paged', 1)) . '"><span class="screen-reader-text">First page</span><span aria-hidden="true">&laquo;</span></a>';
                            } else {
                                echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&laquo;</span>';
                            }
                            
                            // Previous page link
                            if ($current_page > 1) {
                                echo '<a class="prev-page button" href="' . esc_url(add_query_arg('paged', max(1, $current_page - 1))) . '"><span class="screen-reader-text">Previous page</span><span aria-hidden="true">&lsaquo;</span></a>';
                            } else {
                                echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&lsaquo;</span>';
                            }
                            
                            // Current page text
                            echo '<span class="paging-input">' . $current_page . ' of <span class="total-pages">' . $total_pages . '</span></span>';
                            
                            // Next page link
                            if ($current_page < $total_pages) {
                                echo '<a class="next-page button" href="' . esc_url(add_query_arg('paged', min($total_pages, $current_page + 1))) . '"><span class="screen-reader-text">Next page</span><span aria-hidden="true">&rsaquo;</span></a>';
                            } else {
                                echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&rsaquo;</span>';
                            }
                            
                            // Last page link
                            if ($current_page < $total_pages) {
                                echo '<a class="last-page button" href="' . esc_url(add_query_arg('paged', $total_pages)) . '"><span class="screen-reader-text">Last page</span><span aria-hidden="true">&raquo;</span></a>';
                            } else {
                                echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&raquo;</span>';
                            }
                            ?>
                        </span>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Get geolocation data for the current user
     * 
     * @return array|false Geolocation data or false on failure
     */
    public function get_geo_data($ip = null) {
        // Check if we have cached data
        $user_ip = $ip ?? $_SERVER['REMOTE_ADDR'];
        $cache_key = 'ffb_geo_' . md5($user_ip);
        $cached_data = get_transient($cache_key);
        
        if ($cached_data !== false) {
            return $cached_data;
        }
        
        $api_key = get_option('ffb_api_key', $this->api_key);
        
        if (empty($api_key)) {
            error_log('FFB: No API key configured');
            return false;
        }
        
        // Make API call with correct URL format
        $api_url = "https://api.ipapi.com/api/{$user_ip}?access_key={$api_key}";
        $response = wp_remote_get($api_url);
        
        if (is_wp_error($response)) {
            error_log('FFB: API Error - ' . $response->get_error_message());
            return false;
        }
        
        $http_code = wp_remote_retrieve_response_code($response);
        if ($http_code !== 200) {
            error_log('FFB: API returned non-200 status code: ' . $http_code);
        }
        
        $body = wp_remote_retrieve_body($response);
        $geo_data = json_decode($body, true);
        
        // Check if JSON decode failed
        if ($geo_data === null) {
            error_log('FFB: Failed to decode API response - ' . $body);
            return false;
        }
        
        // Log the complete response for debugging
        error_log('FFB: Complete API response - ' . print_r($geo_data, true));
        
        // Check for API error messages (success field may not be present in valid responses)
        if (isset($geo_data['success']) && $geo_data['success'] === false) {
            $error_info = isset($geo_data['error']['info']) ? $geo_data['error']['info'] : 'Unknown API error';
            $error_code = isset($geo_data['error']['code']) ? $geo_data['error']['code'] : 'Unknown';
            
            error_log("FFB: API Error - {$error_info} (Code: {$error_code})");
            
            // If we have usage limits exceeded, return a special error
            if (isset($geo_data['error']['code']) && $geo_data['error']['code'] == 104) {
                // Usage limit reached - create a minimal geo_data with just the error
                $fallback_geo_data = [
                    'error' => true,
                    'error_code' => 104,
                    'error_message' => 'API usage limit reached'
                ];
                
                // Cache the error for a shorter time (5 minutes)
                set_transient($cache_key, $fallback_geo_data, 300);
                return $fallback_geo_data;
            }
            
            return false;
        }
        
        // Ensure we have the minimum required data
        if (!isset($geo_data['country_code'])) {
            error_log('FFB: API response missing country_code - ' . print_r($geo_data, true));
            return false;
        }
        
        // Standardize the response format for our plugin
        $standardized_data = [
            'ip' => $geo_data['ip'] ?? $user_ip,
            'country_code' => $geo_data['country_code'] ?? '',
            'country_name' => $geo_data['country_name'] ?? '',
            'region' => $geo_data['region_name'] ?? ($geo_data['region_code'] ?? ''),
            'region_code' => $geo_data['region_code'] ?? '',
            'region_name' => $geo_data['region_name'] ?? '',
            'city' => $geo_data['city'] ?? '',
            'zip' => $geo_data['zip'] ?? '',
            'latitude' => $geo_data['latitude'] ?? 0,
            'longitude' => $geo_data['longitude'] ?? 0
        ];
        
        // Cache the standardized data for 1 hour
        set_transient($cache_key, $standardized_data, 3600);
        
        return $standardized_data;
    }

    /**
     * Clear the IP cache
     */
    public function clear_ip_cache() {
        delete_option('ffb_ip_cache');
        
        // Also clear all transients that start with ffb_geo_
        global $wpdb;
        $wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE '_transient_ffb_geo_%'");
        $wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE '_transient_timeout_ffb_geo_%'");
        
        return true;
    }
    
    /**
     * Search for an IP in the cache
     */
    public function search_ip_cache($ip) {
        $cached_data = get_option('ffb_ip_cache', []);
        
        if (isset($cached_data[$ip])) {
            return $cached_data[$ip];
        }
        
        return false;
    }
    
    /**
     * Delete an IP from the cache
     */
    public function delete_ip_from_cache($ip) {
        $cached_data = get_option('ffb_ip_cache', []);
        
        if (isset($cached_data[$ip])) {
            unset($cached_data[$ip]);
            update_option('ffb_ip_cache', $cached_data);
            return true;
        }
        
        return false;
    }
}

new FormidableFormsBlocker();

// Register activation hook to create database table
register_activation_hook(__FILE__, 'ffb_create_log_table');

function ffb_create_log_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'ffb_access_log';
    
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
        ip_address varchar(100) NOT NULL,
        country varchar(50),
        region varchar(50),
        zip_code varchar(20),
        form_id varchar(20),
        status varchar(20) NOT NULL,
        reason varchar(255),
        PRIMARY KEY  (id)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}
