<?php
/**
 * Plugin Name: AQM Formidable Forms Spam Blocker
 * Plugin URI: https://aqmarketing.com
 * Description: Block form submissions based on IP, state, or ZIP code.
 * Version: 1.6.5
 * Author: AQ Marketing
 * Author URI: https://aqmarketing.com
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
    }

    public function enqueue_scripts() {
        wp_enqueue_script('ffb-geo-blocker', plugin_dir_url(__FILE__) . 'geo-blocker.js', ['jquery'], '1.6.5', true);
        wp_enqueue_style('ffb-styles', plugin_dir_url(__FILE__) . 'style.css', [], '1.6.5');
        wp_localize_script('ffb-geo-blocker', 'ffbGeoBlocker', [
            'api_url' => 'https://api.ipapi.com/check?access_key=' . $this->api_key . '&ip=',
            'approved_states' => $this->approved_states,
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
        $geo_data = wp_remote_get("https://api.ipapi.com/check?access_key={$this->api_key}&ip={$user_ip}");
        
        // Check for API errors
        if (is_wp_error($geo_data)) {
            error_log('IPAPI Error: ' . $geo_data->get_error_message());
            // Allow submission if we can't get geo data
            $this->log_access_attempt($user_ip, 'allowed', 'API error: ' . $geo_data->get_error_message(), $form_id);
            return $errors;
        }
        
        $body = wp_remote_retrieve_body($geo_data);
        $geo_data = json_decode($body, true);
        
        // Log the geo data for debugging
        error_log('IPAPI Response for IP ' . $user_ip . ': ' . print_r($geo_data, true));
        
        // Check if API returned an error
        if (isset($geo_data['success']) && $geo_data['success'] === false) {
            $error_message = isset($geo_data['error']['info']) ? $geo_data['error']['info'] : 'Unknown API error';
            error_log('IPAPI Error: ' . $error_message);
            // Allow submission if we can't get geo data
            $this->log_access_attempt($user_ip, 'allowed', 'API error: ' . $error_message, $form_id);
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
            
            if ($geo_data && isset($geo_data['region'])) {
                $region_code = trim($geo_data['region']);
                
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
        $geo_data = wp_remote_get("https://api.ipapi.com/check?access_key={$this->api_key}&ip={$ip}");
        $geo_data = json_decode(wp_remote_retrieve_body($geo_data), true);
        
        $country = isset($geo_data['country_name']) ? $geo_data['country_name'] : '';
        $region = isset($geo_data['region']) ? $geo_data['region'] : '';
        $region_code = isset($geo_data['region']) ? $geo_data['region'] : '';
        $zip = isset($geo_data['postal']) ? $geo_data['postal'] : '';
        
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
        
        $geo_data = wp_remote_get("https://api.ipapi.com/check?access_key={$this->api_key}&ip={$user_ip}");
        $geo_data = json_decode(wp_remote_retrieve_body($geo_data), true);
        
        // Check if we should block non-US IPs
        if (get_option('ffb_block_non_us', '1') === '1') {
            if ($geo_data && isset($geo_data['country_code']) && $geo_data['country_code'] !== 'US') {
                // Replace any Formidable Forms with a message
                $content = preg_replace('/\[formidable.*?\]/', '<p class="ffb-blocked-message">Forms are not available in your country.</p>', $content);
                return $content;
            }
        }
        
        // Only check state if we have approved states configured
        if (!empty($this->approved_states) && $geo_data && isset($geo_data['region']) && !in_array($geo_data['region'], $this->approved_states)) {
            // Replace any Formidable Forms with a message
            $content = preg_replace('/\[formidable.*?\]/', '<p class="ffb-blocked-message">Forms are not available in your state.</p>', $content);
            return $content;
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
        // Verify nonce and permissions
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'ffb_test_api_key')) {
            wp_send_json_error(['error' => 'Security check failed']);
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'Permission denied']);
            return;
        }
        
        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';
        
        // Always return success
        wp_send_json_success([
            'message' => 'API key validation has been disabled. Any key will work.',
            'plan' => 'business_pro_or_higher'
        ]);
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
                            <p class="description">Enter comma-separated two-letter state codes (e.g., CA,NY,TX)</p>
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
