<?php
/**
 * Plugin Name: AQM Formidable Forms Spam Blocker
 * Plugin URI: https://aqmarketing.com
 * Description: Blocks form submissions from disallowed IPs and countries.
 * Version: 2.0.0
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
    private $approved_states = array('CA', 'NY', 'TX'); // Default approved states
    private $approved_countries = array('US'); // Default approved countries (United States)
    private $approved_zip_codes = ['10001', '90001', '73301']; // Add allowed ZIPs here
    private $api_key = ''; // API key for ipapi.com - set in admin settings
    private $rate_limit_time = 10; // Time frame in seconds
    private $rate_limit_requests = 3; // Max requests per IP in timeframe
    private $blocked_ips = array(); // IPs to block for testing
    private $log_enabled = true; // Whether to log access attempts

    public function __construct() {
        // Initialize settings
        $this->approved_states = get_option('ffb_approved_states', $this->approved_states);
        if (!is_array($this->approved_states)) {
            $this->approved_states = explode(',', $this->approved_states);
            $this->approved_states = array_map('trim', $this->approved_states);
        }
        
        $this->approved_countries = get_option('ffb_approved_countries', $this->approved_countries);
        if (!is_array($this->approved_countries)) {
            $this->approved_countries = explode(',', $this->approved_countries);
            $this->approved_countries = array_map('trim', $this->approved_countries);
        }
        
        $this->api_key = defined('FFB_API_KEY') ? FFB_API_KEY : get_option('ffb_api_key', '');
        $this->log_enabled = get_option('ffb_log_enabled', $this->log_enabled);
        $this->blocked_ips = get_option('ffb_blocked_ips', array());
        
        // Admin hooks
        add_action('admin_menu', array($this, 'admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // AJAX handlers
        add_action('wp_ajax_ffb_test_api_key', array($this, 'ajax_test_api_key'));
        add_action('wp_ajax_ffb_search_ip', array($this, 'ajax_search_ip'));
        add_action('wp_ajax_ffb_delete_ip', array($this, 'ajax_delete_ip'));
        add_action('wp_ajax_ffb_clear_cache', array($this, 'ajax_clear_cache'));
        add_action('wp_ajax_ffb_test_api_response', array($this, 'ajax_test_api_response'));
        add_action('wp_ajax_ffb_check_location', array($this, 'ajax_check_location'));
        add_action('wp_ajax_nopriv_ffb_check_location', array($this, 'ajax_check_location'));
        
        // Frontend hooks
        add_action('wp', array($this, 'check_visitor_location'));
        add_filter('the_content', array($this, 'hide_forms_for_disallowed_ips'), 99);
        add_filter('frm_validate_entry', array($this, 'validate_form_submission'), 20, 2);
        
        // Admin actions
        add_action('admin_post_ffb_clear_logs', array($this, 'clear_access_logs'));
        
        // Cache clearing hooks
        add_action('update_option_ffb_api_key', array($this, 'clear_caches_after_update'), 10, 3);
        add_action('update_option_ffb_approved_states', array($this, 'clear_caches_after_update'), 10, 3);
        add_action('update_option_ffb_approved_countries', array($this, 'clear_caches_after_update'), 10, 3);
        add_action('update_option_ffb_approved_zip_codes', array($this, 'clear_caches_after_update'), 10, 3);
    }

    public function start_session() {
        // Only start session for admin pages or AJAX requests
        if (!is_admin() && !wp_doing_ajax()) {
            return;
        }
        
        // Check if headers have been sent
        if (headers_sent($filename, $linenum)) {
            error_log("FFB Debug: Headers already sent in $filename on line $linenum");
            return;
        }
        
        // Check if session is already active
        if (session_status() === PHP_SESSION_ACTIVE) {
            error_log('FFB Debug: Session already active');
            return;
        }
        
        // Try to start the session
        try {
            session_start();
            error_log('FFB Debug: Session started successfully');
        } catch (Exception $e) {
            error_log('FFB Error: Failed to start session - ' . $e->getMessage());
        }
    }

    /**
     * Check visitor location when they first land on the site
     */
    public function check_visitor_location() {
        if (is_admin() || wp_doing_ajax()) {
            return;
        }

        error_log('FFB Debug: Starting visitor location check');
        
        $user_ip = $this->get_client_ip();
        error_log('FFB Debug: Visitor IP: ' . $user_ip);
        
        // Always log the visit, even if cached
        $geo_data = $this->check_location($user_ip);
        
        if ($geo_data) {
            error_log('FFB Debug: Got geo data: ' . print_r($geo_data, true));
            $is_blocked = $this->is_location_blocked($geo_data);
            $status = $is_blocked ? 'blocked' : 'allowed';
            $message = $is_blocked ? 'Location blocked' : 'Location allowed';
            
            // Log the access attempt
            $this->log_access(
                $user_ip,
                $geo_data['country_code'] ?? '',
                $geo_data['region_code'] ?? '',
                $status,
                $message,
                $geo_data
            );
        } else {
            error_log('FFB Debug: Failed to get geo data for IP');
            // Log the failed attempt
            $this->log_access(
                $user_ip,
                '',
                '',
                'error',
                'Failed to get location data'
            );
        }
    }

    private function get_client_ip() {
        $ip_address = '';
        
        // Check for proxy first
        $proxy_headers = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED');
        foreach ($proxy_headers as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                        $ip_address = $ip;
                        break 2;
                    }
                }
            }
        }
        
        // If no proxy detected, get direct IP
        if (!$ip_address) {
            $ip_address = $_SERVER['REMOTE_ADDR'];
        }
        
        error_log('FFB Debug: Detected client IP: ' . $ip_address);
        return $ip_address;
    }

    private function is_location_blocked($geo_data) {
        error_log('FFB Debug: Checking if location is blocked. Geo data: ' . print_r($geo_data, true));
        error_log('FFB Debug: Approved states: ' . print_r($this->approved_states, true));
        error_log('FFB Debug: Approved countries: ' . print_r($this->approved_countries, true));
        
        // Ensure approved_states is an array
        if (!is_array($this->approved_states)) {
            $this->approved_states = array('CA', 'NY', 'TX');
            error_log('FFB Debug: Reset approved states to default array');
        }
        
        // Ensure approved_countries is an array
        if (!is_array($this->approved_countries)) {
            $this->approved_countries = array('US');
            error_log('FFB Debug: Reset approved countries to default array');
        }
        
        // If no geo data, block access
        if (!$geo_data || empty($geo_data)) {
            error_log('FFB Debug: No geo data available - blocking access');
            return true;
        }

        // Check if country is in approved list
        if (!isset($geo_data['country_code']) || !in_array($geo_data['country_code'], $this->approved_countries)) {
            error_log('FFB Debug: Country not in approved list: ' . ($geo_data['country_code'] ?? 'unknown') . ' - blocking access');
            error_log('FFB Debug: Approved countries list: ' . implode(', ', $this->approved_countries));
            return true;
        }

        // Check if state is in approved list (only if country is US)
        if (isset($geo_data['country_code']) && $geo_data['country_code'] === 'US') {
            if (!isset($geo_data['region_code']) || !in_array($geo_data['region_code'], $this->approved_states)) {
                error_log('FFB Debug: State not in approved list: ' . ($geo_data['region_code'] ?? 'unknown') . ' - blocking access');
                error_log('FFB Debug: Approved states list: ' . implode(', ', $this->approved_states));
                return true;
            }
        }

        error_log('FFB Debug: Location check passed - allowing access');
        return false;
    }

    /**
     * Modified hide_forms_for_disallowed_ips to check logs first
     */
    public function hide_forms_for_disallowed_ips($content) {
        if (is_admin()) {
            return $content;
        }

        $user_ip = $this->get_client_ip();
        $cached_check = get_transient('ffb_location_check_' . $user_ip);

        // Check cache first
        if ($cached_check !== false) {
            if ($cached_check['status'] !== 'allowed') {
                return $this->replace_forms_with_message($content, 'Your location is not allowed to access these forms.');
            }
            return $content;
        }

        // If no cache, check location directly
        $geo_data = $this->check_location($user_ip);
        
        if ($geo_data) {
            $is_blocked = $this->is_location_blocked($geo_data);
            if ($is_blocked) {
                // Log the access attempt if logging is enabled
                if ($this->log_enabled) {
                    $this->log_access(
                        $user_ip,
                        $geo_data['country_code'] ?? '',
                        $geo_data['region_code'] ?? '',
                        'blocked',
                        'Forms hidden - location not allowed',
                        $geo_data
                    );
                }
                
                // Cache the result for future requests
                set_transient(
                    'ffb_location_check_' . $user_ip,
                    [
                        'status' => 'blocked',
                        'timestamp' => time(),
                        'country' => $geo_data['country_code'] ?? '',
                        'region' => $geo_data['region_code'] ?? ''
                    ],
                    DAY_IN_SECONDS
                );
                
                return $this->replace_forms_with_message($content, 'Your location is not allowed to access these forms.');
            }
            
            // Cache the allowed result
            set_transient(
                'ffb_location_check_' . $user_ip,
                [
                    'status' => 'allowed',
                    'timestamp' => time(),
                    'country' => $geo_data['country_code'] ?? '',
                    'region' => $geo_data['region_code'] ?? ''
                ],
                DAY_IN_SECONDS
            );
        }

        return $content;
    }

    /**
     * Helper function to replace forms with message
     */
    private function replace_forms_with_message($content, $message) {
        $pattern = '/<form[^>]*class=["\'][^"\']*frm_forms[^"\']*["\'][^>]*>.*?<\/form>/s';
        return preg_replace($pattern, '<div class="frm-blocked-message">' . esc_html($message) . '</div>', $content);
    }

    // Helper method to get approved states
    public function get_approved_states() {
        // Get approved states from options
        $approved_states = get_option('ffb_approved_states', $this->approved_states);
        
        // Make sure approved states are properly formatted
        if (!is_array($approved_states)) {
            $approved_states = explode(',', $approved_states);
        }
        
        // Clean up each state code
        $approved_states = array_map(function($state) {
            return trim(strtoupper($state));
        }, $approved_states);
        
        // Debug log
        error_log('FFB: Passing approved states to JS: ' . implode(',', $approved_states));
        
        return $approved_states;
    }
    
    // Helper method to get approved zip codes
    public function get_approved_zip_codes() {
        // Get approved zip codes from options
        $approved_zip_codes = get_option('ffb_approved_zip_codes', $this->approved_zip_codes);
        
        // Make sure approved zip codes are properly formatted
        if (!is_array($approved_zip_codes)) {
            $approved_zip_codes = explode(',', $approved_zip_codes);
        }
        
        // Clean up each zip code
        $approved_zip_codes = array_map(function($zip) {
            return trim($zip);
        }, $approved_zip_codes);
        
        return $approved_zip_codes;
    }

    public function enqueue_scripts() {
        // Get the approved states and zip codes
        $approved_states = $this->get_approved_states();
        $approved_zip_codes = $this->get_approved_zip_codes();
        $approved_countries = $this->approved_countries;
        $zip_validation_enabled = get_option('ffb_zip_validation_enabled', '0') === '1';
        
        // Always enqueue the scripts and styles to ensure they're available when needed
        wp_enqueue_script('jquery');
        
        // Enqueue the geo-blocker script
        wp_enqueue_script('ffb-geo-blocker', plugin_dir_url(__FILE__) . 'geo-blocker.js', array('jquery'), '2.0.0', true);
        
        // Enqueue the styles
        wp_enqueue_style('ffb-styles', plugin_dir_url(__FILE__) . 'style.css', array(), '2.0.0');
        
        // Localize the script with necessary data
        wp_localize_script('ffb-geo-blocker', 'ffbGeoBlocker', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'api_url' => 'https://api.ipapi.com/api/',
            'api_key' => defined('FFB_API_KEY') ? FFB_API_KEY : get_option('ffb_api_key', ''),
            'approved_states' => $approved_states,
            'approved_countries' => $approved_countries,
            'approved_zip_codes' => $approved_zip_codes,
            'zip_validation_enabled' => $zip_validation_enabled,
            'is_admin' => current_user_can('manage_options'),
            'testing_own_ip' => in_array($_SERVER['REMOTE_ADDR'], $this->blocked_ips)
        ));
        
        // Localize the script with AJAX data
        wp_localize_script('ffb-geo-blocker', 'ffb_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ffb_nonce')
        ));
    }

    public function validate_form_submission($errors, $values) {
        $user_ip = $this->get_client_ip();
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
        
        // Check if we should block non-approved countries
        if (isset($geo_data['country_code'])) {
            if (!in_array($geo_data['country_code'], $this->approved_countries)) {
                $errors['general'] = 'We are currently not accepting submissions from your country.';
                $this->log_access_attempt($user_ip, 'blocked', 'Country not approved: ' . $geo_data['country_code'], $form_id);
                return $errors;
            }
        }
        
        // Check state - only if we have approved states configured
        if (!empty($this->approved_states)) {
            // Make sure approved_states is an array of trimmed, uppercase values
            $approved_states = array_map(function($state) {
                return strtoupper(trim($state));
            }, $this->approved_states);
            
            if ($geo_data && (isset($geo_data['region_code']) || isset($geo_data['region_name']) || isset($geo_data['region']))) {
                // Get the region code, prioritizing region_code over region
                $region_code = '';
                if (!empty($geo_data['region_code'])) {
                    $region_code = strtoupper(trim($geo_data['region_code']));
                } elseif (!empty($geo_data['region'])) {
                    $region_code = strtoupper(trim($geo_data['region']));
                } elseif (!empty($geo_data['region_name'])) {
                    $region_code = strtoupper(trim($geo_data['region_name']));
                }
                
                // Special handling for Massachusetts
                if ($region_code === 'MASSACHUSETTS' || $region_code === 'MASS' || $region_code === 'MA') {
                    // Check if MA is in the approved list
                    if (in_array('MA', $approved_states) || 
                        in_array('MASSACHUSETTS', $approved_states) || 
                        in_array('MASS', $approved_states)) {
                        // Massachusetts is approved
                        error_log('FFB: Massachusetts (MA) is in the approved list - allowing access');
                        // State is approved, so we'll continue processing the form
                        $this->log_access_attempt($user_ip, 'allowed', 'Approved state: ' . $region_code . ' (Massachusetts)', $form_id);
                    } else {
                        $errors['general'] = 'Forms are not available in your state.';
                        $this->log_access_attempt($user_ip, 'blocked', 'Disallowed state: ' . $region_code . ' (Massachusetts)', $form_id);
                        return $errors;
                    }
                } else {
                    // Debug log
                    error_log('FFB: Checking state: ' . $region_code . ' against approved states: ' . implode(',', $approved_states));
                    
                    // Check if the state code is in the approved list
                    if (in_array($region_code, $approved_states)) {
                        // State is approved, so we'll continue processing the form
                        error_log('FFB: State ' . $region_code . ' is in the approved list - allowing access');
                        $this->log_access_attempt($user_ip, 'allowed', 'Approved state: ' . $region_code, $form_id);
                    } else {
                        $errors['general'] = 'Forms are not available in your state.';
                        $this->log_access_attempt($user_ip, 'blocked', 'Disallowed state: ' . $region_code, $form_id);
                        return $errors;
                    }
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
        $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
        
        // Check if table exists
        if($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            ffb_create_log_table();
        }
        
        // Get geo data for the specific IP
        $geo_data = $this->get_geo_data();
        
        $country = isset($geo_data['country_code']) ? $geo_data['country_code'] : '';
        $region = isset($geo_data['region_name']) ? $geo_data['region_name'] : '';
        
        // Prepare data according to the table structure
        $data = array(
            'ip_address' => $ip,
            'country' => $country,
            'region' => $region,
            'status' => $status,
            'message' => $reason . ($form_id ? ' (Form ID: ' . $form_id . ')' : ''),
            'geo_data' => $geo_data ? wp_json_encode($geo_data) : null
        );
        
        error_log('FFB Debug: Log data: ' . print_r($data, true));
        
        // Insert with current timestamp
        $result = $wpdb->insert($table_name, $data);
        
        if ($result === false) {
            error_log('FFB Log Error: ' . $wpdb->last_error);
            
            // If we get an unknown column error, try to update the database structure
            if (strpos($wpdb->last_error, 'Unknown column') !== false) {
                error_log('FFB Debug: Attempting to update database structure...');
                ffb_create_log_table();
                
                // Try the insert again
                $result = $wpdb->insert($table_name, $data);
                
                if ($result === false) {
                    error_log('FFB Log Error: Second attempt failed: ' . $wpdb->last_error);
                } else {
                    error_log('FFB Debug: Second attempt successful, logged access with ID: ' . $wpdb->insert_id);
                }
            }
        }
    }

    public function admin_menu() {
        add_menu_page(
            'AQM Formidable Forms Spam Blocker Settings',
            'Form Spam Blocker',
            'edit_pages',
            'formidable-forms-blocker',
            array($this, 'settings_page'),
            'dashicons-shield'
        );

        // Register AJAX handlers for the API tester
        add_action('wp_ajax_ffb_test_api_response', array($this, 'ajax_test_api_response'));
        
        // Add script to fix the footer on our admin page
        add_action('admin_enqueue_scripts', array($this, 'admin_scripts'));
    }
    
    public function admin_scripts($hook) {
        // Only on our plugin page
        if ($hook === 'toplevel_page_formidable-forms-blocker') {
            wp_enqueue_script('ffb-footer-fix', plugin_dir_url(__FILE__) . 'footer-fix.js', array('jquery'), '2.0.0', true);
        }
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Show success message if logs were cleared
        if (isset($_GET['ffb_logs_cleared']) && $_GET['ffb_logs_cleared'] === 'true') {
            echo '<div class="notice notice-success is-dismissible"><p>Access logs have been cleared successfully.</p></div>';
        }

        ?>
        <div class="wrap">
            <h1>Formidable Forms Spam Blocker Settings</h1>
            
            <form method="post" action="options.php">
                <?php
                settings_fields('ffb_settings');
                do_settings_sections('ffb_settings');
                submit_button();
                ?>
            </form>

            <hr>

            <h2>Access Logs</h2>
            <form method="post" action="<?php echo admin_url('admin-post.php'); ?>">
                <?php wp_nonce_field('ffb_clear_logs', 'ffb_clear_logs_nonce'); ?>
                <input type="hidden" name="action" value="ffb_clear_logs">
                <?php submit_button('Clear Access Logs', 'delete', 'submit', false, array(
                    'onclick' => 'return confirm("Are you sure you want to clear all access logs? This action cannot be undone.");'
                )); ?>
            </form>

            <?php $this->display_access_logs(); ?>
        </div>
        <?php
    }

    private function render_ip_testing_section() {
        $current_ip = $this->get_client_ip();
        $geo_data = $this->get_geo_data($current_ip);
        $is_blocked = $this->is_location_blocked($geo_data);
        
        ?>
        <div class="card" style="max-width: 800px; margin-top: 20px; padding: 20px; border: 1px solid #ccd0d4; border-radius: 4px; background: #fff;">
            <h3>Your Current IP</h3>
            
            <?php if ($geo_data): ?>
                <table class="form-table">
                    <tr>
                        <th>IP Address</th>
                        <td><?php echo esc_html($geo_data['ip']); ?></td>
                    </tr>
                    <tr>
                        <th>Location Status</th>
                        <td>
                            <?php if ($is_blocked): ?>
                                <span style="color: #dc3232;">&#x1F6AB; Blocked</span>
                            <?php else: ?>
                                <span style="color: #46b450;">&#x2713; Allowed</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th>Country</th>
                        <td>
                            <?php 
                            echo esc_html($geo_data['country_name'] ?? 'Unknown');
                            if (!empty($geo_data['country_code'])) {
                                echo ' (' . esc_html($geo_data['country_code']) . ')';
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th>Region</th>
                        <td>
                            <?php 
                            echo esc_html($geo_data['region_name'] ?? 'Unknown');
                            if (!empty($geo_data['region_code'])) {
                                echo ' (' . esc_html($geo_data['region_code']) . ')';
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th>City</th>
                        <td><?php echo esc_html($geo_data['city'] ?? 'Unknown'); ?></td>
                    </tr>
                    <tr>
                        <th>Zip Code</th>
                        <td><?php echo esc_html($geo_data['zip'] ?? 'Unknown'); ?></td>
                    </tr>
                    <tr>
                        <th>Coordinates</th>
                        <td>
                            <?php 
                            if (!empty($geo_data['latitude']) && !empty($geo_data['longitude'])) {
                                printf(
                                    '<a href="https://www.google.com/maps?q=%1$f,%2$f" target="_blank">%1$f, %2$f</a>',
                                    $geo_data['latitude'],
                                    $geo_data['longitude']
                                );
                            } else {
                                echo 'Unknown';
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th>API Response</th>
                        <td>
                            <button type="button" class="button" onclick="jQuery('#ffb-api-response').toggle();">Show/Hide Raw Response</button>
                            <pre id="ffb-api-response" style="display: none; margin-top: 10px; padding: 10px; background: #f8f9fa; border: 1px solid #ddd; max-height: 200px; overflow: auto;">
<?php echo esc_html(json_encode($geo_data, JSON_PRETTY_PRINT)); ?>
                            </pre>
                        </td>
                    </tr>
                </table>
                
                <div style="margin-top: 20px;">
                    <button type="button" class="button button-primary" onclick="ffbTestLocation();">Test Location Again</button>
                    <span id="ffb-test-result" style="margin-left: 10px;"></span>
                </div>
            <?php else: ?>
                <div class="notice notice-error">
                    <p>Unable to retrieve location data. Please check your API key and try again.</p>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    private function render_settings_fields() {
        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row">Approved States</th>
                <td>
                    <?php 
                        $approved_states = get_option('ffb_approved_states', $this->approved_states);
                        if (!is_array($approved_states)) {
                            $approved_states = explode(',', $approved_states);
                            $approved_states = array_map('trim', $approved_states);
                        }
                        $approved_states = array_map('strtoupper', $approved_states);
                    ?>
                    <input type="text" name="ffb_approved_states" value="<?php echo esc_attr(implode(',', $approved_states)); ?>" />
                    <p class="description">Enter comma-separated state codes (e.g., NY,CA,TX) to allow form submissions from these states.</p>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row">Approved Countries</th>
                <td>
                    <?php 
                        $approved_countries = get_option('ffb_approved_countries', $this->approved_countries);
                        if (!is_array($approved_countries)) {
                            $approved_countries = explode(',', $approved_countries);
                            $approved_countries = array_map('trim', $approved_countries);
                        }
                        $approved_countries = array_map('strtoupper', $approved_countries);
                    ?>
                    <input type="text" name="ffb_approved_countries" value="<?php echo esc_attr(implode(',', $approved_countries)); ?>" />
                    <p class="description">Enter comma-separated country codes (e.g., US,CA,UK) to allow form submissions from these countries.</p>
                </td>
            </tr>
            <tr valign="top">
                <th scope="row">Log Access Attempts</th>
                <td>
                    <input type="checkbox" name="ffb_log_enabled" value="1" <?php checked(get_option('ffb_log_enabled', $this->log_enabled), '1'); ?> />
                    <span>Log all access attempts to the database</span>
                </td>
            </tr>
        </table>

        <h2>API Settings</h2>
        <p>This plugin uses the ipapi.com service to determine user location.</p>
        <table class="form-table">
            <tr valign="top">
                <th scope="row">API Key</th>
                <td>
                    <?php $api_key = defined('FFB_API_KEY') ? FFB_API_KEY : get_option('ffb_api_key', ''); ?>
                    <input type="password" id="ffb_api_key" name="ffb_api_key" value="<?php echo esc_attr($api_key); ?>" style="width: 300px;" />
                    <p class="description">Get your API key from <a href="https://ipapi.com/" target="_blank">ipapi.com</a></p>
                </td>
            </tr>
        </table>

        <h2>Cache Management</h2>
        <table class="form-table">
            <tr valign="top">
                <th scope="row">Clear Cache</th>
                <td>
                    <form method="post" action="">
                        <input type="submit" name="clear_cache" class="button button-secondary" value="Clear Plugin Cache" />
                        <?php if (function_exists('rocket_clean_domain')): ?>
                        <input type="submit" name="clear_wp_rocket" class="button button-secondary" value="Clear WP Rocket Cache" />
                        <?php endif; ?>
                        <p class="description">Clear the IP cache to ensure changes take effect immediately.</p>
                    </form>
                </td>
            </tr>
        </table>
        <?php
    }

    public function register_settings() {
        register_setting('ffb_settings', 'ffb_approved_states', [
            'sanitize_callback' => [$this, 'sanitize_comma_list'],
            'default' => implode(',', $this->approved_states)
        ]);
        register_setting('ffb_settings', 'ffb_approved_countries', [
            'sanitize_callback' => [$this, 'sanitize_comma_list'],
            'default' => implode(',', $this->approved_countries)
        ]);
        register_setting('ffb_settings', 'ffb_api_key', [
            'sanitize_callback' => 'sanitize_text_field'
        ]);
        register_setting('ffb_settings', 'ffb_approved_zip_codes', [
            'sanitize_callback' => [$this, 'sanitize_comma_list']
        ]);
        register_setting('ffb_settings', 'ffb_log_enabled');
    }
    
    /**
     * Clear all caches after settings are updated
     */
    public function clear_caches_after_update($option, $old_value, $value) {
        // Clear our own cache
        $this->clear_ip_cache();
        
        // Clear WP Rocket cache if active
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
            error_log('FFB: WP Rocket cache cleared after settings update');
        }
        
        return $value;
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
        if (empty($key)) {
            return array(
                'valid' => false,
                'message' => 'API key is required'
            );
        }

        // Test with a known US IP address
        $test_ip = '8.8.8.8';
        $url = sprintf(
            'https://api.ipapi.com/api/%s?access_key=%s',
            urlencode($test_ip),
            urlencode($key)
        );

        error_log('FFB Debug: Testing API key with URL: ' . $url);

        $response = wp_remote_get($url, array(
            'timeout' => 15,
            'headers' => array(
                'User-Agent' => 'WordPress/FFB-' . get_bloginfo('version')
            )
        ));
        
        if (is_wp_error($response)) {
            error_log('FFB Error: API test failed - ' . $response->get_error_message());
            return array(
                'valid' => false,
                'message' => 'Connection failed: ' . $response->get_error_message()
            );
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            error_log('FFB Error: API returned non-200 status code: ' . $status_code);
            return array(
                'valid' => false,
                'message' => 'API returned status code ' . $status_code
            );
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        error_log('FFB Debug: API test response - ' . print_r($data, true));

        // Check if JSON decode failed
        if ($data === null) {
            $error_message = 'Invalid response from API. Please check your API key.';
            set_transient('ffb_api_key_error', $error_message, 60);
            wp_send_json_error(['message' => $error_message, 'raw_response' => $body]);
            return;
        }
        
        // Check for API error messages
        if (isset($data['error'])) {
            $error_type = isset($data['error']['type']) ? $data['error']['type'] : 'unknown';
            $error_info = isset($data['error']['info']) ? $data['error']['info'] : 'Unknown API error';
            
            // Special handling for rate limits - key is valid but limited
            if ($error_type === 'usage_limit_reached' || $error_type === 'monthly_limit_reached') {
                return array(
                    'valid' => true, // API key is valid but rate limited
                    'message' => 'API key is valid but rate limited: ' . $error_info
                );
            }
            
            error_log('FFB Error: API error - Type: ' . $error_type . ', Info: ' . $error_info);
            return array(
                'valid' => false,
                'message' => $error_info
            );
        }

        // API key is valid
        $success_message = 'API key is valid! Test IP: ' . $test_ip . ', Location: ' . $data['country_name'] . ', ' . $data['region'];
        set_transient('ffb_api_key_success', $success_message, 60);
        return array(
            'valid' => true,
            'message' => $success_message
        );
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
        if (isset($geo_data['error'])) {
            $error_info = isset($geo_data['error']['info']) ? $geo_data['error']['info'] : 'Unknown API error';
            $error_code = isset($geo_data['error']['code']) ? $geo_data['error']['code'] : 'Unknown';
            $error_type = isset($geo_data['error']['type']) ? $geo_data['error']['type'] : 'Unknown';
            
            // Special handling for rate limits - key is valid but limited
            if ($error_type === 'usage_limit_reached' || $error_type === 'monthly_limit_reached') {
                return array(
                    'valid' => true, // API key is valid but rate limited
                    'message' => 'API key is valid but rate limited: ' . $error_info
                );
            }
            
            error_log('FFB Error: API error - Type: ' . $error_type . ', Info: ' . $error_info);
            return array(
                'valid' => false,
                'message' => $error_info
            );
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
        global $wpdb;
        
        // Get the user's IP
        $user_ip = $this->get_client_ip();
        
        // Clear any existing cached data for this IP
        $this->delete_ip_from_cache($user_ip);
        
        // Get fresh geo data
        $geo_data = $this->get_geo_data($user_ip);
        
        // Get the most recent log entries
        $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
        $recent_logs = $wpdb->get_results("SELECT * FROM $table_name ORDER BY id DESC LIMIT 10");
        
        echo '<div style="background-color: #f8f9fa; padding: 20px; border: 1px solid #ddd; margin: 20px 0;">';
        echo '<h2>API Response Format Test</h2>';
        
        if ($geo_data) {
            echo '<h3>Your Current Location:</h3>';
            echo '<ul>';
            echo '<li><strong>IP:</strong> ' . esc_html($user_ip) . '</li>';
            echo '<li><strong>Country:</strong> ' . esc_html($geo_data['country_name'] ?? 'N/A') . ' (' . esc_html($geo_data['country_code'] ?? 'N/A') . ')</li>';
            echo '<li><strong>Region Name:</strong> ' . esc_html($geo_data['region_name'] ?? 'N/A') . '</li>';
            echo '<li><strong>Region Code:</strong> ' . esc_html($geo_data['region_code'] ?? 'N/A') . '</li>';
            echo '<li><strong>City:</strong> ' . esc_html($geo_data['city'] ?? 'N/A') . '</li>';
            echo '<li><strong>ZIP:</strong> ' . esc_html($geo_data['zip'] ?? 'N/A') . '</li>';
            echo '</ul>';
            
            // Check if this state is in the approved list
            $approved_states = get_option('ffb_approved_states', []);
            if (!is_array($approved_states)) {
                $approved_states = explode(',', $approved_states);
                $approved_states = array_map('trim', $approved_states);
            }
            
            // Convert to uppercase for comparison
            $approved_states = array_map('strtoupper', $approved_states);
            $region_code = strtoupper($geo_data['region_code'] ?? '');
            
            echo '<h3>State Validation Check:</h3>';
            echo '<ul>';
            echo '<li><strong>Your State Code:</strong> ' . esc_html($region_code) . '</li>';
            echo '<li><strong>Approved States:</strong> ' . esc_html(implode(', ', $approved_states)) . '</li>';
            
            // Special check for Massachusetts
            if ($region_code === 'MASSACHUSETTS' || $region_code === 'MASS' || $region_code === 'MA') {
                echo '<li><strong>Special Massachusetts Check:</strong> ';
                if (in_array('MA', $approved_states) || 
                    in_array('MASSACHUSETTS', $approved_states) || 
                    in_array('MASS', $approved_states)) {
                    echo 'MA is in the approved list ';
                } else {
                    echo 'MA is NOT in the approved list ';
                }
                echo '</li>';
            }
            
            echo '<li><strong>Is Approved:</strong> ' . (in_array($region_code, $approved_states) ? 'YES ' : 'NO ') . '</li>';
            echo '</ul>';
            
            // Show the raw API response
            echo '<h3>Raw API Response:</h3>';
            echo '<pre style="background-color: #f0f0f0; padding: 10px; overflow: auto; max-height: 300px;">';
            print_r($geo_data);
            echo '</pre>';
        } else {
            echo '<p>Error: Could not retrieve geolocation data.</p>';
        }
        
        // Display recent log entries
        echo '<h3>Recent Access Log Entries:</h3>';
        if (empty($recent_logs)) {
            echo '<p>No recent log entries found.</p>';
        } else {
            echo '<table class="wp-list-table widefat fixed striped" style="width: 100%;">';
            echo '<thead><tr>';
            echo '<th>Time</th><th>IP</th><th>Country</th><th>Region</th><th>Status</th><th>Reason</th>';
            echo '</tr></thead><tbody>';
            
            foreach ($recent_logs as $log) {
                echo '<tr>';
                echo '<td>' . esc_html($log->time) . '</td>';
                echo '<td>' . esc_html($log->ip_address) . '</td>';
                echo '<td>' . esc_html($log->country) . '</td>';
                echo '<td>' . esc_html($log->region) . '</td>';
                echo '<td>' . esc_html($log->status) . '</td>';
                echo '<td>' . esc_html($log->reason) . '</td>';
                echo '</tr>';
            }
            
            echo '</tbody></table>';
        }
        
        echo '</div>';
        
        return true;
    }

    /**
     * AJAX endpoint to check location status
     */
    public function ajax_check_location() {
        check_ajax_referer('ffb_nonce', 'nonce');
        
        $user_ip = $this->get_client_ip();
        $cached_check = get_transient('ffb_location_check_' . $user_ip);

        if ($cached_check !== false) {
            wp_send_json_success([
                'is_allowed' => $cached_check['status'] === 'allowed',
                'timestamp' => $cached_check['timestamp']
            ]);
            return;
        }
        
        // If no cache, check logs
        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
        $last_log = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name WHERE ip_address = %s ORDER BY timestamp DESC LIMIT 1",
            $user_ip
        ));

        if ($last_log) {
            $is_allowed = ($last_log->status === 'allowed');
            wp_send_json_success([
                'is_allowed' => $is_allowed,
                'message' => $last_log->reason
            ]);
            return;
        }
        
        // If no log entry, perform a new check
        $this->check_visitor_location();
        $cached_check = get_transient('ffb_location_check_' . $user_ip);
        
        wp_send_json_success([
            'is_allowed' => $cached_check['status'] === 'allowed',
            'timestamp' => $cached_check['timestamp']
        ]);
    }

    /**
     * Get geolocation data for the current user
     * 
     * @return array|false Geolocation data or false on failure
     */
    public function get_geo_data($ip = null) {
        if (!$ip) {
            $ip = $this->get_client_ip();
        }
        
        error_log('FFB Debug: Getting geo data for IP: ' . $ip);
        
        if (empty($this->api_key)) {
            error_log('FFB Error: No API key configured');
            return false;
        }

        // Use the correct API endpoint format
        $url = sprintf(
            'https://api.ipapi.com/api/%s?access_key=%s',
            urlencode($ip),
            urlencode($this->api_key)
        );

        error_log('FFB Debug: Making API request to: ' . $url);

        $response = wp_remote_get($url, array(
            'timeout' => 15,
            'headers' => array(
                'User-Agent' => 'WordPress/FFB-' . get_bloginfo('version')
            )
        ));
        
        if (is_wp_error($response)) {
            error_log('FFB Error: API request failed - ' . $response->get_error_message());
            return false;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            error_log('FFB Error: API returned non-200 status code: ' . $status_code);
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        error_log('FFB Debug: API Response - ' . print_r($data, true));
        
        // Check for API error responses
        if (!is_array($data)) {
            error_log('FFB Error: Invalid API response format');
            return false;
        }

        // Check for API error messages
        if (isset($data['error'])) {
            $error_type = isset($data['error']['type']) ? $data['error']['type'] : 'unknown';
            $error_info = isset($data['error']['info']) ? $data['error']['info'] : 'Unknown error';
            
            // Special handling for rate limits - key is valid but limited
            if ($error_type === 'usage_limit_reached' || $error_type === 'monthly_limit_reached') {
                return array(
                    'valid' => true, // API key is valid but rate limited
                    'message' => 'API key is valid but rate limited: ' . $error_info
                );
            }
            
            error_log('FFB Error: API error - Type: ' . $error_type . ', Info: ' . $error_info);
            return false;
        }

        // Validate required fields
        if (!isset($data['country_code'])) {
            error_log('FFB Error: API response missing required fields');
            return false;
        }
        
        // Return standardized data
        return array(
            'ip' => $data['ip'] ?? $ip,
            'country_code' => $data['country_code'] ?? '',
            'country_name' => $data['country_name'] ?? '',
            'region' => $data['region_name'] ?? '',
            'region_code' => $data['region_code'] ?? '',
            'region_name' => $data['region_name'] ?? '',
            'city' => $data['city'] ?? '',
            'zip' => $data['zip'] ?? '',
            'latitude' => $data['latitude'] ?? 0,
            'longitude' => $data['longitude'] ?? 0
        );
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
        
        // Clear WP Rocket cache if active
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
            error_log('FFB: WP Rocket cache cleared');
        }
        
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

    public function check_location($ip_address = null) {
        if (!$ip_address) {
            $ip_address = $this->get_client_ip();
        }

        error_log('FFB Debug: Checking location for IP: ' . $ip_address);

        // Check if logging is enabled
        $logging_enabled = get_option('ffb_log_enabled', true);
        error_log('FFB Debug: Logging enabled: ' . ($logging_enabled ? 'true' : 'false'));

        // Always log the visit, even if cached
        $geo_data = $this->get_geo_data();
        
        if ($geo_data) {
            error_log('FFB Debug: Got geo data: ' . print_r($geo_data, true));
            $is_blocked = $this->is_location_blocked($geo_data);
            $status = $is_blocked ? 'blocked' : 'allowed';
            $message = $status === 'blocked' ? 'Access blocked' : 'Access allowed';
            
            // Log the access attempt
            $this->log_access(
                $ip_address,
                isset($geo_data['country_code']) ? $geo_data['country_code'] : '',
                isset($geo_data['region_name']) ? $geo_data['region_name'] : '',
                $status,
                $message,
                $geo_data
            );
        } else {
            error_log('FFB Debug: Failed to get geo data for IP');
            // Log the failed attempt
            $this->log_access(
                $ip_address,
                '',
                '',
                'error',
                'Failed to get location data'
            );
        }
    }

    public function log_access($ip_address, $country, $region, $status, $message, $geo_data = null) {
        if (!$this->log_enabled) {
            return;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
        
        // Check if table exists, create if not
        if($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            error_log('FFB Debug: Table does not exist, creating...');
            ffb_create_log_table();
        }
        
        // Store full geo data as JSON if available
        $geo_json = null;
        if ($geo_data && is_array($geo_data)) {
            $geo_json = wp_json_encode($geo_data);
        }
        
        // Ensure proper data types and lengths
        $data = array(
            'ip_address' => substr($ip_address, 0, 45),
            'country' => substr($country, 0, 2),
            'region' => substr($region, 0, 50),
            'status' => substr($status, 0, 20),
            'message' => $message,
            'geo_data' => $geo_json
        );
        
        error_log('FFB Debug: Log data: ' . print_r($data, true));
        
        // Insert with current timestamp
        $result = $wpdb->insert(
            $table_name,
            $data,
            array(
                '%s', // ip_address
                '%s', // country
                '%s', // region
                '%s', // status
                '%s', // message
                '%s'  // geo_data
            )
        );

        if ($result === false) {
            error_log('FFB Log Error: ' . $wpdb->last_error);
        } else {
            error_log('FFB Debug: Successfully logged access with ID: ' . $wpdb->insert_id);
        }
    }

    private function display_access_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
        
        // Get the latest 100 log entries
        $logs = $wpdb->get_results(
            "SELECT * FROM $table_name ORDER BY timestamp DESC LIMIT 100"
        );

        if (empty($logs)) {
            echo '<p>No access logs found.</p>';
            return;
        }

        ?>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($log->timestamp))); ?></td>
                        <td><?php echo esc_html($log->ip_address); ?></td>
                        <td><?php echo esc_html($log->country_code); ?></td>
                        <td><?php echo esc_html($log->region_code); ?></td>
                        <td><?php echo esc_html($log->status); ?></td>
                        <td><?php echo esc_html($log->message); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    public function clear_access_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_ffb_access_log';

        // Check if table exists
        if($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            echo '<div class="notice notice-error"><p>Access log table does not exist.</p></div>';
            return;
        }

        // Clear the access logs
        $wpdb->query("TRUNCATE TABLE $table_name");

        // Redirect to remove the query arg
        wp_redirect(add_query_arg('ffb_logs_cleared', 'true', remove_query_arg('ffb_clear_logs')));
        exit;
    }
}

new FormidableFormsBlocker();

// Register activation hook to create database table
register_activation_hook(__FILE__, 'ffb_create_log_table');
register_activation_hook(__FILE__, 'ffb_update_db_check');

// Function to check and update database schema if needed
function ffb_update_db_check() {
    $current_version = get_option('ffb_db_version', '1.0');
    
    // If the database version is less than 2.0.0, run the update
    if (version_compare($current_version, '2.0.0', '<')) {
        ffb_create_log_table();
        update_option('ffb_db_version', '2.0.0');
    }
}

function ffb_create_log_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        timestamp datetime DEFAULT CURRENT_TIMESTAMP,
        ip_address varchar(45) NOT NULL,
        country varchar(2),
        region varchar(50),
        status varchar(20) NOT NULL,
        message text,
        geo_data longtext,
        PRIMARY KEY  (id),
        KEY timestamp (timestamp),
        KEY ip_address (ip_address),
        KEY status (status)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
    
    // Update database version
    update_option('ffb_db_version', '2.0.0');
}

// Add admin notice to update database if needed
add_action('admin_notices', 'ffb_admin_notices');
function ffb_admin_notices() {
    // Only show to admins
    if (!current_user_can('edit_pages')) {
        return;
    }
    
    $current_version = get_option('ffb_db_version', '1.0');
    
    // If the database version is less than 2.0.0, show update notice
    if (version_compare($current_version, '2.0.0', '<')) {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><?php _e('AQM Formidable Forms Spam Blocker database needs to be updated.', 'aqm-formidable-spam-blocker'); ?> <a href="<?php echo esc_url(add_query_arg(array('ffb_update_db' => 'true'), admin_url('admin.php?page=formidable-forms-blocker'))); ?>" class="button button-primary"><?php _e('Update Now', 'aqm-formidable-spam-blocker'); ?></a></p>
        </div>
        <?php
    }
}

// Handle database update request
add_action('admin_init', 'ffb_handle_db_update');
function ffb_handle_db_update() {
    if (isset($_GET['ffb_update_db']) && $_GET['ffb_update_db'] === 'true' && current_user_can('edit_pages')) {
        ffb_create_log_table();
        
        // Redirect to remove the query arg
        wp_redirect(add_query_arg('ffb_db_updated', 'true', remove_query_arg('ffb_update_db')));
        exit;
    }
}

// Show success message after database update
add_action('admin_notices', 'ffb_db_updated_notice');
function ffb_db_updated_notice() {
    if (isset($_GET['ffb_db_updated']) && $_GET['ffb_db_updated'] === 'true') {
        ?>
        <div class="notice notice-success is-dismissible">
            <p><?php _e('AQM Formidable Forms Spam Blocker database has been successfully updated.', 'aqm-formidable-spam-blocker'); ?></p>
        </div>
        <?php
    }
}
