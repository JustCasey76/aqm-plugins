<?php
/**
 * Plugin Name: AQM Formidable Forms Spam Blocker
 * Plugin URI: https://aqmarketing.com
 * Description: Blocks spam submissions in Formidable Forms based on IP geolocation and other factors.
 * Version: 2.1.83
 * Author: AQMarketing
 * Author URI: https://aqmarketing.com
 * License: GPL3
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
    private $approved_countries = array('US', 'CA'); // Default approved countries (United States)
    private $approved_zip_codes = array(); // Add allowed ZIPs here
    private $api_key = ''; // API key for ipapi.com - set in admin settings
    private $rate_limit_time = 10; // Time frame in seconds
    private $rate_limit_requests = 3; // Max requests per IP in timeframe
    private $blocked_ips = array(); // IPs to block for testing
    private $log_enabled = true; // Whether to log access attempts
    private $version = '2.1.83';
    private $geo_data = null;
    private $is_blocked = null;
    private $blocked_message = ''; // Blocked message
    private $diagnostic_mode = false; // Diagnostic mode

    public function __construct() {
        // Set version
        $this->version = '2.1.83';
        
        // Initialize properties
        $this->init_properties();
        
        // Add hooks
        $this->add_hooks();
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Add a unique action for the plugin to allow it to be called without
        // conflicting with other plugins
        add_action('plugins_loaded', array($this, 'plugins_loaded'));
        
        // Add admin menu items
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Add settings link to plugins page
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_settings_link'));
        
        // Register scripts
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_enqueue_scripts', array($this, 'admin_scripts'));
        
        // Add callbacks for AJAX
        add_action('wp_ajax_ffb_test_api', array($this, 'test_api'));
        add_action('wp_ajax_nopriv_ffb_test_api', array($this, 'test_api'));
        add_action('wp_ajax_ffb_get_usage', array($this, 'get_api_usage'));
        add_action('wp_ajax_ffb_search_ip', array($this, 'search_ip_cache'));
        add_action('wp_ajax_ffb_clear_cache', array($this, 'clear_geolocation_cache'));
        add_action('wp_ajax_ffb_export_logs_csv', array($this, 'handle_export_logs_csv'));
        add_action('wp_ajax_ffb_check_location', array($this, 'ajax_check_location'));
        add_action('wp_ajax_nopriv_ffb_check_location', array($this, 'ajax_check_location'));
        
        // Add handlers for form submission
        add_action('admin_post_ffb_save_settings', array($this, 'handle_save_settings'));
    }

    private function init_properties() {
        // Load API key
        $this->api_key = get_option('ffb_api_key', '');
        
        // Load approved countries
        $approved_countries = get_option('ffb_approved_countries', array('US'));
        $this->approved_countries = is_array($approved_countries) && !empty($approved_countries) ? $approved_countries : array('US');
        
        // Log the approved countries for debugging
        error_log('FFB Debug: Approved countries: ' . print_r($this->approved_countries, true));
        
        // Load approved states
        $approved_states = get_option('ffb_approved_states', array());
        $this->approved_states = is_array($approved_states) ? $approved_states : array();
        
        // Log the approved states for debugging
        error_log('FFB Debug: Approved states: ' . print_r($this->approved_states, true));
        
        // Load approved ZIP codes
        $approved_zip_codes = get_option('ffb_approved_zip_codes', array());
        $this->approved_zip_codes = is_array($approved_zip_codes) ? $approved_zip_codes : array();
        
        // Load blocked message
        $this->blocked_message = stripslashes(get_option('ffb_blocked_message', 'We apologize, but forms are not available in your location.'));
        
        // Load rate limiting settings
        $this->rate_limit_enabled = get_option('ffb_rate_limit_enabled', '1') === '1';
        $this->rate_limit_timeframe = get_option('ffb_rate_limit_timeframe', 3600);
        $this->rate_limit_requests = get_option('ffb_rate_limit_requests', 3);
        
        // Load blocked IPs for testing
        $blocked_ips = get_option('ffb_blocked_ips', '');
        $this->blocked_ips = is_array($blocked_ips) ? $blocked_ips : array();
        
        // Load IP whitelist
        $ip_whitelist = get_option('ffb_ip_whitelist', array());
        $this->ip_whitelist = is_array($ip_whitelist) ? $ip_whitelist : array();
        
        // Load IP blacklist
        $ip_blacklist = get_option('ffb_ip_blacklist', array());
        $this->ip_blacklist = is_array($ip_blacklist) ? $ip_blacklist : array();
        
        // Load logging settings
        $this->log_enabled = get_option('ffb_log_enabled', '1') === '1';
        
        // Load diagnostic mode setting
        $this->diagnostic_mode = get_option('ffb_diagnostic_mode', '0') === '1';
    }

    /**
     * Initialize the plugin
     */
    public function init() {
        // Initialize properties
        $this->init_properties();
        
        // Cache-busting notice
        if (is_admin()) {
            add_action('admin_notices', array($this, 'display_cache_notice'));
        }
        
        // Add JavaScript for location checking
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // Admin page
        add_action('admin_menu', array($this, 'add_admin_menu'));
        
        // Listen for AJAX submissions
        add_action('wp_ajax_ffb_log_form_submit', array($this, 'ajax_log_form_submit'));
        add_action('wp_ajax_nopriv_ffb_log_form_submit', array($this, 'ajax_log_form_submit'));
        
        // Formidable Forms integration
        add_filter('frm_validate_entry', array($this, 'validate_form_submission'), 20, 2);
        
        // Register shortcodes
        add_shortcode('ffb_location_check', array($this, 'location_check_shortcode'));
        add_shortcode('ffb_access_log', array($this, 'access_log_shortcode'));
        
        // Filter content (with caching precautions)
        add_filter('the_content', array($this, 'block_form'), 99);
        
        // Add AJAX endpoint for dynamic form visibility checking (CDN/cache compatible)
        add_action('wp_ajax_ffb_check_location', array($this, 'ajax_check_location'));
        add_action('wp_ajax_nopriv_ffb_check_location', array($this, 'ajax_check_location'));
        
        // Register assets for dynamic location checking
        add_action('wp_enqueue_scripts', array($this, 'register_assets'));
        add_action('admin_enqueue_scripts', array($this, 'register_admin_assets'));
    }
    
    /**
     * Register frontend assets
     */
    public function register_assets() {
        // Register frontend script but only enqueue it conditionally
        wp_register_script('ffb-frontend', plugins_url('js/ffb-frontend.js', __FILE__), array('jquery'), $this->version, true);
        
        // Always enqueue the script to avoid fatal errors
        wp_enqueue_script('ffb-frontend');
        
        // Localize frontend script with data
        wp_localize_script('ffb-frontend', 'ffbFrontendData', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ffb_check_location'),
            'hasForm' => '1'
        ));
        
        error_log('FFB Debug: Frontend script enqueued');
    }
    
    /**
     * Register admin assets
     */
    public function register_admin_assets() {
        // Only load on our plugin pages
        $screen = get_current_screen();
        if (!$screen || strpos($screen->id, 'ffb') === false) {
            return;
        }
        
        // Register and enqueue admin script
        wp_register_script('ffb-admin', plugins_url('js/ffb-admin.js', __FILE__), array('jquery'), $this->version, true);
        wp_enqueue_script('ffb-admin');
        
        // Localize admin script with data
        wp_localize_script('ffb-admin', 'ffbAdminData', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ffb_admin_nonce')
        ));
    }
    
    /**
     * Display cache notice
     */
    public function display_cache_notice() {
        // Only show in admin area
        if (!is_admin()) {
            return;
        }
        
        // Only show to users who can manage options
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Check if caching plugins are active
        $caching_plugins = array('wp-rocket/wp-rocket.php', 'w3-total-cache/w3-total-cache.php', 'wp-super-cache/wp-cache.php');
        $active_caching_plugins = array();
        foreach ($caching_plugins as $plugin) {
            if (is_plugin_active($plugin)) {
                $active_caching_plugins[] = $plugin;
            }
        }
        
        // If no caching plugins are active, don't show notice
        if (empty($active_caching_plugins)) {
            return;
        }
        
        // Display notice
        $message = 'You are using caching plugins that may interfere with the proper functioning of this plugin. Please ensure you have configured the caching plugins to exclude the <code>ffb_check_location</code> AJAX endpoint.';
        echo '<div class="notice notice-warning is-dismissible"><p>' . $message . '</p></div>';
    }

    public function add_admin_menu() {
        add_menu_page(
            'Formidable Forms Spam Blocker',
            'FF Spam Blocker',
            'manage_options',
            'ff-spam-blocker',
            array($this, 'settings_page'),
            'dashicons-shield',
            100
        );
        
        add_submenu_page(
            'ff-spam-blocker',
            'Settings',
            'Settings',
            'manage_options',
            'ff-spam-blocker',
            array($this, 'settings_page')
        );
        
        add_submenu_page(
            'ff-spam-blocker',
            'Access Logs',
            'Access Logs',
            'manage_options',
            'ff-spam-blocker-logs',
            array($this, 'logs_page')
        );
        
        // Add action to handle form submission
        add_action('admin_post_ffb_save_settings', array($this, 'handle_save_settings'));
        
        // Add debug action to directly update API key (temporary)
        add_action('admin_post_ffb_update_api_key', array($this, 'update_api_key'));
        
        // Add action to handle clearing the access log
        add_action('admin_post_ffb_clear_access_log', array($this, 'handle_clear_logs'));
        
        // Add action to manually create/recreate the access log table
        add_action('admin_post_ffb_create_table', array($this, 'manual_create_table'));
        
        // Add action to handle exporting logs to CSV
        add_action('admin_post_ffb_export_logs_csv', array($this, 'handle_export_logs_csv'));
    }
    
    /**
     * Emergency function to update API key directly
     */
    public function update_api_key() {
        // Only allow administrators
        if (!current_user_can('manage_options')) {
            wp_die('Access denied');
        }
        
        // Get the API key from the URL
        $api_key = isset($_GET['key']) ? sanitize_text_field($_GET['key']) : '';
        
        if (!empty($api_key)) {
            // Update the API key
            update_option('ffb_api_key', $api_key);
            error_log('FFB Debug: API key updated via emergency function');
            
            // Redirect back to settings page
            wp_redirect(admin_url('admin.php?page=ff-spam-blocker&settings-updated=true'));
            exit;
        }
        
        // If no key provided, redirect back with error
        wp_redirect(admin_url('admin.php?page=ff-spam-blocker&error=no-key'));
        exit;
    }

    public function logs_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Show success message if logs were cleared
        if (isset($_GET['ffb_logs_cleared']) && $_GET['ffb_logs_cleared'] === 'true') {
            echo '<div class="notice notice-success is-dismissible"><p>Access logs have been cleared successfully.</p></div>';
        }
        ?>
        <div class="wrap">
            <h1>Access Logs</h1>
            
            <div class="ffb-admin-actions" style="margin-bottom: 20px; display: flex; gap: 10px;">
                <!-- Clear Logs Button -->
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('ffb_clear_logs', 'ffb_clear_logs_nonce'); ?>
                    <input type="hidden" name="action" value="ffb_clear_access_log">
                    <input type="hidden" name="redirect_to" value="<?php echo esc_url(admin_url('admin.php?page=ff-spam-blocker-logs')); ?>">
                    <?php submit_button('Clear Access Logs', 'delete', 'submit', false, array(
                        'onclick' => 'return confirm("Are you sure you want to clear all access logs? This action cannot be undone.");'
                    )); ?>
                </form>
                
                <!-- Export to CSV Button -->
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('ffb_export_logs', 'ffb_export_logs_nonce'); ?>
                    <input type="hidden" name="action" value="ffb_export_logs_csv">
                    
                    <!-- Pass any active filters to the export -->
                    <?php if (!empty($_GET['start_date'])): ?>
                        <input type="hidden" name="start_date" value="<?php echo esc_attr($_GET['start_date']); ?>">
                    <?php endif; ?>
                    
                    <?php if (!empty($_GET['end_date'])): ?>
                        <input type="hidden" name="end_date" value="<?php echo esc_attr($_GET['end_date']); ?>">
                    <?php endif; ?>
                    
                    <?php if (!empty($_GET['ip_address'])): ?>
                        <input type="hidden" name="ip_address" value="<?php echo esc_attr($_GET['ip_address']); ?>">
                    <?php endif; ?>
                    
                    <?php if (!empty($_GET['country'])): ?>
                        <input type="hidden" name="country" value="<?php echo esc_attr($_GET['country']); ?>">
                    <?php endif; ?>
                    
                    <?php if (!empty($_GET['region'])): ?>
                        <input type="hidden" name="region" value="<?php echo esc_attr($_GET['region']); ?>">
                    <?php endif; ?>
                    
                    <?php if (!empty($_GET['status'])): ?>
                        <input type="hidden" name="status" value="<?php echo esc_attr($_GET['status']); ?>">
                    <?php endif; ?>
                    
                    <?php if (!empty($_GET['message'])): ?>
                        <input type="hidden" name="message" value="<?php echo esc_attr($_GET['message']); ?>">
                    <?php endif; ?>
                    
                    <input type="submit" class="button" value="Export to CSV">
                </form>
            </div>

            <?php $this->display_access_logs(); ?>
        </div>
        <?php
    }

    private function display_access_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
        
        error_log('FFB Debug: Starting display_access_logs');
        
        // Check if table exists
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") !== $table_name) {
            echo '<div class="notice notice-error"><p>' . __('Access log table does not exist. Try deactivating and reactivating the plugin.', 'aqm-formidable-spam-blocker') . '</p></div>';
            return;
        }
        
        // Get table columns to ensure we only query for existing columns
        $columns = $wpdb->get_results("SHOW COLUMNS FROM $table_name");
        $column_names = array();
        foreach ($columns as $column) {
            $column_names[] = $column->Field;
        }
        
        error_log('FFB Debug: Table columns: ' . implode(', ', $column_names));
        
        // Build WHERE clause based on filters
        $where_clauses = array();
        $query_args = array();
        
        // Date range filter
        if (!empty($_GET['start_date'])) {
            $where_clauses[] = "timestamp >= %s";
            $query_args[] = $_GET['start_date'] . ' 00:00:00';
        }
        
        if (!empty($_GET['end_date'])) {
            $where_clauses[] = "timestamp <= %s";
            $query_args[] = $_GET['end_date'] . ' 23:59:59';
        }
        
        // IP address filter
        if (!empty($_GET['ip_address'])) {
            $where_clauses[] = "ip_address LIKE %s";
            $query_args[] = '%' . $wpdb->esc_like($_GET['ip_address']) . '%';
        }
        
        // Country filter
        if (!empty($_GET['country']) && in_array('country_code', $column_names)) {
            $where_clauses[] = "(country_code LIKE %s OR country_name LIKE %s)";
            $query_args[] = '%' . $wpdb->esc_like($_GET['country']) . '%';
            $query_args[] = '%' . $wpdb->esc_like($_GET['country']) . '%';
        }
        
        // Region filter
        if (!empty($_GET['region']) && in_array('region_name', $column_names)) {
            $where_clauses[] = "(region_code LIKE %s OR region_name LIKE %s)";
            $query_args[] = '%' . $wpdb->esc_like($_GET['region']) . '%';
            $query_args[] = '%' . $wpdb->esc_like($_GET['region']) . '%';
        }
        
        // Status filter
        if (!empty($_GET['status']) && in_array('status', $column_names)) {
            $where_clauses[] = "status = %s";
            $query_args[] = $_GET['status'];
        }
        
        // Message filter
        if (!empty($_GET['message'])) {
            if (in_array('reason', $column_names)) {
                $where_clauses[] = "reason LIKE %s";
                $query_args[] = '%' . $wpdb->esc_like($_GET['message']) . '%';
            }
        }
        
        // Pagination
        $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($current_page - 1) * $per_page;
        
        // Build the WHERE clause string
        $where_sql = '';
        if (!empty($where_clauses)) {
            $where_sql = 'WHERE ' . implode(' AND ', $where_clauses);
        }
        
        // Get the total number of filtered records
        $total_query = "SELECT COUNT(*) FROM $table_name $where_sql";
        if (!empty($query_args)) {
            $total_query = $wpdb->prepare($total_query, $query_args);
        }
        $total_items = $wpdb->get_var($total_query);
        
        error_log('FFB Debug: Total filtered records: ' . $total_items);
        
        // Get the filtered records
        $query = "SELECT * FROM $table_name $where_sql ORDER BY timestamp DESC LIMIT %d OFFSET %d";
        $query_args[] = $per_page;
        $query_args[] = $offset;
        
        $prepared_query = $wpdb->prepare($query, $query_args);
        error_log('FFB Debug: Prepared query: ' . $prepared_query);
        
        $results = $wpdb->get_results($prepared_query);
        
        error_log('FFB Debug: Query results count: ' . count($results));
        
        // Continue with existing display code...
        if (empty($results)) {
            echo '<div class="notice notice-info"><p>No access logs found matching your filters. Try adjusting your search criteria.</p></div>';
            return;
        }

        // Debug the first result to see what data we have
        if (!empty($results)) {
            error_log('FFB Debug: First result data: ' . print_r($results[0], true));
        }

        // Display filter form
        ?>
        <form method="get" action="" class="ffb-filters">
            <input type="hidden" name="page" value="<?php echo esc_attr($_GET['page']); ?>">
            
            <div class="ffb-filter-row">
                <label>
                    Date Range:
                    <input type="date" name="start_date" value="<?php echo esc_attr($_GET['start_date'] ?? ''); ?>">
                    to
                    <input type="date" name="end_date" value="<?php echo esc_attr($_GET['end_date'] ?? ''); ?>">
                </label>
                
                <label>
                    IP Address:
                    <input type="text" name="ip_address" value="<?php echo esc_attr($_GET['ip_address'] ?? ''); ?>" placeholder="Search IP...">
                </label>
                
                <label>
                    Country:
                    <select name="country">
                        <option value="">All Countries</option>
                        <?php 
                        // Get unique countries from the database
                        $countries = $wpdb->get_col("SELECT DISTINCT country_code FROM $table_name WHERE country_code != '' ORDER BY country_code");
                        foreach ($countries as $country): 
                        ?>
                            <option value="<?php echo esc_attr($country); ?>" <?php selected($_GET['country'] ?? '', $country); ?>>
                                <?php echo esc_html($country); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
                
                <label>
                    State:
                    <select name="region">
                        <option value="">All States</option>
                        <?php 
                        // Get unique regions from the database
                        $regions = $wpdb->get_col("SELECT DISTINCT region_name FROM $table_name WHERE region_name != '' ORDER BY region_name");
                        foreach ($regions as $region): 
                        ?>
                            <option value="<?php echo esc_attr($region); ?>" <?php selected($_GET['region'] ?? '', $region); ?>>
                                <?php echo esc_html($region); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
                
                <label>
                    Status:
                    <select name="status">
                        <option value="">All Statuses</option>
                        <option value="blocked" <?php selected($_GET['status'] ?? '', 'blocked'); ?>>Blocked</option>
                        <option value="allowed" <?php selected($_GET['status'] ?? '', 'allowed'); ?>>Allowed</option>
                    </select>
                </label>
                
                <label>
                    Message:
                    <input type="text" name="message" value="<?php echo esc_attr($_GET['message'] ?? ''); ?>" placeholder="Search message...">
                </label>
                
                <input type="submit" class="button" value="Apply Filters">
                <a href="<?php echo esc_url(remove_query_arg(array('start_date', 'end_date', 'ip_address', 'country', 'region', 'status', 'message', 'paged'))); ?>" class="button">Reset Filters</a>
            </div>
        </form>

        <div class="ffb-actions" style="margin: 15px 0;">
            <!-- Clear logs button -->
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display: inline-block;">
                <?php wp_nonce_field('ffb_clear_log', 'ffb_clear_log_nonce'); ?>
                <input type="hidden" name="action" value="ffb_clear_access_log">
                
                <input type="submit" class="button" value="Clear All Logs" onclick="return confirm('Are you sure you want to clear all logs? This action cannot be undone.');">
            </form>
            
            <!-- Export to CSV button -->
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display: inline-block; margin-left: 10px;">
                <?php wp_nonce_field('ffb_export_logs', 'ffb_export_logs_nonce'); ?>
                <input type="hidden" name="action" value="ffb_export_logs_csv">
                
                <!-- Pass current filters to the export -->
                <?php if (!empty($_GET['start_date'])): ?>
                    <input type="hidden" name="start_date" value="<?php echo esc_attr($_GET['start_date']); ?>">
                <?php endif; ?>
                
                <?php if (!empty($_GET['end_date'])): ?>
                    <input type="hidden" name="end_date" value="<?php echo esc_attr($_GET['end_date']); ?>">
                <?php endif; ?>
                
                <?php if (!empty($_GET['ip_address'])): ?>
                    <input type="hidden" name="ip_address" value="<?php echo esc_attr($_GET['ip_address']); ?>">
                <?php endif; ?>
                
                <?php if (!empty($_GET['country'])): ?>
                    <input type="hidden" name="country" value="<?php echo esc_attr($_GET['country']); ?>">
                <?php endif; ?>
                
                <?php if (!empty($_GET['region'])): ?>
                    <input type="hidden" name="region" value="<?php echo esc_attr($_GET['region']); ?>">
                <?php endif; ?>
                
                <?php if (!empty($_GET['status'])): ?>
                    <input type="hidden" name="status" value="<?php echo esc_attr($_GET['status']); ?>">
                <?php endif; ?>
                
                <?php if (!empty($_GET['message'])): ?>
                    <input type="hidden" name="message" value="<?php echo esc_attr($_GET['message']); ?>">
                <?php endif; ?>
                
                <input type="submit" class="button button-primary" value="Export to CSV">
            </form>
        </div>

        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Reason</th>
                    <th>Form ID</th>
                    <th>Log Type</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($results as $log): 
                    // Try to get geo data if it exists
                    $geo_data = [];
                    if (isset($log->geo_data) && !empty($log->geo_data)) {
                        $geo_data = json_decode($log->geo_data, true);
                        error_log('FFB Debug: Decoded geo_data for log ID ' . $log->id . ': ' . print_r($geo_data, true));
                    }
                    
                    // Get country from different possible sources
                    $country = '';
                    if (isset($log->country_name) && !empty($log->country_name) && $log->country_name !== 'Unknown') {
                        $country = $log->country_name;
                        error_log('FFB Debug: Using country_name from log: ' . $country);
                    } elseif (isset($geo_data['country_name']) && !empty($geo_data['country_name'])) {
                        $country = $geo_data['country_name'];
                        error_log('FFB Debug: Using country_name from geo_data: ' . $country);
                    } elseif (isset($geo_data['country']) && !empty($geo_data['country'])) {
                        $country = $geo_data['country'];
                        error_log('FFB Debug: Using country from geo_data: ' . $country);
                    }
                    
                    // Get region from different possible sources
                    $region = '';
                    if (isset($log->region_name) && !empty($log->region_name) && $log->region_name !== 'Unknown') {
                        $region = $log->region_name;
                        error_log('FFB Debug: Using region_name from log: ' . $region);
                    } elseif (isset($geo_data['region_name']) && !empty($geo_data['region_name'])) {
                        $region = $geo_data['region_name'];
                        error_log('FFB Debug: Using region_name from geo_data: ' . $region);
                    } elseif (isset($geo_data['region_code']) && !empty($geo_data['region_code'])) {
                        $region = $geo_data['region_code'];
                        error_log('FFB Debug: Using region_code from geo_data: ' . $region);
                    } elseif (isset($geo_data['region']) && !empty($geo_data['region'])) {
                        $region = $geo_data['region'];
                        error_log('FFB Debug: Using region from geo_data: ' . $region);
                    } elseif (isset($geo_data['regionName']) && !empty($geo_data['regionName'])) {
                        $region = $geo_data['regionName'];
                        error_log('FFB Debug: Using regionName from geo_data: ' . $region);
                    } elseif (isset($geo_data['regionCode']) && !empty($geo_data['regionCode'])) {
                        $region = $geo_data['regionCode'];
                        error_log('FFB Debug: Using regionCode from geo_data: ' . $region);
                    } elseif (isset($geo_data['state']) && !empty($geo_data['state'])) {
                        $region = $geo_data['state'];
                        error_log('FFB Debug: Using state from geo_data: ' . $region);
                    } elseif (isset($geo_data['subdivision_1_name']) && !empty($geo_data['subdivision_1_name'])) {
                        $region = $geo_data['subdivision_1_name'];
                        error_log('FFB Debug: Using subdivision_1_name from geo_data: ' . $region);
                    } elseif (isset($geo_data['subdivision_1_code']) && !empty($geo_data['subdivision_1_code'])) {
                        $region = $geo_data['subdivision_1_code'];
                        error_log('FFB Debug: Using subdivision_1_code from geo_data: ' . $region);
                    }
                    
                    // Convert to strings to ensure proper display
                    $country = (string)$country;
                    $region = (string)$region;
                ?>
                    <tr>
                        <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($log->timestamp))); ?></td>
                        <td><?php echo esc_html($log->ip_address); ?></td>
                        <td><?php echo esc_html($country); ?></td>
                        <td><?php echo esc_html($region); ?></td>
                        <td><?php echo isset($log->status) ? esc_html($log->status) : ''; ?></td>
                        <td><?php echo isset($log->reason) ? esc_html($log->reason) : ''; ?></td>
                        <td><?php echo isset($log->form_id) ? esc_html($log->form_id) : ''; ?></td>
                        <td><?php echo isset($log->log_type) ? esc_html($log->log_type) : 'form_load'; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php
        // Add pagination
        if ($total_items > $per_page) {
            $total_pages = ceil($total_items / $per_page);
            
            echo '<div class="ffb-pagination">';
            echo paginate_links(array(
                'base' => add_query_arg('paged', '%#%'),
                'format' => '',
                'prev_text' => __('&laquo;'),
                'next_text' => __('&raquo;'),
                'total' => $total_pages,
                'current' => $current_page,
                'type' => 'list'
            ));
            echo '</div>';
        }
    }

    public function handle_clear_logs() {
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }

        check_admin_referer('ffb_clear_logs', 'ffb_clear_logs_nonce');
        
        $this->clear_access_logs();
        
        wp_redirect(add_query_arg('ffb_logs_cleared', 'true', admin_url('admin.php?page=ff-spam-blocker-logs')));
        exit;
    }

    public function clear_access_logs() {
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized access');
        }

        check_admin_referer('ffb_clear_logs', 'ffb_clear_logs_nonce');

        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';

        // Clear the access logs
        $wpdb->query("TRUNCATE TABLE $table_name");

        // Redirect back to the logs page
        wp_redirect(add_query_arg('ffb_logs_cleared', 'true', admin_url('admin.php?page=ff-spam-blocker-logs')));
        exit;
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

    public function check_location($ip_address = null) {
        if (!$ip_address) {
            $ip_address = $this->get_client_ip();
        }

        error_log('FFB Debug: Starting check_location for IP: ' . $ip_address);

        // Only check if we haven't already or if a specific IP is provided
        if ($this->geo_data === null || $ip_address !== null) {
            $this->geo_data = $this->get_geo_data($ip_address);
            if ($this->geo_data) {
                $this->is_blocked = $this->is_location_blocked($this->geo_data);
                error_log('FFB Debug: Location check - IP: ' . $ip_address . ' Blocked: ' . ($this->is_blocked ? 'Yes' : 'No'));
                error_log('FFB Debug: Geo Data: ' . print_r($this->geo_data, true));
                error_log('FFB Debug: Allowed States: ' . print_r($this->approved_states, true));
                error_log('FFB Debug: Allowed Countries: ' . print_r($this->approved_countries, true));
                
                // Log the access attempt if logging is enabled
                if ($this->log_enabled) {
                    $this->log_access_attempt(
                        $ip_address,
                        $this->is_blocked ? 'blocked' : 'allowed',
                        $this->is_blocked ? 'Access blocked' : 'Access allowed',
                        0, // form_id is 0 since we're just checking location
                        'location_check' // custom log type for location checks
                    );
                }
            }
        }
        
        return $this->geo_data;
    }

    public function get_geo_data($ip = null, $force_refresh = false) {
        // If no IP provided, get the current client IP
        if (empty($ip)) {
            $ip = $this->get_client_ip();
        }
        
        // Check if we already have the data in the instance
        if (!$force_refresh && $this->geo_data !== null) {
            return $this->geo_data;
        }
        
        // Check if the IP is private
        if ($this->is_private_ip($ip)) {
            error_log('FFB Debug: IP ' . $ip . ' is a private IP, skipping geolocation');
            return array();
        }
        
        // Check if we have cached data
        $cache_key = 'ffb_geo_' . md5($ip);
        $cached_data = get_transient($cache_key);
        
        if (!$force_refresh && $cached_data !== false) {
            // Store in instance variable
            $this->geo_data = $cached_data;
            error_log('FFB Debug: Using cached geolocation data for IP ' . $ip);
            return $cached_data;
        }
        
        // Get the API key
        $this->api_key = defined('FFB_API_KEY') ? FFB_API_KEY : get_option('ffb_api_key', '');
        
        // If no API key, return empty data
        if (empty($this->api_key)) {
            error_log('FFB Debug: No API key configured');
            return array();
        }
        
        // Make the API request
        error_log('FFB Debug: Making API request for IP ' . $ip);
        $api_url = 'https://api.ipapi.com/api/' . $ip . '?access_key=' . $this->api_key;
        
        // Add additional debug logging for the API URL
        error_log('FFB Debug: Full API URL: ' . $api_url);
        
        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
            'user-agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
        ));
        
        if (is_wp_error($response)) {
            error_log('FFB Debug: API request error: ' . $response->get_error_message());
            return array();
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        // Debug the API response
        error_log('FFB Debug: Raw API response for IP ' . $ip . ': ' . $body);
        
        // Debug the exact structure
        if (is_array($data)) {
            error_log('FFB Debug: API response array keys: ' . implode(', ', array_keys($data)));
            
            // Ensure we have region and country data
            // ipapi.com uses region_name and country_name, make sure they're set
            if (isset($data['region_code']) && !isset($data['region_name'])) {
                $data['region_name'] = $data['region_code'];
                error_log('FFB Debug: Set region_name from region_code: ' . $data['region_name']);
            }
            
            if (isset($data['region']) && !isset($data['region_name']) && !isset($data['region_code'])) {
                $data['region_name'] = $data['region'];
                $data['region_code'] = $data['region'];
                error_log('FFB Debug: Set region_name and region_code from region: ' . $data['region']);
            }
            
            if (isset($data['country_code']) && !isset($data['country_name'])) {
                $data['country_name'] = $data['country_code'];
                error_log('FFB Debug: Set country_name from country_code: ' . $data['country_name']);
            }
            
            if (isset($data['country']) && !isset($data['country_name']) && !isset($data['country_code'])) {
                $data['country_name'] = $data['country'];
                $data['country_code'] = $data['country'];
                error_log('FFB Debug: Set country_name and country_code from country: ' . $data['country']);
            }
            
            // Log region-specific keys if they exist
            if (isset($data['region_name'])) {
                error_log('FFB Debug: Found region_name: ' . $data['region_name']);
            } elseif (isset($data['region_code'])) {
                error_log('FFB Debug: Found region_code: ' . $data['region_code']);
            } elseif (isset($data['region'])) {
                error_log('FFB Debug: Found region: ' . $data['region']);
            } elseif (isset($data['regionName'])) {
                error_log('FFB Debug: Found regionName: ' . $data['regionName']);
            } elseif (isset($data['regionCode'])) {
                error_log('FFB Debug: Found regionCode: ' . $data['regionCode']);
            } elseif (isset($data['state'])) {
                error_log('FFB Debug: Found state: ' . $data['state']);
            } elseif (isset($data['subdivision_1_name'])) {
                error_log('FFB Debug: Found subdivision_1_name: ' . $data['subdivision_1_name']);
            } elseif (isset($data['subdivision_1_code'])) {
                error_log('FFB Debug: Found subdivision_1_code: ' . $data['subdivision_1_code']);
            }
            
            // Log country-specific keys
            if (isset($data['country_name'])) {
                error_log('FFB Debug: Found country_name: ' . $data['country_name']);
            } elseif (isset($data['country_code'])) {
                error_log('FFB Debug: Found country_code: ' . $data['country_code']);
            } elseif (isset($data['countryName'])) {
                error_log('FFB Debug: Found countryName: ' . $data['countryName']);
            } elseif (isset($data['countryCode'])) {
                error_log('FFB Debug: Found countryCode: ' . $data['countryCode']);
            }
        }
        
        if (empty($data) || !is_array($data) || isset($data['status']) && $data['status'] === 'fail') {
            $error_msg = isset($data['message']) ? $data['message'] : 'Unknown error';
            error_log('FFB Debug: API returned error: ' . $error_msg);
            return array();
        }
        
        // Cache the data for 1 hour
        set_transient($cache_key, $data, 3600);
        
        // Store in instance variable
        $this->geo_data = $data;
        
        return $data;
    }

    /**
     * Check if an IP address is private
     */
    private function is_private_ip($ip) {
        // Check if IP is in private ranges
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false || 
               filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false;
    }

    public function get_client_ip() {
        // Check if FrmAppHelper exists and use its method
        if (class_exists('FrmAppHelper') && method_exists('FrmAppHelper', 'get_ip_address')) {
            $ip = FrmAppHelper::get_ip_address();
            
            // Log the IP detection process for debugging
            error_log('FFB Debug: Using Formidable Forms IP detection. Detected IP: ' . $ip);
            
            return $ip;
        }
        
        // Fallback to our own implementation if Formidable Forms' method is not available
        // Start with REMOTE_ADDR as the most reliable source
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        
        // Only consider forwarded headers if the request is from a trusted proxy
        if ($this->is_trusted_proxy($ip)) {
            $forwarded_headers = array(
                'HTTP_CLIENT_IP',
                'HTTP_CF_CONNECTING_IP', // Cloudflare
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_FORWARDED',
                'HTTP_X_CLUSTER_CLIENT_IP',
                'HTTP_X_REAL_IP',
                'HTTP_FORWARDED_FOR',
                'HTTP_FORWARDED'
            );
            
            foreach ($forwarded_headers as $header) {
                if (isset($_SERVER[$header])) {
                    // For X-Forwarded-For, the first IP is usually the client's real IP
                    $header_value = $_SERVER[$header];
                    $ips = explode(',', $header_value);
                    
                    foreach ($ips as $potential_ip) {
                        $potential_ip = trim($potential_ip);
                        
                        // Validate the IP format and ensure it's not a private/reserved range
                        if (filter_var($potential_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                            $ip = $potential_ip;
                            break 2; // Break both loops
                        }
                    }
                }
            }
        }
        
        // Log the IP detection process for debugging
        error_log('FFB Debug: Using fallback IP detection. Detected IP: ' . $ip . ' from ' . 
                 (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown User Agent'));
        
        return $ip;
    }
    
    /**
     * Check if an IP is a trusted proxy
     * This can be customized to include known proxy IPs for your server setup
     */
    private function is_trusted_proxy($ip) {
        // Define trusted proxies - customize this based on your server infrastructure
        // For example, if you're behind Cloudflare, you might want to include their IPs
        $trusted_proxies = array(
            '127.0.0.1',      // Localhost
            '::1'             // IPv6 localhost
            // Add your server's trusted proxies here
        );
        
        // Check if the IP is in the trusted proxies list
        return in_array($ip, $trusted_proxies);
    }

    public function is_location_blocked($geo_data) {
        try {
            if (empty($geo_data)) {
                // If no geo data, default to blocking for safety
                error_log('IPAPI Error: Unable to retrieve geo data for IP: ' . $this->get_client_ip());
                
                // If diagnostic mode is enabled, don't block when geo data is missing
                if ($this->diagnostic_mode) {
                    error_log('FFB Diagnostic: Allowing submission despite missing geo data (diagnostic mode enabled)');
                    return false;
                }
                
                // Block submission if we can't get geo data - safer default
                return true;
            }
            
            // Check country
            if (!empty($geo_data['country_code'])) {
                $country_code = strtoupper($geo_data['country_code']);
                $approved_countries = array_map('strtoupper', $this->approved_countries);
                
                error_log('FFB Debug: Checking country: ' . $country_code . ' against approved countries: ' . implode(',', $approved_countries));
                
                if (!in_array($country_code, $approved_countries)) {
                    error_log('FFB Debug: Country blocked: ' . $country_code . ' - Approved countries: ' . implode(',', $approved_countries));
                    return true;
                }
            }
            
            // If in US, check state
            if (isset($geo_data['country_code']) && strtoupper($geo_data['country_code']) == 'US' && !empty($geo_data['region_code'])) {
                $region_code = strtoupper($geo_data['region_code']);
                $approved_states_upper = array_map('strtoupper', $this->get_approved_states());
                
                error_log('FFB Debug: Checking state: ' . $region_code . ' against approved states: ' . implode(',', $approved_states_upper));
                
                // If approved states list is empty, allow all states
                if (empty($approved_states_upper)) {
                    error_log('FFB Debug: No approved states configured, allowing all states');
                    return false;
                }
                
                if (!in_array($region_code, $approved_states_upper)) {
                    error_log('FFB Debug: State blocked: ' . $region_code);
                    return true;
                } else {
                    error_log('FFB Debug: State allowed: ' . $region_code);
                    // State is approved, no need to check ZIP
                    return false;
                }
            }
            
            // Check ZIP code if available and if we're in the US
            if (isset($geo_data['country_code']) && strtoupper($geo_data['country_code']) == 'US' && 
                !empty($geo_data['zip']) && !empty($this->approved_zip_codes)) {
                $zip = substr($geo_data['zip'], 0, 5); // Get first 5 digits for US zip codes
                
                // If we have a non-empty approved ZIP list, check against it
                if (!empty($this->approved_zip_codes)) {
                    if (!in_array($zip, $this->approved_zip_codes)) {
                        error_log('FFB Debug: ZIP code blocked: ' . $zip);
                        return true;
                    } else {
                        error_log('FFB Debug: ZIP code allowed: ' . $zip);
                        return false;
                    }
                }
            }
            
            // If we get here, location is allowed
            error_log('FFB Debug: Location allowed');
            return false;
        } catch (Exception $e) {
            error_log('FFB Error in is_location_blocked: ' . $e->getMessage());
            
            // If diagnostic mode is enabled, don't block on errors
            if ($this->diagnostic_mode) {
                error_log('FFB Diagnostic: Allowing submission despite error (diagnostic mode enabled)');
                return false;
            }
            
            // Default to blocking if there's an error
            return true;
        }
    }

    public function replace_forms_with_message($content, $message) {
        error_log('FFB Debug: Replacing forms with message');
        
        // Replace Formidable Forms shortcodes with message
        $pattern = '/\[formidable.*?\]/';
        $replacement = '<div class="ffb-blocked-message">' . $message . '</div>';
        $content = preg_replace($pattern, $replacement, $content);
        
        // Also handle Formidable Forms rendered via HTML - form element with frm_pro_form class
        $form_pattern = '/<form[^>]*class="[^"]*frm[_-]pro[_-]form[^"]*".*?>.*?<\/form>/s';
        $content = preg_replace($form_pattern, $replacement, $content);
        
        // Handle forms with other frm classes (needed for mobile)
        $form_pattern2 = '/<form[^>]*class="[^"]*frm[_-].*?".*?>.*?<\/form>/s';
        $content = preg_replace($form_pattern2, $replacement, $content);
        
        // Handle div container with frm_forms class
        $div_pattern = '/<div[^>]*class="[^"]*frm_forms.*?".*?>.*?<form.*?>.*?<\/form>.*?<\/div>/s';
        $content = preg_replace($div_pattern, $replacement, $content);
        
        error_log('FFB Debug: Form replacement complete');
        return $content;
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
        
        // Remove duplicates and empty values
        $approved_states = array_filter(array_unique($approved_states));
        
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
        
        // Remove duplicates and empty values
        $approved_zip_codes = array_filter(array_unique($approved_zip_codes));
        
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
        
        // Enqueue the geo-blocker script with cache busting
        $js_version = '2.1.83-' . time(); // Add timestamp for cache busting
        wp_enqueue_script('ffb-geo-blocker', plugin_dir_url(__FILE__) . 'geo-blocker.js', array('jquery'), $js_version, true);
        
        // Enqueue the styles
        wp_enqueue_style('ffb-styles', plugin_dir_url(__FILE__) . 'style.css', array(), '2.1.83');
        
        // Add honeypot CSS
        $honeypot_css = "
            .ffb-honeypot-field {
                position: absolute !important;
                left: -9999px !important;
                top: -9999px !important;
                opacity: 0 !important;
                height: 0 !important;
                width: 0 !important;
                z-index: -1 !important;
                pointer-events: none !important;
            }
        ";
        wp_add_inline_style('ffb-styles', $honeypot_css);
        
        // Add honeypot field to forms via JavaScript
        $honeypot_js = "
            jQuery(document).ready(function(\$) {
                // Add honeypot field to all Formidable forms
                \$('.frm_forms').each(function() {
                    var \$form = \$(this).find('form');
                    if (\$form.length && !\$form.find('.ffb-honeypot-field').length) {
                        $('<div class=\"ffb-honeypot-field\"><label for=\"ffb_website\">Website</label><input type=\"text\" name=\"ffb_website\" id=\"ffb_website\" autocomplete=\"off\"></div>').appendTo(\$form);
                    }
                });
                
                // Also handle dynamically loaded forms
                \$(document).on('frmFormComplete', function(event, form, response) {
                    var \$form = \$(form);
                    if (\$form.length && !\$form.find('.ffb-honeypot-field').length) {
                        $('<div class=\"ffb-honeypot-field\"><label for=\"ffb_website\">Website</label><input type=\"text\" name=\"ffb_website\" id=\"ffb_website\" autocomplete=\"off\"></div>').appendTo(\$form);
                    }
                });
            });
        ";
        wp_add_inline_script('ffb-geo-blocker', $honeypot_js);
        
        // Localize the script with necessary data
        wp_localize_script('ffb-geo-blocker', 'ffbGeoBlocker', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'api_url' => 'https://api.ipapi.com/api/', // Reverted back to ipapi.com
            'api_key' => defined('FFB_API_KEY') ? FFB_API_KEY : get_option('ffb_api_key', ''),
            'approved_states' => $approved_states,
            'approved_countries' => $approved_countries,
            'approved_zip_codes' => $approved_zip_codes,
            'zip_validation_enabled' => $zip_validation_enabled,
            'is_admin' => current_user_can('manage_options'),
            'testing_own_ip' => in_array($_SERVER['REMOTE_ADDR'], $this->blocked_ips),
            'blocked_message' => $this->get_blocked_message()
        ));
        
        // Localize the script with AJAX data
        wp_localize_script('ffb-geo-blocker', 'ffb_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ffb_admin_nonce')
        ));
    }

    public function admin_scripts($hook) {
        // Only load on our plugin pages
        if (strpos($hook, 'ff-spam-blocker') === false) {
            return;
        }
        
        // Enqueue jQuery and jQuery UI
        wp_enqueue_script('jquery');
        wp_enqueue_script('jquery-ui-core');
        wp_enqueue_script('jquery-ui-tabs');
        wp_enqueue_script('jquery-ui-datepicker');
        
        // Enqueue Select2 for better dropdowns
        wp_enqueue_script('select2', 'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js', array('jquery'), '4.1.0', true);
        wp_enqueue_style('select2', 'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css', array(), '4.1.0');
        
        // Enqueue our admin script
        wp_enqueue_script('ffb-admin', plugin_dir_url(__FILE__) . 'assets/js/admin.js', array('jquery', 'jquery-ui-tabs', 'select2'), '2.1.83', true);
        
        // Enqueue our admin styles
        wp_enqueue_style('ffb-admin-styles', plugin_dir_url(__FILE__) . 'assets/css/admin.css', array(), '2.1.83');
        
        // Pass data to the script
        wp_localize_script('ffb-admin', 'ffbAdminVars', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ffb_admin_nonce'),
            'api_key' => get_option('ffb_api_key', ''),
            'approved_countries' => $this->approved_countries,
            'approved_states' => $this->approved_states,
            'approved_zip_codes' => $this->approved_zip_codes,
            'diagnostic_mode' => $this->diagnostic_mode ? '1' : '0',
            'refreshing_usage' => __('Refreshing...', 'aqm-formidable-spam-blocker'),
            'strings' => array(
                'testing' => __('Testing...', 'aqm-formidable-spam-blocker'),
                'test_success' => __('API key is valid!', 'aqm-formidable-spam-blocker'),
                'test_error' => __('Error testing API key', 'aqm-formidable-spam-blocker'),
                'confirm_delete' => __('Are you sure you want to delete this IP?', 'aqm-formidable-spam-blocker'),
                'confirm_clear' => __('Are you sure you want to clear all logs?', 'aqm-formidable-spam-blocker'),
                'searching' => __('Searching...', 'aqm-formidable-spam-blocker'),
                'no_results' => __('No results found', 'aqm-formidable-spam-blocker')
            )
        ));
    }

    public function validate_form_submission($errors, $values) {
        try {
            error_log('FFB Debug: validate_submission called for form ID: ' . (isset($values['form_id']) ? $values['form_id'] : 'unknown'));
            
            // Get client IP
            $ip = $this->get_client_ip();
            error_log('FFB Debug: Client IP: ' . $ip);
            
            // Skip validation for whitelisted IPs
            if ($this->is_ip_whitelisted($ip)) {
                error_log('FFB Debug: IP is whitelisted, skipping validation');
                return $errors;
            }
            
            // Block blacklisted IPs
            if ($this->is_ip_blacklisted($ip)) {
                error_log('FFB Debug: IP is blacklisted, blocking submission');
                $errors['ffb_location'] = $this->get_blocked_message();
                return $errors;
            }
            
            // Get geolocation data
            $geo_data = $this->get_geo_data($ip);
            
            // Check if location is blocked
            if ($this->is_location_blocked($geo_data)) {
                error_log('FFB Debug: Location is blocked, adding validation error');
                $errors['ffb_location'] = $this->get_blocked_message();
                
                // Log the blocked submission attempt
                $this->log_access_attempt($ip, 'blocked', 'Location blocked', isset($values['form_id']) ? $values['form_id'] : '', 'form_submit');
            } else {
                // Log the allowed submission attempt
                $this->log_access_attempt($ip, 'allowed', 'Location allowed', isset($values['form_id']) ? $values['form_id'] : '', 'form_submit');
            }
            
            return $errors;
        } catch (Exception $e) {
            error_log('FFB Error in validate_submission: ' . $e->getMessage());
            
            // If diagnostic mode is enabled, don't block on errors
            if ($this->diagnostic_mode) {
                error_log('FFB Diagnostic: Allowing submission despite error (diagnostic mode enabled)');
                return $errors;
            }
            
            // Add error message if there's an exception
            $errors['ffb_location'] = 'Error validating submission location. Please try again later.';
            return $errors;
        }
    }
    
    /**
     * Pre-create entry filter for Formidable Forms
     * 
     * @param array $values Form values
     * @param array $params Additional parameters
     * @return array Form values
     */
    public function pre_create_entry($values, $params = array()) {
        try {
            error_log('FFB Debug: pre_create_entry called for form ID: ' . (isset($values['form_id']) ? $values['form_id'] : 'unknown'));
            
            // Get client IP
            $ip = $this->get_client_ip();
            
            // Skip validation for whitelisted IPs
            if ($this->is_ip_whitelisted($ip)) {
                error_log('FFB Debug: IP is whitelisted, allowing submission');
                return $values;
            }
            
            // Block blacklisted IPs
            if ($this->is_ip_blacklisted($ip)) {
                error_log('FFB Debug: IP is blacklisted, blocking submission');
                // We can't add errors here, so we'll just log it
                return $values;
            }
            
            // Get geolocation data
            $geo_data = $this->get_geo_data($ip);
            
            // Check if location is blocked
            if ($this->is_location_blocked($geo_data)) {
                error_log('FFB Debug: Location is blocked in pre_create_entry');
                // We can't add errors here, so we'll just log it
            }
            
            return $values;
        } catch (Exception $e) {
            error_log('FFB Error in pre_create_entry: ' . $e->getMessage());
            // Return values unchanged on error
            return $values;
        }
    }

    /**
     * Check if an IP address is in the whitelist
     * 
     * @param string $ip The IP address to check
     * @return bool True if IP is whitelisted, false otherwise
     */
    private function is_ip_whitelisted($ip) {
        // Load IP whitelist
        $ip_whitelist = get_option('ffb_ip_whitelist', array());
        $whitelist = is_array($ip_whitelist) ? $ip_whitelist : array();
        
        // Check if IP is in whitelist
        return in_array($ip, $whitelist);
    }
    
    /**
     * Check if an IP address is in the blacklist
     * 
     * @param string $ip The IP address to check
     * @return bool True if IP is blacklisted, false otherwise
     */
    public function is_ip_blacklisted($ip) {
        if (empty($ip) || !is_array($this->ip_blacklist)) {
            return false;
        }
        
        // Check for exact match
        if (in_array($ip, $this->ip_blacklist)) {
            return true;
        }
        
        // Check for wildcard matches (e.g., 192.168.*)
        foreach ($this->ip_blacklist as $blacklisted_ip) {
            if (strpos($blacklisted_ip, '*') !== false) {
                $pattern = '/^' . str_replace('*', '.*', $blacklisted_ip) . '$/';
                if (preg_match($pattern, $ip)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    public function block_form($content) {
        // Check if we're on a form page
        if (!$this->is_form_page($content)) {
            return $content;
        }
        
        // Get client IP
        $ip = $this->get_client_ip();
        
        // Check if IP is in the whitelist
        if ($this->is_ip_whitelisted($ip)) {
            error_log('FFB Debug: IP ' . $ip . ' is whitelisted, allowing form display');
            $this->log_access_attempt($ip, 'allowed', 'IP whitelisted', $this->get_form_id_from_content($content), 'form_load');
            return $content;
        }
        
        // Get geo data
        $geo_data = $this->get_geo_data($ip);
        
        // Debug the geo data
        error_log('FFB Debug: Geo data for IP ' . $ip . ': ' . print_r($geo_data, true));
        
        // Check if location is allowed
        if (!$this->is_location_allowed($geo_data)) {
            error_log('FFB Debug: Location not allowed for IP ' . $ip . ', blocking form');
            $this->log_access_attempt($ip, 'blocked', 'Location not allowed', $this->get_form_id_from_content($content), 'form_load');
            return $this->get_blocked_message();
        }
        
        // Check if IP is in the blacklist
        if ($this->is_ip_blacklisted($ip)) {
            error_log('FFB Debug: IP ' . $ip . ' is blacklisted, blocking form');
            $this->log_access_attempt($ip, 'blocked', 'IP blacklisted', $this->get_form_id_from_content($content), 'form_load');
            return $this->get_blocked_message();
        }
        
        // Log the allowed access
        $country_name = isset($geo_data['country_name']) ? $geo_data['country_name'] : 'Unknown';
        $region_name = isset($geo_data['region']) ? $geo_data['region'] : 'Unknown';
        $this->log_access_attempt($ip, 'allowed', 'Location allowed', $this->get_form_id_from_content($content), 'form_load');
        
        // Allow the form to be displayed
        return $content;
    }
    
    /**
     * Debug function to output detailed geolocation data and settings
     */
    private function debug_geo_data($ip, $geo_data) {
        // Create a detailed log message
        $debug = "FFB DETAILED DEBUG INFO:\n";
        $debug .= "IP: " . $ip . "\n";
        $debug .= "Timestamp: " . date('Y-m-d H:i:s') . "\n\n";
        
        // Geo data
        $debug .= "GEOLOCATION DATA:\n";
        if (empty($geo_data)) {
            $debug .= "No geolocation data available\n";
        } else {
            foreach ($geo_data as $key => $value) {
                $debug .= "$key: $value\n";
            }
        }
        $debug .= "\n";
        
        // Plugin settings
        $debug .= "PLUGIN SETTINGS:\n";
        $debug .= "Approved Countries: " . implode(', ', $this->approved_countries) . "\n";
        $debug .= "Approved States: " . implode(', ', $this->approved_states) . "\n";
        $debug .= "Approved ZIP Codes: " . implode(', ', $this->approved_zip_codes) . "\n";
        $debug .= "DB Option - ffb_approved_countries: " . get_option('ffb_approved_countries', 'NOT SET') . "\n";
        $debug .= "DB Option - ffb_approved_states: " . get_option('ffb_approved_states', 'NOT SET') . "\n";
        $debug .= "DB Option - ffb_approved_zip_codes: " . get_option('ffb_approved_zip_codes', 'NOT SET') . "\n\n";
        
        // Decision process
        $debug .= "DECISION PROCESS:\n";
        
        // Country check
        if (!empty($geo_data)) {
            $country_code = strtoupper($geo_data['country_code']);
            $approved_countries = array_map('strtoupper', $this->approved_countries);
            
            error_log('FFB Debug: Checking country: ' . $country_code . ' against approved countries: ' . implode(',', $approved_countries));
            
            // If approved countries list is empty, allow all countries
            if (empty($approved_countries)) {
                error_log('FFB Debug: No approved countries configured, allowing all countries');
                return;
            }
            
            if (!in_array($country_code, $approved_countries)) {
                error_log('FFB Debug: Country blocked: ' . $country_code . ' - Approved countries: ' . implode(',', $approved_countries));
                return;
            }
        }
        
        // State check
        if (isset($geo_data['country_code']) && strtoupper($geo_data['country_code']) == 'US' && !empty($geo_data['region_code'])) {
            $region_code = strtoupper($geo_data['region_code']);
            $approved_states_upper = array_map('strtoupper', $this->get_approved_states());
            
            error_log('FFB Debug: Checking state: ' . $region_code . ' against approved states: ' . implode(',', $approved_states_upper));
            
            // If approved states list is empty, allow all states
            if (empty($approved_states_upper)) {
                error_log('FFB Debug: No approved states configured, allowing all states');
                return;
            }
            
            if (!in_array($region_code, $approved_states_upper)) {
                error_log('FFB Debug: State blocked: ' . $region_code);
                return;
            } else {
                error_log('FFB Debug: State allowed: ' . $region_code);
                // State is approved, no need to check ZIP
                return;
            }
        }
        
        // ZIP check
        if (!empty($geo_data['zip']) && !empty($this->approved_zip_codes)) {
            $zip = substr($geo_data['zip'], 0, 5); // Get first 5 digits for US zip codes
            
            // If we have a non-empty approved ZIP list, check against it
            if (!empty($this->approved_zip_codes)) {
                if (!in_array($zip, $this->approved_zip_codes)) {
                    error_log('FFB Debug: ZIP code blocked: ' . $zip);
                    return;
                } else {
                    error_log('FFB Debug: ZIP code allowed: ' . $zip);
                    return;
                }
            }
        }
        
        // Log the debug info
        error_log($debug);
    }

    public function display_api_limit_warning() {
        // Only show in admin area
        if (!is_admin()) {
            return;
        }
        
        // Only show to users who can manage options
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Get API usage data
        $usage = get_option('ffb_api_usage', array());
        
        // If we don't have usage data or it's demo data, don't show warning
        if (empty($usage) || empty($usage['requests']) || empty($usage['limit']) || !empty($usage['is_demo'])) {
            return;
        }
        
        // Calculate usage percentage
        $percentage = ($usage['requests'] / $usage['limit']) * 100;
        
        // If usage is over 90%, show a warning
        if ($percentage >= 90) {
            $remaining = $usage['limit'] - $usage['requests'];
            $message = sprintf(
                'Warning: You have used %d%% of your monthly ipapi.com API limit (%d of %d requests). You have %d requests remaining this month. <a href="%s">View Settings</a>',
                round($percentage),
                $usage['requests'],
                $usage['limit'],
                $remaining,
                admin_url('admin.php?page=ff-spam-blocker')
            );
            
            echo '<div class="notice notice-warning is-dismissible"><p>' . $message . '</p></div>';
        }
        // If usage is over 75%, show a notice
        else if ($percentage >= 75) {
            $remaining = $usage['limit'] - $usage['requests'];
            $message = sprintf(
                'Notice: You have used %d%% of your monthly ipapi.com API limit (%d of %d requests). You have %d requests remaining this month. <a href="%s">View Settings</a>',
                round($percentage),
                $usage['requests'],
                $usage['limit'],
                $remaining,
                admin_url('admin.php?page=ff-spam-blocker')
            );
            
            echo '<div class="notice notice-info is-dismissible"><p>' . $message . '</p></div>';
        }
    }

    public function ajax_test_api_key() {
        // Verify nonce
        check_ajax_referer('ffb_admin_nonce', 'nonce');
        
        // Get the API key from the request
        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';
        
        if (empty($api_key)) {
            wp_send_json_error('API key is required');
            return;
        }
        
        // Basic validation of API key format
        $api_key = trim($api_key); // Remove any whitespace
        if (!preg_match('/^[a-zA-Z0-9]{32}$/', $api_key)) {
            error_log('FFB Debug: API key format appears invalid: ' . substr($api_key, 0, 5) . '...');
            wp_send_json_error('API Error: The API key format appears to be invalid. It should be a 32-character alphanumeric string without spaces or special characters.');
            return;
        }
        
        // Test the API key with a sample IP
        $test_ip = $this->get_client_ip(); // Use admin's actual IP instead of hardcoded value
        
        // Updated API URL format to use access_key parameter instead of key
        $api_url = "https://api.ipapi.com/api/{$test_ip}?access_key={$api_key}";
        
        // Log the API request for debugging
        error_log('FFB Debug: Testing API key with URL: ' . $api_url);
        
        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
            'user-agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
        ));
        
        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            error_log('FFB Debug: API request error: ' . $error_message);
            wp_send_json_error('API Error: ' . $error_message);
            return;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        // Log the response for debugging
        error_log('FFB Debug: API response status code: ' . $status_code);
        error_log('FFB Debug: API response body: ' . (strlen($body) > 1000 ? substr($body, 0, 1000) . '...' : $body));
        
        // Try to decode the JSON response
        $data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $json_error = json_last_error_msg();
            error_log('FFB Debug: JSON parsing error: ' . $json_error);
            wp_send_json_error('API Error: Invalid response format. JSON parsing error: ' . $json_error);
            return;
        }
        
        // Check if the API returned an error
        if (isset($data['success']) && $data['success'] === false) {
            $error_type = isset($data['error']['type']) ? $data['error']['type'] : 'Unknown error';
            $error_code = isset($data['error']['code']) ? $data['error']['code'] : '';
            $error_info = isset($data['error']['info']) ? $data['error']['info'] : '';
            
            $error_message = $error_info ? $error_info : $error_type;
            if ($error_code) {
                $error_message .= ' (Code: ' . $error_code . ')';
            }
            
            error_log('FFB Debug: API returned error: ' . $error_message);
            wp_send_json_error('API Error: ' . $error_message);
            return;
        }
        
        // Check if we have the expected data
        if (empty($data) || !isset($data['country_code'])) {
            error_log('FFB Debug: API response missing expected data');
            wp_send_json_error('API Error: Response missing expected data');
            return;
        }
        
        // If we got here, the API key is valid
        error_log('FFB Debug: API key test successful');
        wp_send_json_success(array(
            'message' => 'API key is valid. Location data received for ' . $test_ip . ': ' . $data['country_name'],
            'data' => $data
        ));
    }
    
    /**
     * AJAX handler for refreshing API usage
     */
    public function ajax_refresh_api_usage() {
        // Check nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'ffb_admin_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Get API key
        $api_key = $this->api_key;
        if (empty($api_key)) {
            wp_send_json_error('API key is not set');
            return;
        }

        // Get the current time
        $current_time = time();
        
        // Check if we have cached usage data that's less than 1 hour old
        $usage = get_option('ffb_api_usage', array());
        
        // If we have recent data (less than 1 hour old), return it
        if (!empty($usage) && isset($usage['last_check']) && ($current_time - $usage['last_check']) < 3600) {
            wp_send_json_success($usage);
            return;
        }
        
        // Try to get real usage data from the API
        // Use the usage endpoint specifically to get accurate cross-site data
        $api_url = 'https://api.ipapi.com/api/check?access_key=' . $api_key;
        
        error_log('FFB Debug: Refreshing API usage from ' . $api_url);
        
        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
            'user-agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
        ));
        
        if (is_wp_error($response)) {
            error_log('FFB Debug: API usage refresh error: ' . $response->get_error_message());
            wp_send_json_error($response->get_error_message());
            return;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('FFB Debug: API usage refresh error: Invalid API response (JSON error)');
            wp_send_json_error('Invalid API response');
            return;
        }

        // If we have valid data, format and return it
        if (isset($data['usage']) && isset($data['usage']['limit']) && isset($data['usage']['current'])) {
            // This endpoint gives us aggregate usage across all sites using the same API key
            $usage = array(
                'month' => date('Y-m'),
                'requests' => $data['usage']['current'],
                'limit' => $data['usage']['limit'],
                'last_check' => $current_time
            );
            
            error_log('FFB Debug: API usage updated. ' . $usage['requests'] . ' / ' . $usage['limit']);
            
            // Update the option with the new data
            update_option('ffb_api_usage', $usage);
            
            // Send response
            wp_send_json_success($usage);
            return;
        }
        
        // If the endpoint didn't return usage data but the response is valid
        if (isset($data)) {
            // Check if there's an error message in the API response
            if (isset($data['error']) && isset($data['error']['info'])) {
                error_log('FFB Debug: API usage refresh error: ' . $data['error']['info']);
                wp_send_json_error('API Error: ' . $data['error']['info']);
                return;
            }
            
            // Check if we can extract usage data from API response headers
            $headers = wp_remote_retrieve_headers($response);
            if ($headers && isset($headers['X-Rate-Limit-Limit']) && isset($headers['X-Rate-Limit-Remaining'])) {
                $limit = intval($headers['X-Rate-Limit-Limit']);
                $used = $limit - intval($headers['X-Rate-Limit-Remaining']);
                
                $usage = array(
                    'month' => date('Y-m'),
                    'requests' => $used,
                    'limit' => $limit,
                    'last_check' => $current_time
                );
                
                error_log('FFB Debug: API usage extracted from headers. ' . $usage['requests'] . ' / ' . $usage['limit']);
                
                // Update the option with the header data
                update_option('ffb_api_usage', $usage);
                
                // Send response
                wp_send_json_success($usage);
                return;
            }
        }
        
        // If we couldn't get real data, generate demo data
        $usage = array(
            'month' => date('Y-m'),
            'requests' => mt_rand(100, 5000), // Random number for demo
            'limit' => 10000,
            'last_check' => $current_time,
            'is_demo' => true // Flag to indicate this is demo data
        );
        
        error_log('FFB Debug: Using demo API usage data');
        
        // Update the option with the demo data
        update_option('ffb_api_usage', $usage);
        
        // Send response
        wp_send_json_success($usage);
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Save settings if form was submitted
        if (isset($_POST['ffb_save_settings']) && check_admin_referer('ffb_save_settings', 'ffb_nonce')) {
            try {
                // API key
                if (isset($_POST['ffb_api_key'])) {
                    update_option('ffb_api_key', sanitize_text_field($_POST['ffb_api_key']));
                    $this->api_key = sanitize_text_field($_POST['ffb_api_key']);
                }
                
                // Approved countries
                if (isset($_POST['ffb_approved_countries'])) {
                    $countries = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_countries']));
                    $countries = array_map('trim', $countries);
                    $countries = array_filter($countries);
                    update_option('ffb_approved_countries', $countries);
                    $this->approved_countries = $countries;
                } else {
                    update_option('ffb_approved_countries', array());
                    $this->approved_countries = array();
                }
                
                // Approved states
                if (isset($_POST['ffb_approved_states'])) {
                    $states = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_states']));
                    $states = array_map('trim', $states);
                    update_option('ffb_approved_states', $states);
                    $this->approved_states = $states;
                } else {
                    update_option('ffb_approved_states', array());
                    $this->approved_states = array();
                }
                
                // Approved ZIP codes
                if (isset($_POST['ffb_approved_zip_codes'])) {
                    $zip_codes = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_zip_codes']));
                    $zip_codes = array_map('trim', $zip_codes);
                    update_option('ffb_approved_zip_codes', $zip_codes);
                    $this->approved_zip_codes = $zip_codes;
                } else {
                    update_option('ffb_approved_zip_codes', array());
                    $this->approved_zip_codes = array();
                }
                
                // Blocked message
                if (isset($_POST['ffb_blocked_message'])) {
                    $blocked_message = wp_kses_post(stripslashes($_POST['ffb_blocked_message']));
                    update_option('ffb_blocked_message', $blocked_message);
                    $this->blocked_message = $blocked_message;
                }
                
                // Logging enabled
                $log_enabled = isset($_POST['ffb_log_enabled']) ? '1' : '0';
                update_option('ffb_log_enabled', $log_enabled);
                $this->log_enabled = $log_enabled === '1';
                
                // Diagnostic mode
                $diagnostic_mode = isset($_POST['ffb_diagnostic_mode']) ? '1' : '0';
                update_option('ffb_diagnostic_mode', $diagnostic_mode);
                $this->diagnostic_mode = $diagnostic_mode === '1';
                
                // Rate limiting settings
                $rate_limit_enabled = isset($_POST['ffb_rate_limit_enabled']) ? '1' : '0';
                update_option('ffb_rate_limit_enabled', $rate_limit_enabled);
                $this->rate_limit_enabled = $rate_limit_enabled === '1';
                
                $rate_limit_timeframe = isset($_POST['ffb_rate_limit_timeframe']) ? intval($_POST['ffb_rate_limit_timeframe']) : 3600;
                update_option('ffb_rate_limit_timeframe', $rate_limit_timeframe);
                $this->rate_limit_timeframe = $rate_limit_timeframe;
                
                $rate_limit_requests = isset($_POST['ffb_rate_limit_requests']) ? intval($_POST['ffb_rate_limit_requests']) : 3;
                update_option('ffb_rate_limit_requests', $rate_limit_requests);
                $this->rate_limit_requests = $rate_limit_requests;
                
                // Blocked IPs
                if (isset($_POST['ffb_blocked_ips'])) {
                    $blocked_ips = explode("\n", $_POST['ffb_blocked_ips']);
                    $blocked_ips = array_map('trim', $blocked_ips);
                    $blocked_ips = array_filter($blocked_ips);
                    update_option('ffb_blocked_ips', $blocked_ips);
                    $this->blocked_ips = $blocked_ips;
                } else {
                    update_option('ffb_blocked_ips', array());
                    $this->blocked_ips = array();
                }
                
                // IP whitelist
                if (isset($_POST['ffb_ip_whitelist'])) {
                    $whitelist = explode("\n", $_POST['ffb_ip_whitelist']);
                    $whitelist = array_map('trim', $whitelist);
                    $whitelist = array_filter($whitelist);
                    update_option('ffb_ip_whitelist', $whitelist);
                    $this->ip_whitelist = $whitelist;
                }
                
                // IP blacklist
                if (isset($_POST['ffb_ip_blacklist'])) {
                    $blacklist = explode("\n", $_POST['ffb_ip_blacklist']);
                    $blacklist = array_map('trim', $blacklist);
                    $blacklist = array_filter($blacklist);
                    update_option('ffb_ip_blacklist', $blacklist);
                    $this->ip_blacklist = $blacklist;
                } else {
                    update_option('ffb_ip_blacklist', array());
                    $this->ip_blacklist = array();
                }
                
                // Clear geolocation cache
                error_log('FFB Debug: Clearing geolocation cache');
                $this->clear_all_geo_cache();
                
                // Set transient to show success message
                error_log('FFB Debug: Setting success transient');
                set_transient('ffb_settings_saved', true, 30);
                
                // Define the redirect URL
                $redirect_url = admin_url('admin.php') . '?page=ff-spam-blocker&settings-updated=true';
                error_log('FFB Debug: About to redirect to: ' . $redirect_url);
                
                // Clean any output to prevent headers already sent issues
                if (ob_get_length()) {
                    ob_end_clean();
                }
                
                // Try different redirect approaches
                if (!headers_sent()) {
                    error_log('FFB Debug: Performing standard redirect using wp_safe_redirect');
                    wp_safe_redirect($redirect_url);
                    exit;
                } else {
                    error_log('FFB Debug: Headers already sent, using JavaScript redirect');
                    ?>
                    <script type="text/javascript">
                        window.location.href = "<?php echo $redirect_url; ?>";
                    </script>
                    <noscript><meta http-equiv="refresh" content="0;url=<?php echo $redirect_url; ?>"></noscript>
                    <p>If you are not redirected automatically, please <a href="<?php echo $redirect_url; ?>">click here</a>.</p>
                    <?php
                    exit;
                }
                
            } catch (Exception $e) {
                // Log any exceptions that occur during saving
                error_log('FFB Debug: Exception in save_settings: ' . $e->getMessage());
                error_log('FFB Debug: Exception trace: ' . $e->getTraceAsString());
                
                // Clean any output buffers
                while (ob_get_level()) {
                    ob_end_clean();
                }
                
                // Force JavaScript redirect as a final fallback
                ?>
                <script type="text/javascript">
                    console.log("FFB Debug: Using JavaScript redirect after exception");
                    window.location.href = "<?php echo admin_url('admin.php?page=ff-spam-blocker&error=exception&message=' . urlencode($e->getMessage())); ?>";
                </script>
                <noscript><meta http-equiv="refresh" content="0;url=<?php echo admin_url('admin.php?page=ff-spam-blocker&error=exception&message=' . urlencode($e->getMessage())); ?>"></noscript>
                <p>If you are not redirected automatically, please <a href="<?php echo admin_url('admin.php?page=ff-spam-blocker&error=exception&message=' . urlencode($e->getMessage())); ?>">click here</a>.</p>
                <?php
                exit;
            }
        }
        
        // Prepare data for the template
        $api_key = $this->api_key;
        $approved_countries = $this->approved_countries;
        $approved_states = $this->approved_states;
        $approved_zip_codes = $this->approved_zip_codes;
        $blocked_message = $this->blocked_message;
        $log_enabled = $this->log_enabled ? '1' : '0';
        $diagnostic_mode = $this->diagnostic_mode ? '1' : '0';
        $rate_limit_enabled = $this->rate_limit_enabled ? '1' : '0';
        $rate_limit_timeframe = $this->rate_limit_timeframe;
        $rate_limit_requests = $this->rate_limit_requests;
        $blocked_ips = implode("\n", $this->blocked_ips);
        $ip_whitelist = implode("\n", $this->ip_whitelist);
        $ip_blacklist = implode("\n", $this->ip_blacklist);
        
        // Include the settings template
        include_once(plugin_dir_path(__FILE__) . 'templates/settings.php');
    }

    public function manual_create_table() {
        // Security check
        if (!current_user_can('manage_options') || !check_admin_referer('ffb_create_table', 'ffb_table_nonce')) {
            wp_die('Unauthorized');
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';

        // Drop the table if it exists
        $wpdb->query("DROP TABLE IF EXISTS $table_name");
        error_log('FFB Debug: Manually dropped access log table');
        
        // Create the table
        ffb_create_log_table();
        
        // Update the DB version option to track that we've created the table
        update_option('ffb_db_version', $this->version);
        error_log('FFB Debug: Created access log table with updated structure');
    }

    public function is_location_allowed($geo_data) {
        // If no geo data, default to block (fail closed) for security
        if (empty($geo_data)) {
            error_log('FFB Debug: No geo data available, blocking access for security');
            return false;
        }
        
        // Add detailed debugging
        if (is_array($geo_data)) {
            error_log('FFB Debug: Geo data for location check: ' . json_encode($geo_data));
        }
        
        // Check country first
        if (!empty($geo_data['country_code'])) {
            $country_code = strtoupper($geo_data['country_code']);
            $approved_countries = array_map('strtoupper', $this->approved_countries);
            
            error_log('FFB Debug: Checking country: ' . $country_code . ' against approved countries: ' . implode(',', $approved_countries));
            
            // If approved countries list is empty, allow all countries
            if (empty($approved_countries)) {
                error_log('FFB Debug: No approved countries configured, allowing all countries');
                return true;
            }
            
            if (!in_array($country_code, $approved_countries)) {
                error_log('FFB Debug: Country blocked: ' . $country_code);
                return false;
            }
        } elseif (!empty($geo_data['countryCode'])) {
            // Try alternate field name (some APIs use different formats)
            $country_code = strtoupper($geo_data['countryCode']);
            $approved_countries = array_map('strtoupper', $this->approved_countries);
            
            error_log('FFB Debug: Checking country (alt format): ' . $country_code . ' against approved countries: ' . implode(',', $approved_countries));
            
            if (empty($approved_countries)) {
                error_log('FFB Debug: No approved countries configured, allowing all countries');
                return true;
            }
            
            if (!in_array($country_code, $approved_countries)) {
                error_log('FFB Debug: Country blocked: ' . $country_code);
                return false;
            }
        }
        
        // If country is allowed, check state/region if it's US
        if (isset($geo_data['country_code']) && strtoupper($geo_data['country_code']) == 'US' || 
            isset($geo_data['countryCode']) && strtoupper($geo_data['countryCode']) == 'US') {
            // Get region code from API response
            $region_code = '';
            
            // First try to use region_code directly from the API
            if (isset($geo_data['region_code']) && !empty($geo_data['region_code'])) {
                $region_code = strtoupper($geo_data['region_code']);
                error_log('FFB Debug: Using region_code directly from API: ' . $region_code);
            } 
            // Otherwise try to convert region_name to a code
            else if (isset($geo_data['region_name']) && !empty($geo_data['region_name'])) {
                $region_name = $geo_data['region_name'];
                $region_code = $this->get_region_code_from_name($region_name, 'US');
                error_log('FFB Debug: Converted region_name to code: ' . $region_name . ' -> ' . $region_code);
            }
            // If region is still empty, check for region in other fields
            else if (isset($geo_data['region']) && !empty($geo_data['region'])) {
                $region = $geo_data['region'];
                $region_code = $this->get_region_code_from_name($region, 'US');
                error_log('FFB Debug: Converted region to code: ' . $region . ' -> ' . $region_code);
            }
            
            // Also check if we have a region code
            if ($region_code === 'Unknown' || $region_code === '') {
                if (isset($geo_data['region_code'])) {
                    $region_code = $geo_data['region_code'];
                } elseif (isset($geo_data['regionCode'])) {
                    $region_code = $geo_data['regionCode'];
                }
            }
            
            // If we have a region code, check if it's allowed
            if (!empty($region_code)) {
                $approved_states = array_map('strtoupper', $this->get_approved_states());
                error_log('FFB Debug: Checking if state ' . $region_code . ' is in approved list: ' . implode(',', $approved_states));
                
                // If approved states list is not empty, check if state is in the list
                if (!empty($approved_states)) {
                    if (!in_array($region_code, $approved_states)) {
                        error_log('FFB Debug: State ' . $region_code . ' not in approved list: ' . implode(',', $approved_states));
                        return false;
                    } else {
                        error_log('FFB Debug: State ' . $region_code . ' is in approved list - allowing access');
                    }
                } else {
                    // If no states are approved, block all states
                    error_log('FFB Debug: No approved states configured, blocking all states');
                    return false;
                }
            } else {
                // Special handling for mobile cases where region code might be missing
                error_log('FFB Debug: No region code available for checking');
                
                // If we're in diagnostic mode, allow access
                if ($this->diagnostic_mode) {
                    error_log('FFB Debug: Diagnostic mode enabled, allowing access despite missing region code');
                    return true;
                }
                
                // If the IP is in an approved location AND we can't determine region, 
                // let's give benefit of the doubt rather than incorrectly blocking
                if (!empty($this->approved_states)) {
                    error_log('FFB Debug: Cannot determine region but IP is from approved country - allowing access');
                    return true;
                }
                
                error_log('FFB Debug: No region code available for checking, but no approved states configured - defaulting to allowing access');
                return true;
            }
            
            // If state is allowed, check ZIP code if we have it and ZIP restrictions are in place
            if (isset($geo_data['zip']) && !empty($geo_data['zip']) && !empty($this->approved_zip_codes)) {
                $zip = substr($geo_data['zip'], 0, 5);
                $approved_zip_codes = $this->get_approved_zip_codes();
                if (!in_array($zip, $approved_zip_codes)) {
                    error_log('FFB Debug: ZIP code ' . $zip . ' not in approved list');
                    return false;
                }
            } elseif (isset($geo_data['postal']) && !empty($geo_data['postal']) && !empty($this->approved_zip_codes)) {
                // Try alternate field name
                $zip = substr($geo_data['postal'], 0, 5);
                $approved_zip_codes = $this->get_approved_zip_codes();
                if (!in_array($zip, $approved_zip_codes)) {
                    error_log('FFB Debug: ZIP code (from postal) ' . $zip . ' not in approved list');
                    return false;
                }
            }
        }
        
        // If we made it here, location is allowed
        error_log('FFB Debug: Location is allowed');
        return true;
    }
    
    /**
     * Convert a region name to a region code
     */
    private function get_region_code_from_name($region_name, $country_code) {
        // If empty, return empty
        if (empty($region_name)) {
            return '';
        }
        
        // If it's already a 2-letter code, return as is
        if (strlen($region_name) == 2 && ctype_alpha($region_name)) {
            return strtoupper($region_name);
        }
        
        // For US states
        if ($country_code == 'US') {
            $states = array(
                'Alabama' => 'AL',
                'Alaska' => 'AK',
                'Arizona' => 'AZ',
                'Arkansas' => 'AR',
                'California' => 'CA',
                'Colorado' => 'CO',
                'Connecticut' => 'CT',
                'Delaware' => 'DE',
                'Florida' => 'FL',
                'Georgia' => 'GA',
                'Hawaii' => 'HI',
                'Idaho' => 'ID',
                'Illinois' => 'IL',
                'Indiana' => 'IN',
                'Iowa' => 'IA',
                'Kansas' => 'KS',
                'Kentucky' => 'KY',
                'Louisiana' => 'LA',
                'Maine' => 'ME',
                'Maryland' => 'MD',
                'Massachusetts' => 'MA',
                'Michigan' => 'MI',
                'Minnesota' => 'MN',
                'Mississippi' => 'MS',
                'Missouri' => 'MO',
                'Montana' => 'MT',
                'Nebraska' => 'NE',
                'Nevada' => 'NV',
                'New Hampshire' => 'NH',
                'New Jersey' => 'NJ',
                'New Mexico' => 'NM',
                'New York' => 'NY',
                'North Carolina' => 'NC',
                'North Dakota' => 'ND',
                'Ohio' => 'OH',
                'Oklahoma' => 'OK',
                'Oregon' => 'OR',
                'Pennsylvania' => 'PA',
                'Rhode Island' => 'RI',
                'South Carolina' => 'SC',
                'South Dakota' => 'SD',
                'Tennessee' => 'TN',
                'Texas' => 'TX',
                'Utah' => 'UT',
                'Vermont' => 'VT',
                'Virginia' => 'VA',
                'Washington' => 'WA',
                'West Virginia' => 'WV',
                'Wisconsin' => 'WI',
                'Wyoming' => 'WY',
                'District of Columbia' => 'DC',
                'American Samoa' => 'AS',
                'Guam' => 'GU',
                'Northern Mariana Islands' => 'MP',
                'Puerto Rico' => 'PR',
                'United States Minor Outlying Islands' => 'UM',
                'U.S. Virgin Islands' => 'VI',
                // Add common abbreviations and alternate names
                'Mass' => 'MA',
                'Mass.' => 'MA',
                'MA' => 'MA',
                'Ma' => 'MA',
                'ma' => 'MA',
                'Massachusetts' => 'MA',
                'MASSACHUSETTS' => 'MA',
            );
            
            // Direct lookup
            if (isset($states[$region_name])) {
                return $states[$region_name];
            }
            
            // Check for case-insensitive match
            foreach ($states as $name => $code) {
                if (strtolower($name) == strtolower($region_name)) {
                    return $code;
                }
            }
            
            // Check for partial match (e.g., "Mass" for "Massachusetts")
            foreach ($states as $name => $code) {
                if (stripos($name, $region_name) === 0 || stripos($region_name, $name) === 0) {
                    return $code;
                }
            }
        }
        
        // If no match found or not US, return the region name as is
        return strtoupper($region_name);
    }

    public function log_access_attempt($ip, $status, $reason, $form_id = 0, $log_type = 'form_load') {
        // Check if logging is enabled
        if (!$this->log_enabled) {
            return false;
        }
        
        // Get geo data
        $geo_data = $this->get_geo_data($ip);
        
        // Debug the received geo data
        error_log('FFB Debug: Received geo data for logging: ' . print_r($geo_data, true));
        
        // Prepare data for logging
        // Different APIs use different keys, so check all possible variations
        $country = '';
        if (isset($geo_data['country_name']) && !empty($geo_data['country_name']) && $geo_data['country_name'] !== 'Unknown') {
            $country = $geo_data['country_name'];
        } elseif (isset($geo_data['country']) && !empty($geo_data['country'])) {
            $country = $geo_data['country'];
        } elseif (isset($geo_data['countryName']) && !empty($geo_data['countryName'])) {
            $country = $geo_data['countryName'];
        }
        
        $country_code = '';
        if (isset($geo_data['country_code']) && !empty($geo_data['country_code']) && $geo_data['country_code'] !== 'Unknown') {
            $country_code = $geo_data['country_code'];
        } elseif (isset($geo_data['countryCode']) && !empty($geo_data['countryCode'])) {
            $country_code = $geo_data['countryCode'];
        }
        
        $region_name = '';
        if (isset($geo_data['region_name']) && !empty($geo_data['region_name']) && $geo_data['region_name'] !== 'Unknown') {
            $region_name = $geo_data['region_name'];
        } elseif (isset($geo_data['regionName']) && !empty($geo_data['regionName'])) {
            $region_name = $geo_data['regionName'];
        } elseif (isset($geo_data['state']) && !empty($geo_data['state'])) {
            $region_name = $geo_data['state'];
        } elseif (isset($geo_data['subdivision_1_name']) && !empty($geo_data['subdivision_1_name'])) {
            $region_name = $geo_data['subdivision_1_name'];
        }
        
        $region_code = '';
        if (isset($geo_data['region_code']) && !empty($geo_data['region_code']) && $geo_data['region_code'] !== 'Unknown') {
            $region_code = $geo_data['region_code'];
        } elseif (isset($geo_data['region']) && !empty($geo_data['region'])) {
            $region_code = $geo_data['region'];
        } elseif (isset($geo_data['regionCode']) && !empty($geo_data['regionCode'])) {
            $region_code = $geo_data['regionCode'];
        } elseif (isset($geo_data['subdivision_1_code']) && !empty($geo_data['subdivision_1_code'])) {
            $region_code = $geo_data['subdivision_1_code'];
        }
        
        // If we have a region code but no region name, use the code as the name
        if (empty($region_name) && !empty($region_code)) {
            $region_name = $region_code;
        }
        
        // If we have a country code but no country name, use the code as the name
        if (empty($country) && !empty($country_code)) {
            $country = $country_code;
        }
        
        // Log geo data for debugging
        error_log('FFB Debug: Logging access attempt with country: ' . $country . ', country_code: ' . $country_code . ', region_name: ' . $region_name . ', region_code: ' . $region_code);
        
        // Get the WordPress database object
        global $wpdb;
        
        // Define the table name
        $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
        
        // Insert the log entry
        $result = $wpdb->insert(
            $table_name,
            array(
                'timestamp' => current_time('mysql'),
                'ip_address' => $ip,
                'status' => $status,
                'reason' => $reason,
                'country_code' => $country_code,
                'country_name' => $country,
                'region_code' => $region_code,
                'region_name' => $region_name,
                'city' => isset($geo_data['city']) && !empty($geo_data['city']) ? $geo_data['city'] : '',
                'zip' => isset($geo_data['zip']) && !empty($geo_data['zip']) ? $geo_data['zip'] : 
                      (isset($geo_data['postal']) && !empty($geo_data['postal']) ? $geo_data['postal'] : ''),
                'form_id' => $form_id,
                'log_type' => $log_type,
                'geo_data' => json_encode($geo_data)
            ),
            array(
                '%s', // timestamp
                '%s', // ip_address
                '%s', // status
                '%s', // reason
                '%s', // country_code
                '%s', // country_name
                '%s', // region_code
                '%s', // region_name
                '%s', // city
                '%s', // zip
                '%d', // form_id
                '%s', // log_type
                '%s'  // geo_data
            )
        );
        
        if ($result === false) {
            error_log('FFB Error: Failed to insert log entry: ' . $wpdb->last_error);
            return false;
        }
        
        return true;
    }
    
    /**
     * AJAX endpoint to get the current approved states list
     */
    public function ajax_get_approved_states() {
        // Verify nonce for security
        if (!isset($_REQUEST['nonce']) || !wp_verify_nonce($_REQUEST['nonce'], 'ffb_admin_nonce')) {
            wp_send_json_error('Invalid security token');
            return;
        }

        // Get the current approved states
        $approved_states = $this->get_approved_states();
        
        // Log for debugging
        error_log('FFB Debug: AJAX request for approved states, returning: ' . implode(',', $approved_states));
        
        // Return the approved states
        wp_send_json_success(array(
            'approved_states' => $approved_states,
            'timestamp' => current_time('timestamp')
        ));
    }
    
    /**
     * Add all hooks and filters
     */
    private function add_hooks() {
        add_action('init', array($this, 'init'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_enqueue_scripts', array($this, 'admin_scripts'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_filter('the_content', array($this, 'block_form'), 99);
        
        // AJAX handlers
        add_action('wp_ajax_ffb_test_api_key', array($this, 'ajax_test_api_key'));
        add_action('wp_ajax_nopriv_ffb_test_api_key', array($this, 'ajax_test_api_key'));
        add_action('wp_ajax_ffb_refresh_api_usage', array($this, 'ajax_refresh_api_usage'));
        add_action('wp_ajax_ffb_get_approved_states', array($this, 'ajax_get_approved_states'));
        add_action('wp_ajax_nopriv_ffb_get_approved_states', array($this, 'ajax_get_approved_states'));
        add_action('wp_ajax_ffb_check_location', array($this, 'ajax_check_location'));
        add_action('wp_ajax_nopriv_ffb_check_location', array($this, 'ajax_check_location'));
        
        // Admin post actions
        add_action('admin_post_ffb_save_settings', array($this, 'handle_save_settings'));
        add_action('admin_post_ffb_clear_access_log', array($this, 'handle_clear_logs'));
        add_action('admin_post_ffb_update_api_key', array($this, 'update_api_key'));
        add_action('admin_post_ffb_create_table', array($this, 'manual_create_table'));
        add_action('admin_post_ffb_export_logs_csv', array($this, 'handle_export_logs_csv'));
    }
    
    /**
     * AJAX handler for location checking
     * This function helps overcome caching issues by providing a dynamic check
     */
    public function ajax_check_location() {
        // Check for nonce for security
        check_ajax_referer('ffb_check_location', 'nonce');
        
        // Get client IP
        $ip = $this->get_client_ip();
        
        // Log the check
        error_log('FFB Debug: AJAX location check for IP ' . $ip);
        
        // Check if IP is in the whitelist
        if ($this->is_ip_whitelisted($ip)) {
            error_log('FFB Debug: IP ' . $ip . ' is whitelisted, allowing form display via AJAX');
            wp_send_json_success(array(
                'allowed' => true,
                'message' => 'IP is whitelisted'
            ));
            return;
        }
        
        // Get geo data
        $geo_data = $this->get_geo_data($ip);
        
        // If geo data is null or empty and diagnostic mode is enabled, allow the form
        if (empty($geo_data) && $this->diagnostic_mode) {
            error_log('FFB Diagnostic: Allowing form despite missing geo data via AJAX');
            wp_send_json_success(array(
                'allowed' => true,
                'message' => 'Diagnostic mode enabled'
            ));
            return;
        }
        
        // If geo data is null or empty, block the form
        if (empty($geo_data)) {
            error_log('FFB Debug: No geo data available for IP ' . $ip . ', blocking form via AJAX');
            wp_send_json_success(array(
                'allowed' => false,
                'message' => $this->get_blocked_message()
            ));
            return;
        }
        
        // Check if location is blocked
        if ($this->is_location_blocked($geo_data)) {
            error_log('FFB Debug: Location is blocked for IP ' . $ip . ', blocking form via AJAX');
            $this->log_access_attempt($ip, 'blocked', 'Location blocked', 'ajax', 'form_load');
            wp_send_json_success(array(
                'allowed' => false,
                'message' => $this->get_blocked_message()
            ));
            return;
        }
        
        // Check if IP is in the blacklist
        if ($this->is_ip_blacklisted($ip)) {
            error_log('FFB Debug: IP ' . $ip . ' is blacklisted, blocking form via AJAX');
            $this->log_access_attempt($ip, 'blocked', 'IP blacklisted', 'ajax', 'form_load');
            wp_send_json_success(array(
                'allowed' => false,
                'message' => $this->get_blocked_message()
            ));
            return;
        }
        
        // Log the allowed access
        $this->log_access_attempt($ip, 'allowed', 'Location allowed', 'ajax', 'form_load');
        
        // Allow the form to be displayed
        wp_send_json_success(array(
            'allowed' => true,
            'message' => 'Location allowed'
        ));
    }
    
    /**
     * Clear all geolocation cache entries
     * This is needed when states or countries are updated
     */
    public function clear_all_geo_cache() {
        global $wpdb;
        
        error_log('FFB Debug: Clearing all geolocation cache entries');
        
        // Find all transients that start with ffb_geo_
        $transients = $wpdb->get_col("
            SELECT option_name 
            FROM $wpdb->options 
            WHERE option_name LIKE '%_transient_ffb_geo_%' 
            OR option_name LIKE '%_transient_timeout_ffb_geo_%'
        ");
        
        if (empty($transients)) {
            error_log('FFB Debug: No geolocation cache entries found');
            return 0;
        }
        
        $count = 0;
        foreach ($transients as $transient) {
            // Extract the actual transient name without the _transient_ prefix
            $name = str_replace(array('_transient_', '_transient_timeout_'), '', $transient);
            delete_transient($name);
            $count++;
        }
        
        error_log('FFB Debug: Cleared ' . $count . ' geolocation cache entries');
        return $count;
    }
    
    /**
     * Get the blocked message to display when forms are blocked
     * 
     * @return string The message to display to blocked users
     */
    public function get_blocked_message() {
        $message = get_option('ffb_blocked_message', '');
        
        // If no message is set, use a default
        if (empty($message)) {
            $message = '<div class="frm_error_style" style="text-align:center;"><p>We apologize, but we are currently not accepting submissions from your location.</p></div>';
        }
        
        return $message;
    }

    /**
     * Check if the current content contains a Formidable Form
     */
    public function is_form_page($content = null) {
        // If content is null, get it from global post
        if ($content === null) {
            global $post;
            
            if (!is_object($post)) {
                error_log('FFB Debug: No post object available for form detection');
                return false;
            }
            
            $content = $post->post_content;
            error_log('FFB Debug: Using post content for form detection. ID: ' . $post->ID);
        }
        
        // Add debug logging
        error_log('FFB Debug: Checking if content contains a form. Content length: ' . strlen($content));
        
        // Check for Formidable Forms shortcode
        if (strpos($content, '[formidable') !== false) {
            error_log('FFB Debug: Found formidable shortcode in content');
            return true;
        }
        
        // Check for Formidable Forms div
        if (strpos($content, 'class="frm_forms') !== false || strpos($content, 'class="frm-show-form') !== false) {
            error_log('FFB Debug: Found frm_forms class in content');
            return true;
        }
        
        // Check for Formidable Forms form element
        if (strpos($content, '<form') !== false && (strpos($content, 'formidable') !== false || strpos($content, 'frm_pro_form') !== false)) {
            error_log('FFB Debug: Found formidable form element in content');
            return true;
        }
        
        // Check for Formidable Forms block
        if (strpos($content, '<!-- wp:formidable/simple-form') !== false) {
            error_log('FFB Debug: Found formidable block in content');
            return true;
        }
        
        error_log('FFB Debug: No form found in content');
        return false;
    }
    
    /**
     * Extract form ID from content if possible
     */
    private function get_form_id_from_content($content) {
        // Try to extract form ID from shortcode
        if (preg_match('/\[formidable.*?id="?(\d+)"?/i', $content, $matches)) {
            return $matches[1];
        }
        
        // Try to extract form ID from div
        if (preg_match('/class="frm_forms[^"]*" id="frm_form_(\d+)_container/i', $content, $matches)) {
            return $matches[1];
        }
        
        // Try to extract form ID from block
        if (preg_match('/<!-- wp:formidable\/simple-form {"formId":"?(\d+)"?/i', $content, $matches)) {
            return $matches[1];
        }
        
        return '';
    }
}

// Initialize the plugin
$formidable_forms_blocker = new FormidableFormsBlocker();

// Create the access log table when the plugin is activated
register_activation_hook(__FILE__, 'ffb_create_log_table');

// Include the direct-settings.php file which contains the ffb_create_log_table function
require_once(plugin_dir_path(__FILE__) . 'direct-settings.php');
