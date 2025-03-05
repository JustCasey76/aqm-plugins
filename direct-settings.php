<?php
/**
 * Direct Settings Update Tool for AQM Formidable Forms Spam Blocker
 * 
 * This file provides a direct method to update plugin settings without using admin-post.php.
 */

// Define a simple log function that doesn't depend on file operations
if (!function_exists('ffb_write_log')) {
    function ffb_write_log($message) {
        // Use error_log which is safer and always available
        error_log("FFB Debug: " . $message);
    }
}

// Check if this file is being accessed directly
$is_direct_access = (basename($_SERVER['SCRIPT_FILENAME']) == basename(__FILE__));

// Only try to load WordPress if this file is accessed directly
// When included from the main plugin, WordPress is already loaded
if ($is_direct_access) {
    ffb_write_log("Direct Settings Update Tool Initialized Directly");
    
    // Try to find WordPress in multiple ways
    $possible_paths = [
        dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php',  // Standard path 
        $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php',                     // Document root
        dirname(dirname(dirname(__FILE__))) . '/wp-load.php',           // Alternative path
        __DIR__ . '/../../../wp-load.php',                              // Additional path relative to plugin
        realpath(__DIR__ . '/../../../../wp-load.php'),                 // Real path checking
    ];

    $wp_loaded = false;

    foreach ($possible_paths as $path) {
        ffb_write_log("Trying WordPress path: {$path}");
        if (file_exists($path)) {
            try {
                require_once($path);
                ffb_write_log("WordPress loaded successfully from: {$path}");
                $wp_loaded = true;
                break;
            } catch (Exception $e) {
                ffb_write_log("Error loading WordPress from {$path}: " . $e->getMessage());
            }
        } else {
            ffb_write_log("WordPress wp-load.php not found at {$path}");
        }
    }
} else {
    // When included from the main plugin, WordPress is already loaded
    $wp_loaded = function_exists('is_user_logged_in');
    if ($wp_loaded) {
        ffb_write_log("WordPress already loaded (included from main plugin)");
    } else {
        ffb_write_log("WARNING: WordPress functions not available when included");
    }
}

// Only proceed with WordPress functionality if WordPress is loaded
if ($wp_loaded) {
    // Process form submissions only if this file is accessed directly
    if ($is_direct_access) {
        try {
            // Check if user is logged in
            if (!is_user_logged_in()) {
                ffb_write_log("User not logged in. Redirecting to login page.");
                wp_redirect(wp_login_url(admin_url('admin.php?page=ff-spam-blocker')));
                exit;
            }
            
            // Check if user has permission
            if (!current_user_can('manage_options')) {
                ffb_write_log("User does not have permission. Access denied.");
                wp_die(__('You do not have sufficient permissions to access this page.'));
            }
            
            ffb_write_log("User authenticated and has permission");
            
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                
                // Handle save settings action
                if (isset($_POST['action']) && $_POST['action'] === 'ffb_save_settings') {
                    ffb_write_log("Form submitted, processing settings update");
                    
                    // Verify nonce
                    if (!isset($_POST['ffb_nonce']) || !wp_verify_nonce($_POST['ffb_nonce'], 'ffb_save_settings')) {
                        ffb_write_log("Nonce verification failed");
                        wp_die(__('Security check failed. Please try again.'));
                    }
                    
                    ffb_write_log("Nonce verified, processing form data");
                    
                    // API Key
                    if (isset($_POST['ffb_api_key'])) {
                        update_option('ffb_api_key', sanitize_text_field($_POST['ffb_api_key']));
                        ffb_write_log("API key updated");
                    }
                    
                    // Approved Countries
                    if (isset($_POST['ffb_approved_countries'])) {
                        $countries = sanitize_text_field($_POST['ffb_approved_countries']);
                        $countries = explode(',', $countries);
                        $countries = array_map('trim', $countries);
                        $countries = array_filter($countries);
                        update_option('ffb_approved_countries', $countries);
                        ffb_write_log("Approved countries updated: " . implode(', ', $countries));
                    }
                    
                    // Approved States
                    if (isset($_POST['ffb_approved_states'])) {
                        $states = sanitize_text_field($_POST['ffb_approved_states']);
                        $states = explode(',', $states);
                        $states = array_map('trim', $states);
                        $states = array_filter($states);
                        update_option('ffb_approved_states', $states);
                        ffb_write_log("Approved states updated: " . implode(', ', $states));
                    }
                    
                    // Approved ZIP Codes
                    if (isset($_POST['ffb_approved_zip_codes'])) {
                        $zip_codes = sanitize_text_field($_POST['ffb_approved_zip_codes']);
                        $zip_codes = explode(',', $zip_codes);
                        $zip_codes = array_map('trim', $zip_codes);
                        $zip_codes = array_filter($zip_codes);
                        update_option('ffb_approved_zip_codes', $zip_codes);
                        ffb_write_log("Approved ZIP codes updated: " . implode(', ', $zip_codes));
                    }
                    
                    // Blocked IPs
                    if (isset($_POST['ffb_blocked_ips'])) {
                        $blocked_ips = explode("\n", $_POST['ffb_blocked_ips']);
                        $blocked_ips = array_map('trim', $blocked_ips);
                        $blocked_ips = array_filter($blocked_ips);
                        update_option('ffb_blocked_ips', $blocked_ips);
                        ffb_write_log("Blocked IPs updated");
                    }
                    
                    // IP Whitelist
                    if (isset($_POST['ffb_ip_whitelist'])) {
                        $whitelist = explode("\n", $_POST['ffb_ip_whitelist']);
                        $whitelist = array_map('trim', $whitelist);
                        $whitelist = array_filter($whitelist);
                        update_option('ffb_ip_whitelist', $whitelist);
                        ffb_write_log("IP whitelist updated");
                    }
                    
                    // Rate Limit Timeframe
                    if (isset($_POST['ffb_rate_limit_timeframe'])) {
                        update_option('ffb_rate_limit_timeframe', absint($_POST['ffb_rate_limit_timeframe']));
                        ffb_write_log("Rate limit timeframe updated to: " . absint($_POST['ffb_rate_limit_timeframe']));
                    }
                    
                    // Rate Limit Requests
                    if (isset($_POST['ffb_rate_limit_requests'])) {
                        update_option('ffb_rate_limit_requests', absint($_POST['ffb_rate_limit_requests']));
                        ffb_write_log("Rate limit requests updated to: " . absint($_POST['ffb_rate_limit_requests']));
                    }
                    
                    // Enable Rate Limiting - properly handle checkbox 
                    $rate_limiting_enabled = isset($_POST['ffb_rate_limit_enabled']) ? '1' : '0';
                    update_option('ffb_rate_limit_enabled', $rate_limiting_enabled);
                    ffb_write_log("Rate limiting " . ($rate_limiting_enabled ? 'enabled' : 'disabled'));
                    
                    // Enable Logging
                    $log_enabled = isset($_POST['ffb_log_enabled']) ? '1' : '0';
                    update_option('ffb_log_enabled', $log_enabled);
                    ffb_write_log("Logging " . ($log_enabled ? 'enabled' : 'disabled'));
                    
                    // Blocked Message
                    if (isset($_POST['ffb_blocked_message'])) {
                        update_option('ffb_blocked_message', wp_kses_post($_POST['ffb_blocked_message']));
                        ffb_write_log("Blocked message updated");
                    }
                    
                    // Diagnostic Mode
                    $diagnostic_mode = isset($_POST['ffb_diagnostic_mode']) ? '1' : '0';
                    update_option('ffb_diagnostic_mode', $diagnostic_mode);
                    ffb_write_log("Diagnostic mode " . ($diagnostic_mode ? 'enabled' : 'disabled'));
                    
                    // Clear geo cache whenever settings change
                    // This is critical to ensure any settings changes are immediately applied
                    delete_option('ffb_geo_cache');
                    ffb_write_log("Geo cache cleared to ensure new settings take effect immediately");
                    
                    // Set transient to show success message
                    set_transient('ffb_settings_saved', true, 60);
                    ffb_write_log("Transient set for settings saved message");
                    
                    // Redirect back to settings page
                    if (isset($_POST['redirect_to'])) {
                        $redirect_to = sanitize_text_field($_POST['redirect_to']);
                        ffb_write_log("Redirecting to: {$redirect_to}");
                        safe_redirect($redirect_to);
                        exit;
                    } else {
                        ffb_write_log("No redirect_to specified, using default");
                        safe_redirect(admin_url('admin.php?page=ff-spam-blocker&settings-updated=true'));
                        exit;
                    }
                }
                // Handle create table action
                elseif (isset($_POST['action']) && $_POST['action'] === 'ffb_create_table') {
                    ffb_write_log("Create table action submitted");
                    
                    // Verify nonce - UPDATED to match template
                    if (!isset($_POST['ffb_table_nonce']) || !wp_verify_nonce($_POST['ffb_table_nonce'], 'ffb_create_table')) {
                        ffb_write_log("Nonce verification failed for create table");
                        wp_die(__('Security check failed. Please try again.'));
                    }
                    
                    ffb_write_log("Nonce verified for create table");
                    
                    // Create table function should be available from the main plugin file
                    if (function_exists('ffb_create_log_table')) {
                        ffb_write_log("Function ffb_create_log_table exists, attempting to create table");
                        
                        // Check if ABSPATH and wp-admin/includes/upgrade.php are available
                        if (defined('ABSPATH')) {
                            ffb_write_log("ABSPATH is defined: " . ABSPATH);
                            
                            // Check if upgrade.php exists
                            $upgrade_file = ABSPATH . 'wp-admin/includes/upgrade.php';
                            ffb_write_log("Checking for upgrade.php at: {$upgrade_file}");
                            
                            if (file_exists($upgrade_file)) {
                                ffb_write_log("Found upgrade.php, including it");
                                require_once($upgrade_file);
                            } else {
                                ffb_write_log("Could not find upgrade.php");
                            }
                        } else {
                            ffb_write_log("ABSPATH is not defined");
                        }
                        
                        // Call the function to create the table
                        ffb_create_log_table();
                        ffb_write_log("Table creation function called");
                        
                        // Set transient for success message
                        set_transient('ffb_table_created', true, 60);
                        ffb_write_log("Transient set for table created message");
                        
                        // Redirect back to settings page
                        safe_redirect(admin_url('admin.php?page=ff-spam-blocker&table-created=true'));
                        exit;
                    } else {
                        ffb_write_log("Function ffb_create_log_table does not exist");
                        
                        // Fallback table creation
                        ffb_write_log("Using fallback table creation method");
                    }
                } else {
                    ffb_write_log("Unknown action: " . (isset($_POST['action']) ? $_POST['action'] : 'No action specified'));
                }
            } else {
                ffb_write_log("No POST data received");
            }
        } catch (Exception $e) {
            ffb_write_log("Error processing form: " . $e->getMessage());
            wp_die("Error processing form: " . $e->getMessage());
        }
    } else {
        ffb_write_log("ERROR: Could not load WordPress!");
        echo "<!DOCTYPE html><html><head><title>Error</title></head><body>";
        echo "<h2>Error: Could not load WordPress</h2>";
        echo "<p>This tool requires WordPress to be properly loaded.</p>";
        echo "<p>Please try the following:</p>";
        echo "<ul>";
        echo "<li>Go back to the WordPress admin area and retry</li>";
        echo "<li>Ensure this file is located in the correct plugin directory</li>";
        echo "<li>Check if the server has proper permissions to access WordPress files</li>";
        echo "</ul>";
        echo "</body></html>";
    }
} else {
    ffb_write_log("WordPress functions not available");
}

/**
 * Create the access log table if it doesn't exist
 */
function ffb_create_log_table() {
    global $wpdb;
    ffb_write_log("Creating log table directly from direct-settings.php");
    
    $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
    
    // Check if dbDelta function exists (part of WordPress)
    if (!function_exists('dbDelta')) {
        ffb_write_log("dbDelta function not found, trying to include upgrade.php");
        if (defined('ABSPATH') && file_exists(ABSPATH . 'wp-admin/includes/upgrade.php')) {
            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            ffb_write_log("Successfully included upgrade.php");
        } else {
            ffb_write_log("Could not find upgrade.php, will proceed with direct SQL execution");
        }
    }
    
    // SQL to create the log table
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        timestamp datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
        ip_address varchar(45) NOT NULL,
        country_code varchar(10),
        country_name varchar(100),
        region_code varchar(10),
        region_name varchar(100),
        city varchar(100),
        zip varchar(20),
        latitude decimal(10,8),
        longitude decimal(11,8),
        status varchar(20) NOT NULL,
        reason text,
        form_id int(11),
        log_type varchar(50) DEFAULT 'form_load',
        geo_data text,
        PRIMARY KEY  (id),
        KEY ip_address (ip_address),
        KEY status (status),
        KEY form_id (form_id),
        KEY timestamp (timestamp)
    ) $charset_collate;";
    
    // Create the table using dbDelta if available, or direct query otherwise
    if (function_exists('dbDelta')) {
        ffb_write_log("Using dbDelta to create table");
        $result = dbDelta($sql);
        ffb_write_log("dbDelta result: " . print_r($result, true));
    } else {
        ffb_write_log("Using direct query to create table");
        // First check if table exists
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
        
        if ($table_exists) {
            ffb_write_log("Table exists, dropping it first");
            $wpdb->query("DROP TABLE IF EXISTS $table_name");
        }
        
        $result = $wpdb->query($sql);
        ffb_write_log("Direct query result: " . ($result !== false ? "Success" : "Failed - " . $wpdb->last_error));
    }
    
    ffb_write_log("Table creation completed");
}

/**
 * Function to redirect back to the settings page with better error handling
 * 
 * @param string $url The URL to redirect to
 */
function safe_redirect($url) {
    global $log_file;
    
    ffb_write_log("Attempting to redirect to: {$url}");
    
    // Try PHP redirect first if headers haven't been sent
    if (!headers_sent()) {
        ffb_write_log("Using wp_redirect() to: {$url}");
        wp_safe_redirect($url);
        exit;
    } else {
        ffb_write_log("Headers already sent, using JavaScript redirect to: {$url}");
        
        // Add JavaScript fallback for redirect
        echo "<!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
            <meta http-equiv='refresh' content='0;url=" . esc_url($url) . "'>
            <script>
                console.log('Initiating JavaScript redirect to: " . esc_js($url) . "');
                window.location.href = '" . esc_js($url) . "';
            </script>
        </head>
        <body>
            <h3>Redirecting...</h3>
            <p>If you are not redirected automatically, <a href='" . esc_url($url) . "'>click here</a>.</p>
            <script>
                // Add timeout as a fallback
                setTimeout(function() {
                    console.log('Timeout triggered, forcing redirect');
                    window.location.replace('" . esc_js($url) . "');
                }, 1000);
            </script>
        </body>
        </html>";
    }
    
    exit;
}
