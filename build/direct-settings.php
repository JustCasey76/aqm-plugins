<?php
/**
 * Direct Settings Update Tool for AQM Formidable Forms Spam Blocker
 * 
 * This file provides a direct method to update plugin settings without using admin-post.php.
 */

// Create a log file in the plugin directory
$log_file = __DIR__ . '/direct-settings.log';
$timestamp = date('Y-m-d H:i:s');

// Log function
function write_log($message) {
    global $log_file, $timestamp;
    file_put_contents($log_file, "[{$timestamp}] {$message}\n", FILE_APPEND);
}

// Initialize log
write_log("Direct Settings Update Tool Initialized");
write_log("POST data: " . print_r($_POST, true));

// Try to find WordPress in multiple ways
$possible_paths = [
    dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php',  // Standard path 
    $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php',                     // Document root
    dirname(dirname(dirname(__FILE__))) . '/wp-load.php',           // Alternative path
];

$wp_loaded = false;

foreach ($possible_paths as $path) {
    write_log("Trying WordPress path: {$path}");
    if (file_exists($path)) {
        try {
            require_once($path);
            write_log("WordPress loaded successfully from: {$path}");
            $wp_loaded = true;
            break;
        } catch (Exception $e) {
            write_log("Error loading WordPress from {$path}: " . $e->getMessage());
        }
    } else {
        write_log("WordPress wp-load.php not found at {$path}");
    }
}

if ($wp_loaded) {
    try {
        // Check if user is logged in
        if (!is_user_logged_in()) {
            write_log("User not logged in. Redirecting to login page.");
            wp_redirect(wp_login_url(admin_url('admin.php?page=ff-spam-blocker')));
            exit;
        }
        
        // Check if user has permission
        if (!current_user_can('manage_options')) {
            write_log("User does not have permission. Access denied.");
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }
        
        write_log("User authenticated and has permission");
        
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            
            // Handle save settings action
            if (isset($_POST['action']) && $_POST['action'] === 'ffb_save_settings') {
                write_log("Form submitted, processing settings update");
                
                // Verify nonce
                if (!isset($_POST['ffb_nonce']) || !wp_verify_nonce($_POST['ffb_nonce'], 'ffb_save_settings')) {
                    write_log("Nonce verification failed");
                    wp_die(__('Security check failed. Please try again.'));
                }
                
                write_log("Nonce verified, processing form data");
                
                // API Key
                if (isset($_POST['ffb_api_key'])) {
                    update_option('ffb_api_key', sanitize_text_field($_POST['ffb_api_key']));
                    write_log("API key updated");
                }
                
                // Approved Countries
                if (isset($_POST['ffb_approved_countries'])) {
                    $countries = sanitize_text_field($_POST['ffb_approved_countries']);
                    $countries = explode(',', $countries);
                    $countries = array_map('trim', $countries);
                    $countries = array_filter($countries);
                    update_option('ffb_approved_countries', $countries);
                    write_log("Approved countries updated: " . implode(', ', $countries));
                }
                
                // Approved States
                if (isset($_POST['ffb_approved_states'])) {
                    $states = sanitize_text_field($_POST['ffb_approved_states']);
                    $states = explode(',', $states);
                    $states = array_map('trim', $states);
                    $states = array_filter($states);
                    update_option('ffb_approved_states', $states);
                    write_log("Approved states updated: " . implode(', ', $states));
                }
                
                // Approved ZIP Codes
                if (isset($_POST['ffb_approved_zip_codes'])) {
                    $zip_codes = sanitize_text_field($_POST['ffb_approved_zip_codes']);
                    $zip_codes = explode(',', $zip_codes);
                    $zip_codes = array_map('trim', $zip_codes);
                    $zip_codes = array_filter($zip_codes);
                    update_option('ffb_approved_zip_codes', $zip_codes);
                    write_log("Approved ZIP codes updated: " . implode(', ', $zip_codes));
                }
                
                // Blocked IPs
                if (isset($_POST['ffb_blocked_ips'])) {
                    $blocked_ips = explode("\n", $_POST['ffb_blocked_ips']);
                    $blocked_ips = array_map('trim', $blocked_ips);
                    $blocked_ips = array_filter($blocked_ips);
                    update_option('ffb_blocked_ips', $blocked_ips);
                    write_log("Blocked IPs updated");
                }
                
                // IP Whitelist
                if (isset($_POST['ffb_ip_whitelist'])) {
                    $whitelist = explode("\n", $_POST['ffb_ip_whitelist']);
                    $whitelist = array_map('trim', $whitelist);
                    $whitelist = array_filter($whitelist);
                    update_option('ffb_ip_whitelist', $whitelist);
                    write_log("IP whitelist updated");
                }
                
                // Rate Limit Time
                if (isset($_POST['ffb_rate_limit_time'])) {
                    update_option('ffb_rate_limit_time', absint($_POST['ffb_rate_limit_time']));
                    write_log("Rate limit time updated");
                }
                
                // Rate Limit Requests
                if (isset($_POST['ffb_rate_limit_requests'])) {
                    update_option('ffb_rate_limit_requests', absint($_POST['ffb_rate_limit_requests']));
                    write_log("Rate limit requests updated");
                }
                
                // Enable Rate Limiting
                $rate_limiting_enabled = isset($_POST['ffb_rate_limiting_enabled']) ? '1' : '0';
                update_option('ffb_rate_limiting_enabled', $rate_limiting_enabled);
                write_log("Rate limiting " . ($rate_limiting_enabled ? 'enabled' : 'disabled'));
                
                // Enable Logging
                $log_enabled = isset($_POST['ffb_log_enabled']) ? '1' : '0';
                update_option('ffb_log_enabled', $log_enabled);
                write_log("Logging " . ($log_enabled ? 'enabled' : 'disabled'));
                
                // Blocked Message
                if (isset($_POST['ffb_blocked_message'])) {
                    update_option('ffb_blocked_message', wp_kses_post($_POST['ffb_blocked_message']));
                    write_log("Blocked message updated");
                }
                
                // Diagnostic Mode
                $diagnostic_mode = isset($_POST['ffb_diagnostic_mode']) ? '1' : '0';
                update_option('ffb_diagnostic_mode', $diagnostic_mode);
                write_log("Diagnostic mode " . ($diagnostic_mode ? 'enabled' : 'disabled'));
                
                // Set transient to show success message
                set_transient('ffb_settings_saved', true, 60);
                write_log("Transient set for settings saved message");
                
                // Redirect back to settings page
                if (isset($_POST['redirect_to'])) {
                    $redirect_to = sanitize_text_field($_POST['redirect_to']);
                    write_log("Redirecting to: {$redirect_to}");
                    safe_redirect($redirect_to);
                    exit;
                } else {
                    write_log("No redirect_to specified, using default");
                    safe_redirect(admin_url('admin.php?page=ff-spam-blocker&settings-updated=true'));
                    exit;
                }
            }
            // Handle create table action
            elseif (isset($_POST['action']) && $_POST['action'] === 'ffb_create_table') {
                write_log("Create table action submitted");
                
                // Verify nonce - UPDATED to match template
                if (!isset($_POST['ffb_table_nonce']) || !wp_verify_nonce($_POST['ffb_table_nonce'], 'ffb_create_table')) {
                    write_log("Nonce verification failed for create table");
                    wp_die(__('Security check failed. Please try again.'));
                }
                
                write_log("Nonce verified for create table");
                
                // Create table function should be available from the main plugin file
                if (function_exists('ffb_create_log_table')) {
                    write_log("Function ffb_create_log_table exists, attempting to create table");
                    
                    // Check if ABSPATH and wp-admin/includes/upgrade.php are available
                    if (defined('ABSPATH')) {
                        write_log("ABSPATH is defined: " . ABSPATH);
                        
                        // Check if upgrade.php exists
                        $upgrade_path = ABSPATH . 'wp-admin/includes/upgrade.php';
                        write_log("Checking for upgrade.php at: " . $upgrade_path);
                        
                        if (file_exists($upgrade_path)) {
                            write_log("wp-admin/includes/upgrade.php exists");
                        } else {
                            write_log("ERROR: wp-admin/includes/upgrade.php not found!");
                        }
                    } else {
                        write_log("ERROR: ABSPATH is not defined!");
                    }
                    
                    // Add error handling around the table creation
                    try {
                        ffb_create_log_table();
                        write_log("Table created successfully");
                    } catch (Exception $e) {
                        write_log("ERROR creating table: " . $e->getMessage());
                        wp_die("Error creating table: " . $e->getMessage());
                    }
                    
                    // Check if the table was actually created
                    global $wpdb;
                    $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
                    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
                    
                    if ($table_exists) {
                        write_log("Table verified to exist: $table_name");
                    } else {
                        write_log("ERROR: Table $table_name does not exist after creation attempt!");
                    }
                    
                    // Set transient to show success message
                    set_transient('ffb_table_created', true, 60);
                    write_log("Transient set for table created message");
                    
                    // Redirect back to settings page
                    if (isset($_POST['redirect_to'])) {
                        $redirect_to = sanitize_text_field($_POST['redirect_to']);
                        write_log("Redirecting to: {$redirect_to}");
                        safe_redirect($redirect_to);
                        exit;
                    } else {
                        write_log("No redirect_to specified for create table, using default");
                        safe_redirect(admin_url('admin.php?page=ff-spam-blocker&table-created=true'));
                        exit;
                    }
                } else {
                    write_log("ffb_create_log_table function not found, using fallback");
                    
                    // Define the create table function here as a fallback
                    if (!function_exists('ffb_create_log_table')) {
                        function ffb_create_log_table() {
                            global $wpdb;
                            $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
                            
                            write_log("Defining fallback ffb_create_log_table function");
                            
                            // Check if the table already exists
                            if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name) {
                                write_log("Table already exists, dropping it for recreation");
                                $wpdb->query("DROP TABLE IF EXISTS $table_name");
                            }
                            
                            // Create the table
                            $charset_collate = $wpdb->get_charset_collate();
                            
                            $sql = "CREATE TABLE $table_name (
                                id mediumint(9) NOT NULL AUTO_INCREMENT,
                                timestamp datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
                                ip_address varchar(45) NOT NULL,
                                country_code varchar(10),
                                country varchar(100),
                                region_name varchar(100),
                                region varchar(100),
                                city varchar(100),
                                zip varchar(20),
                                status varchar(20),
                                reason text,
                                form_id varchar(20),
                                log_type varchar(20) DEFAULT 'form_load',
                                geo_data text,
                                PRIMARY KEY  (id),
                                KEY ip_address (ip_address),
                                KEY status (status),
                                KEY log_type (log_type)
                            ) $charset_collate;";
                            
                            write_log("About to run SQL: " . $sql);
                            
                            // Make sure upgrade.php is included
                            if (!function_exists('dbDelta')) {
                                if (file_exists(ABSPATH . 'wp-admin/includes/upgrade.php')) {
                                    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
                                    write_log("Successfully included wp-admin/includes/upgrade.php");
                                } else {
                                    write_log("ERROR: Could not find wp-admin/includes/upgrade.php");
                                    throw new Exception("Could not find wp-admin/includes/upgrade.php");
                                }
                            }
                            
                            // Run dbDelta
                            try {
                                dbDelta($sql);
                                write_log("dbDelta executed successfully");
                            } catch (Exception $e) {
                                write_log("ERROR in dbDelta: " . $e->getMessage());
                                throw $e;
                            }
                            
                            // Update the DB version option to track that we've created the table
                            update_option('ffb_db_version', '2.1.64');
                            write_log("Updated ffb_db_version option to 2.1.64");
                        }
                    }
                    
                    // Call the fallback function
                    ffb_create_log_table();
                    
                    // Check if the table was actually created
                    global $wpdb;
                    $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
                    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
                    
                    if ($table_exists) {
                        write_log("Table verified to exist: $table_name");
                    } else {
                        write_log("ERROR: Table $table_name does not exist after creation attempt!");
                    }
                    
                    // Set transient to show success message
                    set_transient('ffb_table_created', true, 60);
                    write_log("Transient set for table created message");
                    
                    // Redirect back to settings page
                    if (isset($_POST['redirect_to'])) {
                        $redirect_to = sanitize_text_field($_POST['redirect_to']);
                        write_log("Redirecting to: {$redirect_to}");
                        safe_redirect($redirect_to);
                        exit;
                    } else {
                        write_log("No redirect_to specified for create table, using default");
                        safe_redirect(admin_url('admin.php?page=ff-spam-blocker&table-created=true'));
                        exit;
                    }
                }
            }
            // Handle clear logs action
            elseif (isset($_POST['action']) && $_POST['action'] === 'ffb_clear_logs') {
                write_log("Clear logs action submitted");
                
                // Verify nonce
                if (!isset($_POST['ffb_clear_logs_nonce']) || !wp_verify_nonce($_POST['ffb_clear_logs_nonce'], 'ffb_clear_logs')) {
                    write_log("Nonce verification failed for clear logs");
                    wp_die(__('Security check failed. Please try again.'));
                }
                
                write_log("Nonce verified for clear logs");
                
                global $wpdb;
                $table_name = $wpdb->prefix . 'aqm_formidable_spam_blocker_log';
                write_log("Clearing logs from table: {$table_name}");
                
                $result = $wpdb->query("TRUNCATE TABLE {$table_name}");
                if ($result !== false) {
                    write_log("Logs cleared successfully");
                    
                    // Redirect back to settings page
                    if (isset($_POST['redirect_to'])) {
                        $redirect_to = sanitize_text_field($_POST['redirect_to']);
                        write_log("Redirecting to: {$redirect_to}");
                        safe_redirect($redirect_to);
                        exit;
                    } else {
                        write_log("No redirect_to specified for clear logs, using default");
                        safe_redirect(admin_url('admin.php?page=ff-spam-blocker&logs-cleared=true'));
                        exit;
                    }
                } else {
                    write_log("Error clearing logs: " . $wpdb->last_error);
                    wp_die(__('Error clearing logs: ') . $wpdb->last_error);
                }
            }
            else {
                write_log("Unknown action or no action specified in POST request");
                safe_redirect(admin_url('admin.php?page=ff-spam-blocker&error=unknown_action'));
                exit;
            }
        } else {
            // Not a POST request, redirect to admin page
            write_log("Not a POST request, redirecting to admin page");
            safe_redirect(admin_url('admin.php?page=ff-spam-blocker'));
            exit;
        }
        
    } catch (Exception $e) {
        write_log("Error: " . $e->getMessage());
        wp_die("Error: " . $e->getMessage());
    }
} else {
    write_log("WordPress could not be loaded from any of the attempted paths");
    die("WordPress wp-load.php not found. This script must be placed in the WordPress plugins directory.");
}

// Function to redirect back to the settings page with better error handling
function safe_redirect($url) {
    write_log("Attempting to redirect to: " . $url);
    
    // Try WordPress redirect function if available
    if (function_exists('wp_redirect')) {
        write_log("Using wp_redirect");
        wp_redirect($url);
        exit;
    }
    
    // If headers already sent or wp_redirect not available, use JavaScript
    write_log("Fallback to JavaScript redirect");
    echo '<script type="text/javascript">window.location.href = "' . esc_js($url) . '";</script>';
    echo '<noscript><meta http-equiv="refresh" content="0;url=' . esc_url($url) . '"></noscript>';
    echo '<p>If you are not redirected automatically, please <a href="' . esc_url($url) . '">click here</a>.</p>';
    exit;
}
