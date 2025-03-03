<?php
/**
 * Debug POST request handler for AQM Formidable Forms Spam Blocker
 */

// Create a log file in the plugin directory
$log_file = __DIR__ . '/debug-post.log';
$timestamp = date('Y-m-d H:i:s');

// Log function
function write_log($message) {
    global $log_file, $timestamp;
    file_put_contents($log_file, "[{$timestamp}] {$message}\n", FILE_APPEND);
}

// Initialize log
write_log("Debug POST Handler Initialized");

// Write POST data
write_log("POST Data: " . print_r($_POST, true));

// Try to load WordPress
$wp_load_path = dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php';
write_log("Looking for WordPress at: {$wp_load_path}");

if (file_exists($wp_load_path)) {
    try {
        require_once($wp_load_path);
        write_log("WordPress loaded successfully");
        
        // Check if user is logged in
        if (!is_user_logged_in()) {
            write_log("Error: User not logged in");
            echo 'You must be logged in as an administrator to update settings.';
            exit;
        }
        
        // Check if user has permission
        if (!current_user_can('manage_options')) {
            write_log("Error: Insufficient permissions");
            echo 'You must be an administrator to update settings.';
            exit;
        }
        
        // Process form submissions
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            
            // Handle save settings action
            if (isset($_POST['action']) && $_POST['action'] === 'ffb_save_settings') {
                write_log("Form submitted, processing settings update");
                
                // Verify nonce
                if (!isset($_POST['ffb_nonce']) || !wp_verify_nonce($_POST['ffb_nonce'], 'ffb_save_settings')) {
                    write_log("Error: Invalid nonce");
                    echo 'Security check failed. Please refresh the page and try again.';
                    exit;
                }
                
                // Save API key
                if (isset($_POST['ffb_api_key'])) {
                    $api_key = sanitize_text_field($_POST['ffb_api_key']);
                    write_log("Saving API key: " . substr($api_key, 0, 4) . '...');
                    update_option('ffb_api_key', $api_key);
                }
                
                // Save approved countries
                if (isset($_POST['ffb_approved_countries'])) {
                    $countries = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_countries']));
                    $countries = array_map('trim', $countries);
                    $countries = array_filter($countries);
                    update_option('ffb_approved_countries', $countries);
                    write_log("Saving approved countries: " . implode(',', $countries));
                } else {
                    update_option('ffb_approved_countries', array());
                    write_log("Cleared approved countries");
                }
                
                // Save approved states
                if (isset($_POST['ffb_approved_states'])) {
                    $states = array_map('sanitize_text_field', explode(',', $_POST['ffb_approved_states']));
                    $states = array_map('trim', $states);
                    update_option('ffb_approved_states', $states);
                    write_log("Saving approved states: " . implode(',', $states));
                } else {
                    update_option('ffb_approved_states', array());
                    write_log("Cleared approved states");
                }
                
                // Save all forms selection
                update_option('ffb_block_all_forms', isset($_POST['ffb_block_all_forms']) ? '1' : '0');
                
                // Set transient to show success message
                set_transient('ffb_settings_saved', true, 30);
                
                // Get the redirect URL
                $redirect_url = isset($_POST['redirect_to']) ? 
                    esc_url_raw($_POST['redirect_to']) : 
                    admin_url('admin.php?page=ff-spam-blocker&settings-updated=true');
                
                write_log("Settings saved successfully. Redirecting to: {$redirect_url}");
                
                // Redirect back to settings page
                wp_redirect($redirect_url);
                exit;
            }
        }
        
        // If we get here, something went wrong
        write_log("Error: No action taken");
        echo 'No action taken. Please try again or contact support.';
        
    } catch (Exception $e) {
        write_log("Error: " . $e->getMessage());
        echo "Error: " . $e->getMessage();
    }
} else {
    write_log("WordPress wp-load.php not found at {$wp_load_path}");
    echo "WordPress wp-load.php not found. This script must be placed in the WordPress plugins directory.";
}
