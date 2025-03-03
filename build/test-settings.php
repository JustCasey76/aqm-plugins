<?php
/**
 * Settings Test Script for AQM Formidable Spam Blocker
 * This file helps diagnose issues with the settings saving process
 */

// Create a log file
$log_file = __DIR__ . '/test-settings.log';
$timestamp = date('Y-m-d H:i:s');

// Log function
function write_log($message) {
    global $log_file, $timestamp;
    file_put_contents($log_file, "[{$timestamp}] {$message}\n", FILE_APPEND);
}

// Initialize log
write_log("Settings Test Script Initialized");

// Load WordPress
$wp_load_path = dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php';
write_log("Looking for WordPress at: {$wp_load_path}");

if (file_exists($wp_load_path)) {
    try {
        require_once($wp_load_path);
        write_log("WordPress loaded successfully");
        
        // Check for active plugin
        if (!function_exists('is_plugin_active')) {
            require_once(ABSPATH . 'wp-admin/includes/plugin.php');
        }
        
        $plugin_file = 'aqm-formidable-spam-blocker/aqm-formidable-spam-blocker.php';
        if (is_plugin_active($plugin_file)) {
            write_log("Plugin is active");
        } else {
            write_log("Plugin is NOT active");
        }
        
        // Check if user is logged in
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            write_log("User is logged in: " . $current_user->user_login);
            
            // Check user capabilities
            if (current_user_can('manage_options')) {
                write_log("User has 'manage_options' capability");
            } else {
                write_log("User does NOT have 'manage_options' capability");
            }
        } else {
            write_log("User is NOT logged in");
        }
        
        // Check admin-post.php hooks
        global $wp_filter;
        if (isset($wp_filter['admin_post_ffb_save_settings'])) {
            write_log("'admin_post_ffb_save_settings' hook is registered");
            $callbacks = $wp_filter['admin_post_ffb_save_settings']->callbacks;
            foreach ($callbacks as $priority => $callback_group) {
                foreach ($callback_group as $id => $callback_data) {
                    $callback = $callback_data['function'];
                    if (is_array($callback)) {
                        if (is_object($callback[0])) {
                            $class = get_class($callback[0]);
                            $method = $callback[1];
                            write_log("Callback: {$class}->{$method} (Priority: {$priority})");
                        } else {
                            $class = $callback[0];
                            $method = $callback[1];
                            write_log("Callback: {$class}::{$method} (Priority: {$priority})");
                        }
                    } else if (is_string($callback)) {
                        write_log("Callback: {$callback} (Priority: {$priority})");
                    } else {
                        write_log("Unknown callback type (Priority: {$priority})");
                    }
                }
            }
        } else {
            write_log("'admin_post_ffb_save_settings' hook is NOT registered");
        }
        
        // Check plugin settings
        $api_key = get_option('ffb_api_key', '');
        write_log("API Key: " . (empty($api_key) ? 'Not set' : 'Set (length: ' . strlen($api_key) . ')'));
        
        $approved_countries = get_option('ffb_approved_countries', array());
        if (is_array($approved_countries)) {
            write_log("Approved Countries: " . implode(', ', $approved_countries));
        } else {
            write_log("Approved Countries is not an array: " . var_export($approved_countries, true));
        }
        
        $approved_states = get_option('ffb_approved_states', array());
        if (is_array($approved_states)) {
            write_log("Approved States: " . implode(', ', $approved_states));
        } else {
            write_log("Approved States is not an array: " . var_export($approved_states, true));
        }
        
        // Display results on screen
        echo '<h1>AQM Formidable Forms Spam Blocker Settings Test</h1>';
        echo '<p>Test completed. Check the <code>test-settings.log</code> file for results.</p>';
        echo '<a href="' . admin_url('admin.php?page=ff-spam-blocker') . '">Return to Settings</a>';
        
    } catch (Exception $e) {
        write_log("Error: " . $e->getMessage());
        die("Error: " . $e->getMessage());
    }
} else {
    write_log("WordPress wp-load.php not found at {$wp_load_path}");
    die("WordPress wp-load.php not found. This script must be placed in the WordPress plugins directory.");
}
