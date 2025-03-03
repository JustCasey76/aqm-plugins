<?php
/**
 * Save Settings Debug Tool for AQM Formidable Forms Spam Blocker
 * 
 * This file helps diagnose issues with the settings saving process.
 * Access this by going to: https://normanbuilders.com/wp-content/plugins/aqm-formidable-spam-blocker/save-debug.php
 * 
 * IMPORTANT: Delete this file after debugging is complete for security reasons.
 */

// Create a debug log file in the plugin directory
$log_file = __DIR__ . '/save-debug.log';

// Write a timestamp entry
$timestamp = date('Y-m-d H:i:s');
file_put_contents($log_file, "[{$timestamp}] Save Debug Tool Initialized\n", FILE_APPEND);

// Log PHP error log path
$error_log_path = ini_get('error_log');
file_put_contents($log_file, "[{$timestamp}] PHP error_log path: {$error_log_path}\n", FILE_APPEND);

// Try to read the PHP error log
if ($error_log_path && file_exists($error_log_path) && is_readable($error_log_path)) {
    $error_log_content = file_get_contents($error_log_path);
    if ($error_log_content !== false) {
        // Extract FFB Debug lines
        preg_match_all('/.*FFB Debug.*/', $error_log_content, $matches);
        if (!empty($matches[0])) {
            file_put_contents($log_file, "[{$timestamp}] Found FFB Debug entries in error log:\n", FILE_APPEND);
            file_put_contents($log_file, implode("\n", $matches[0]) . "\n", FILE_APPEND);
        } else {
            file_put_contents($log_file, "[{$timestamp}] No FFB Debug entries found in error log.\n", FILE_APPEND);
        }
    } else {
        file_put_contents($log_file, "[{$timestamp}] Could not read error log content.\n", FILE_APPEND);
    }
} else {
    file_put_contents($log_file, "[{$timestamp}] Error log not found or not readable.\n", FILE_APPEND);
}

// Check if WordPress is loaded
if (file_exists(dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php')) {
    // Try to load WordPress
    try {
        require_once(dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php');
        file_put_contents($log_file, "[{$timestamp}] WordPress loaded successfully.\n", FILE_APPEND);
        
        // Check if user is logged in
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            file_put_contents($log_file, "[{$timestamp}] User is logged in.\n", FILE_APPEND);
            
            // Check if user has admin capabilities
            if (function_exists('current_user_can') && current_user_can('manage_options')) {
                file_put_contents($log_file, "[{$timestamp}] User has admin capabilities.\n", FILE_APPEND);
                
                // Check nonce creation
                if (function_exists('wp_create_nonce')) {
                    $test_nonce = wp_create_nonce('ffb_save_settings');
                    file_put_contents($log_file, "[{$timestamp}] Test nonce created: {$test_nonce}\n", FILE_APPEND);
                    
                    // Check nonce verification
                    if (function_exists('wp_verify_nonce')) {
                        $verify_result = wp_verify_nonce($test_nonce, 'ffb_save_settings') ? 'valid' : 'invalid';
                        file_put_contents($log_file, "[{$timestamp}] Nonce verification test: {$verify_result}\n", FILE_APPEND);
                    }
                }
                
                // Check FFB options
                if (function_exists('get_option')) {
                    $api_key = get_option('ffb_api_key', 'not set');
                    // Mask the API key for security
                    $masked_key = substr($api_key, 0, 4) . '...' . substr($api_key, -4);
                    file_put_contents($log_file, "[{$timestamp}] Current API key: {$masked_key}\n", FILE_APPEND);
                    
                    // Test option update
                    $test_option = 'ffb_test_option_' . time();
                    $update_result = update_option($test_option, 'test_value') ? 'success' : 'failed';
                    file_put_contents($log_file, "[{$timestamp}] Test option update: {$update_result}\n", FILE_APPEND);
                    
                    // Clean up test option
                    delete_option($test_option);
                }
            } else {
                file_put_contents($log_file, "[{$timestamp}] User does not have admin capabilities.\n", FILE_APPEND);
            }
        } else {
            file_put_contents($log_file, "[{$timestamp}] User is not logged in.\n", FILE_APPEND);
        }
    } catch (Exception $e) {
        file_put_contents($log_file, "[{$timestamp}] Error loading WordPress: " . $e->getMessage() . "\n", FILE_APPEND);
    }
} else {
    file_put_contents($log_file, "[{$timestamp}] WordPress wp-load.php not found.\n", FILE_APPEND);
}

// Create a simple form to test saving settings
$form_html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Save Settings Debug Tool</title>
    <style>
        body { font-family: sans-serif; margin: 20px; line-height: 1.5; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #23282d; }
        .test-form { background: #fff; padding: 20px; border: 1px solid #ccc; margin: 20px 0; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 8px; box-sizing: border-box; }
        button { background: #0085ba; color: #fff; border: none; padding: 10px 15px; cursor: pointer; }
        .log-view { background: #f0f0f0; padding: 15px; max-height: 400px; overflow: auto; font-family: monospace; }
        .note { color: #d63638; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Save Settings Debug Tool</h1>
        
        <div class="test-form">
            <h2>Test API Key Save</h2>
            <p>This form will directly update the API key option in the database, bypassing the normal save_settings function.</p>
            
            <form method="post" action="">
                <div class="form-group">
                    <label for="api_key">API Key:</label>
                    <input type="text" id="api_key" name="api_key" placeholder="Enter API key">
                </div>
                <button type="submit" name="direct_update">Update API Key Directly</button>
            </form>
        </div>
        
        <div class="test-form">
            <h2>Test Normal Save Process</h2>
            <p>This form will submit to admin-post.php using the normal save_settings function.</p>
            
            <form method="post" action="/wp-admin/admin-post.php">
                <input type="hidden" name="action" value="ffb_save_settings">
                <div class="form-group">
                    <label for="ffb_api_key">API Key:</label>
                    <input type="text" id="ffb_api_key" name="ffb_api_key" placeholder="Enter API key">
                </div>
                <div class="form-group">
                    <label for="ffb_nonce">Nonce:</label>
                    <input type="text" id="ffb_nonce" name="ffb_nonce" value="<?php echo isset($test_nonce) ? $test_nonce : ''; ?>" readonly>
                </div>
                <button type="submit">Save Settings</button>
            </form>
        </div>
        
        <h2>Debug Log</h2>
        <div class="log-view">
            <?php 
            if (file_exists($log_file)) {
                echo nl2br(htmlspecialchars(file_get_contents($log_file)));
            } else {
                echo "No log file found.";
            }
            ?>
        </div>
        
        <p class="note"><strong>Security Note:</strong> Please delete this file after debugging is complete.</p>
    </div>
</body>
</html>
HTML;

// Process direct update if submitted
if (isset($_POST['direct_update']) && isset($_POST['api_key'])) {
    // Try to load WordPress if not already loaded
    if (!function_exists('update_option') && file_exists(dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php')) {
        require_once(dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php');
    }
    
    if (function_exists('update_option')) {
        $api_key = trim($_POST['api_key']);
        $update_result = update_option('ffb_api_key', $api_key) ? 'success' : 'failed';
        file_put_contents($log_file, "[{$timestamp}] Direct API key update: {$update_result}\n", FILE_APPEND);
        
        // Redirect to prevent form resubmission
        header('Location: ' . $_SERVER['PHP_SELF'] . '?updated=1');
        exit;
    } else {
        file_put_contents($log_file, "[{$timestamp}] Direct update failed: WordPress functions not available\n", FILE_APPEND);
    }
}

// Display success message
if (isset($_GET['updated'])) {
    echo '<div style="background: #d4edda; color: #155724; padding: 10px; margin-bottom: 15px; border-radius: 4px;">API key updated successfully.</div>';
}

// Output the form
echo $form_html;
