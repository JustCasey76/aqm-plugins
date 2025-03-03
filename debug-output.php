<?php
/**
 * Debug Output Tool for AQM Formidable Forms Spam Blocker
 * 
 * This file provides a direct method to add debug output to a log file.
 * Access this by going to: https://your-site.com/wp-content/plugins/aqm-formidable-spam-blocker/debug-output.php
 * 
 * IMPORTANT: Delete this file after debugging is complete for security reasons.
 */

// Create a debug log file in the plugin directory
$log_file = __DIR__ . '/ffb-debug.log';

// Write a timestamp entry
$timestamp = date('Y-m-d H:i:s');
file_put_contents($log_file, "[{$timestamp}] Debug log initialized\n", FILE_APPEND);

// Log server variables
file_put_contents($log_file, "[{$timestamp}] SERVER VARIABLES:\n", FILE_APPEND);
file_put_contents($log_file, print_r($_SERVER, true) . "\n", FILE_APPEND);

// Log request data
file_put_contents($log_file, "[{$timestamp}] REQUEST DATA:\n", FILE_APPEND);
file_put_contents($log_file, "GET: " . print_r($_GET, true) . "\n", FILE_APPEND);
file_put_contents($log_file, "POST: " . print_r($_POST, true) . "\n", FILE_APPEND);
file_put_contents($log_file, "COOKIE: " . print_r($_COOKIE, true) . "\n", FILE_APPEND);

// Log PHP info
file_put_contents($log_file, "[{$timestamp}] PHP INFO:\n", FILE_APPEND);
file_put_contents($log_file, "PHP Version: " . phpversion() . "\n", FILE_APPEND);
file_put_contents($log_file, "error_log path: " . ini_get('error_log') . "\n", FILE_APPEND);
file_put_contents($log_file, "display_errors: " . ini_get('display_errors') . "\n", FILE_APPEND);
file_put_contents($log_file, "log_errors: " . ini_get('log_errors') . "\n", FILE_APPEND);

// Output success message
echo "Debug information has been written to: {$log_file}";
echo "<br><br>You can view the log file at: <a href='ffb-debug.log'>ffb-debug.log</a>";
echo "<br><br><strong>Security Note:</strong> Please delete both this file and the log file after debugging is complete.";
