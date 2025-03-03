<?php
/**
 * Simple Log Viewer for AQM Formidable Forms Spam Blocker
 * 
 * This file provides a basic interface to view PHP error logs directly in the WordPress admin.
 * Access this by going to: https://your-site.com/wp-content/plugins/aqm-formidable-spam-blocker/simple-logs.php
 * 
 * IMPORTANT: Delete this file after debugging is complete for security reasons.
 */

// Basic security check - require WordPress admin
if (!isset($_COOKIE['wordpress_logged_in']) && !isset($_COOKIE['wordpress_test_cookie'])) {
    die('You must be logged in as an administrator to view logs.');
}

// Set the content type
header('Content-Type: text/html; charset=utf-8');

// Function to get log content
function get_log_content($lines = 300) {
    // Try common log locations
    $possible_logs = array(
        // WordPress debug log
        dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-content/debug.log',
        // PHP error log from php.ini
        ini_get('error_log'),
        // Common server logs
        '/var/log/apache2/error.log',
        '/var/log/httpd/error.log',
        '/var/log/nginx/error.log',
        '/var/log/php-errors.log'
    );
    
    foreach ($possible_logs as $log_path) {
        if ($log_path && file_exists($log_path) && is_readable($log_path)) {
            // Try to read the file
            $content = @file_get_contents($log_path);
            if ($content !== false) {
                // Get the last X lines
                $lines_array = explode("\n", $content);
                $lines_array = array_slice($lines_array, -$lines);
                return array(
                    'path' => $log_path,
                    'content' => implode("\n", $lines_array)
                );
            }
        }
    }
    
    return array(
        'path' => 'No log files found',
        'content' => 'Could not find or read any log files.'
    );
}

// Get log content
$log_data = get_log_content();
$log_path = $log_data['path'];
$log_content = $log_data['content'];

// Filter for FFB logs if requested
$filter_ffb = isset($_GET['filter']) && $_GET['filter'] === 'ffb';
if ($filter_ffb) {
    $lines = explode("\n", $log_content);
    $filtered_lines = array();
    
    foreach ($lines as $line) {
        if (strpos($line, 'FFB Debug') !== false) {
            $filtered_lines[] = $line;
        }
    }
    
    $log_content = implode("\n", $filtered_lines);
}

// Basic HTML escape
$log_content_safe = htmlspecialchars($log_content);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Simple Log Viewer</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        pre { background: #f0f0f0; padding: 10px; overflow: auto; max-height: 600px; }
        .controls { margin: 15px 0; }
        .controls a { margin-right: 10px; }
        .path { color: #666; font-style: italic; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>Simple Log Viewer</h1>
    
    <div class="controls">
        <a href="?<?php echo $filter_ffb ? '' : 'filter=ffb'; ?>"><?php echo $filter_ffb ? 'Show All Logs' : 'Show Only FFB Logs'; ?></a>
        <a href="?">Refresh</a>
    </div>
    
    <div class="path">
        Log file: <?php echo htmlspecialchars($log_path); ?>
        <?php if ($filter_ffb): ?>
        (Filtered to show only FFB Debug entries)
        <?php endif; ?>
    </div>
    
    <pre><?php echo $log_content_safe; ?></pre>
    
    <p><strong>Security Note:</strong> Please delete this file after debugging is complete.</p>
</body>
</html>
