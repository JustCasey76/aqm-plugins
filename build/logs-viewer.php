<?php
/**
 * Log Viewer for AQM Formidable Forms Spam Blocker
 * 
 * This file provides a simple interface to view PHP error logs directly in the WordPress admin.
 * Access this by going to: https://your-site.com/wp-content/plugins/aqm-formidable-spam-blocker/logs-viewer.php
 * 
 * IMPORTANT: Delete this file after debugging is complete for security reasons.
 */

// Verify WordPress environment
if (!defined('ABSPATH')) {
    // Define ABSPATH if not already defined
    define('ABSPATH', dirname(dirname(dirname(dirname(__FILE__)))) . '/');
}

// Try to load WordPress
if (file_exists(ABSPATH . 'wp-load.php')) {
    require_once(ABSPATH . 'wp-load.php');
} else {
    die('WordPress not found. This script must be placed in the WordPress plugins directory.');
}

// Security check - only allow administrators
if (!current_user_can('manage_options')) {
    wp_die('You do not have sufficient permissions to access this page.');
}

// Set the content type
header('Content-Type: text/html; charset=utf-8');

// Function to get log file paths
function get_possible_log_paths() {
    $paths = array();
    
    // WordPress debug log (if WP_DEBUG_LOG is true)
    $paths[] = ABSPATH . 'wp-content/debug.log';
    
    // Common server log locations
    $paths[] = '/var/log/apache2/error.log';
    $paths[] = '/var/log/httpd/error.log';
    $paths[] = '/var/log/nginx/error.log';
    $paths[] = '/var/log/php-errors.log';
    $paths[] = '/var/log/php_errors.log';
    
    // PHP error log from php.ini
    $php_error_log = ini_get('error_log');
    if ($php_error_log) {
        $paths[] = $php_error_log;
    }
    
    return $paths;
}

// Function to get log content
function get_log_content($log_path, $lines = 500) {
    if (!file_exists($log_path) || !is_readable($log_path)) {
        return "Log file not found or not readable: $log_path";
    }
    
    // Get the last X lines of the log file
    $log_content = shell_exec("tail -n $lines " . escapeshellarg($log_path));
    
    if (!$log_content) {
        // Try PHP method if shell_exec fails
        $log_content = file_get_contents($log_path);
        if ($log_content) {
            $log_lines = explode("\n", $log_content);
            $log_lines = array_slice($log_lines, -$lines);
            $log_content = implode("\n", $log_lines);
        }
    }
    
    return $log_content ?: "No content found in log file.";
}

// Function to filter log for FFB Debug entries
function filter_ffb_logs($log_content) {
    $lines = explode("\n", $log_content);
    $filtered_lines = array();
    
    foreach ($lines as $line) {
        if (strpos($line, 'FFB Debug') !== false) {
            $filtered_lines[] = $line;
        }
    }
    
    return implode("\n", $filtered_lines);
}

// Get the log file path
$log_paths = get_possible_log_paths();
$log_content = "No log files found or accessible.";

// Try each path until we find one
foreach ($log_paths as $path) {
    if (file_exists($path) && is_readable($path)) {
        $log_content = get_log_content($path);
        $found_path = $path;
        break;
    }
}

// Filter for FFB logs if requested
$filter_ffb = isset($_GET['filter']) && $_GET['filter'] === 'ffb';
if ($filter_ffb && isset($log_content)) {
    $log_content = filter_ffb_logs($log_content);
}

// Refresh interval (in seconds)
$refresh_interval = isset($_GET['refresh']) ? intval($_GET['refresh']) : 0;
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AQM Formidable Forms Spam Blocker - Log Viewer</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            line-height: 1.5;
            color: #333;
            background: #f1f1f1;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        h1 {
            color: #23282d;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .log-container {
            background: #23282d;
            color: #eee;
            padding: 15px;
            border-radius: 3px;
            overflow: auto;
            max-height: 600px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
        }
        .log-container .ffb-highlight {
            color: #46b450;
            font-weight: bold;
        }
        .controls {
            margin: 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .controls a, .controls button {
            display: inline-block;
            background: #0085ba;
            color: #fff;
            padding: 8px 12px;
            text-decoration: none;
            border-radius: 3px;
            border: none;
            cursor: pointer;
            font-size: 13px;
        }
        .controls a:hover, .controls button:hover {
            background: #006799;
        }
        .path-info {
            margin-bottom: 15px;
            font-style: italic;
            color: #666;
        }
        .error {
            color: #dc3232;
            font-weight: bold;
        }
        .warning {
            color: #ffb900;
        }
        .success {
            color: #46b450;
        }
    </style>
    <?php if ($refresh_interval > 0): ?>
    <meta http-equiv="refresh" content="<?php echo $refresh_interval; ?>">
    <?php endif; ?>
</head>
<body>
    <div class="container">
        <h1>AQM Formidable Forms Spam Blocker - Log Viewer</h1>
        
        <div class="controls">
            <div>
                <a href="?<?php echo $filter_ffb ? '' : 'filter=ffb'; ?>"><?php echo $filter_ffb ? 'Show All Logs' : 'Show Only FFB Logs'; ?></a>
                <a href="?<?php echo $filter_ffb ? 'filter=ffb&' : ''; ?>refresh=10">Auto-Refresh (10s)</a>
                <a href="?<?php echo $filter_ffb ? 'filter=ffb' : ''; ?>">Stop Auto-Refresh</a>
            </div>
            <div>
                <button onclick="copyToClipboard()">Copy Logs to Clipboard</button>
            </div>
        </div>
        
        <?php if (isset($found_path)): ?>
        <div class="path-info">
            Showing logs from: <?php echo htmlspecialchars($found_path); ?>
            <?php if ($refresh_interval > 0): ?>
            <span class="success"> (Auto-refreshing every <?php echo $refresh_interval; ?> seconds)</span>
            <?php endif; ?>
            <?php if ($filter_ffb): ?>
            <span class="warning"> (Filtered to show only FFB Debug entries)</span>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        
        <div class="log-container" id="log-content">
            <?php 
            if (empty($log_content) || $log_content === "No content found in log file." || $log_content === "No log files found or accessible.") {
                echo '<span class="error">' . $log_content . '</span>';
            } else {
                // Highlight FFB Debug entries
                $log_content = htmlspecialchars($log_content);
                $log_content = preg_replace('/\[(.*?)\]/', '<span style="color: #ffb900;">[$1]</span>', $log_content);
                $log_content = preg_replace('/(FFB Debug:.*?)(\n|$)/', '<span class="ffb-highlight">$1</span>$2', $log_content);
                $log_content = preg_replace('/(PHP (?:Parse|Fatal|Warning|Notice) error:.*?)(\n|$)/', '<span style="color: #dc3232;">$1</span>$2', $log_content);
                
                echo $log_content;
            }
            ?>
        </div>
        
        <div class="controls" style="margin-top: 20px;">
            <a href="<?php echo admin_url('admin.php?page=ff-spam-blocker'); ?>">Return to FF Spam Blocker Settings</a>
            <div>
                <a href="<?php echo $_SERVER['REQUEST_URI']; ?>">Refresh Logs</a>
            </div>
        </div>
        
        <p><strong class="warning">Security Note:</strong> Please delete this file after debugging is complete for security reasons.</p>
    </div>
    
    <script>
        function copyToClipboard() {
            const logContent = document.getElementById('log-content');
            const textArea = document.createElement('textarea');
            textArea.value = logContent.textContent;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            alert('Logs copied to clipboard!');
        }
        
        // Scroll to bottom of log container on load
        window.onload = function() {
            const logContainer = document.querySelector('.log-container');
            logContainer.scrollTop = logContainer.scrollHeight;
        };
    </script>
</body>
</html>
