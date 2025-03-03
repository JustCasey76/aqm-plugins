<?php
/**
 * Simple test script for ipapi.com API
 * 
 * This script tests the API connection directly without WordPress
 * 
 * INSTRUCTIONS:
 * 1. Enter your API key below
 * 2. Run this script from the command line: php api-test.php
 * 3. Check the output for any errors
 */

// Replace with your actual API key
$api_key = ''; // ENTER YOUR API KEY HERE

// Get the user's actual IP address
function get_client_ip() {
    // Check for various server variables that might contain the IP
    $ip_keys = array(
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    );
    
    foreach ($ip_keys as $key) {
        if (isset($_SERVER[$key]) && filter_var($_SERVER[$key], FILTER_VALIDATE_IP)) {
            return $_SERVER[$key];
        }
    }
    
    // Default fallback if we couldn't determine a valid IP
    return '127.0.0.1';
}

// Use actual IP address for testing instead of hardcoded Google DNS
$test_ip = get_client_ip();

// API URL
$api_url = "https://api.ipapi.com/api/{$test_ip}?access_key={$api_key}";

echo "Testing API URL: {$api_url}\n\n";

// Basic validation of API key format
$api_key = trim($api_key); // Remove any whitespace
if (empty($api_key)) {
    echo "ERROR: API key is required\n";
    exit(1);
}

if (!preg_match('/^[a-zA-Z0-9]{32}$/', $api_key)) {
    echo "WARNING: API key format appears invalid. It should be a 32-character alphanumeric string.\n";
    echo "Your key: " . substr($api_key, 0, 5) . "...\n\n";
    // Continue anyway for testing
}

// Make the request using cURL directly
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
curl_setopt($ch, CURLOPT_USERAGENT, 'PHP Test Script');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_HEADER, true); // Include headers in output

$response = curl_exec($ch);
$error = curl_error($ch);
$info = curl_getinfo($ch);
curl_close($ch);

echo "HTTP Status Code: " . $info['http_code'] . "\n\n";

if (!empty($error)) {
    echo "cURL Error: " . $error . "\n\n";
}

// Split headers and body
$header_size = $info['header_size'];
$headers = substr($response, 0, $header_size);
$body = substr($response, $header_size);

echo "Response Headers:\n";
echo $headers . "\n\n";

echo "Raw Response Body:\n";
echo $body . "\n\n";

$data = json_decode($body, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    echo "JSON Parsing Error: " . json_last_error_msg() . "\n\n";
} else {
    echo "Decoded Response:\n";
    print_r($data);
    
    // Check for API errors
    if (isset($data['success']) && $data['success'] === false) {
        echo "\nAPI ERROR DETECTED:\n";
        echo "Error Type: " . (isset($data['error']['type']) ? $data['error']['type'] : 'Unknown') . "\n";
        echo "Error Code: " . (isset($data['error']['code']) ? $data['error']['code'] : 'Unknown') . "\n";
        echo "Error Info: " . (isset($data['error']['info']) ? $data['error']['info'] : 'No additional info') . "\n";
    }
}

echo "\n\nTROUBLESHOOTING TIPS:\n";
echo "1. Make sure your API key is correct and active\n";
echo "2. Log in to your ipapi.com account to check your subscription status\n";
echo "3. Check if you've reached your monthly API request limit\n";
echo "4. Try generating a new API key from your account dashboard\n";
echo "5. Contact ipapi.com support at support@apilayer.com for assistance\n";
