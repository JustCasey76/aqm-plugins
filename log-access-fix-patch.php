<?php
/**
 * Log Access Fix Patch for AQM Formidable Forms Spam Blocker
 * 
 * This file contains the exact code that needs to be replaced in the main plugin file.
 * 
 * INSTRUCTIONS:
 * 1. Find the log_access_attempt method in aqm-formidable-spam-blocker.php
 * 2. Replace the entire method with the code below
 * 3. Update the plugin version to 1.9.9 in the main file
 * 4. Copy the updated file to the build directory
 */

/**
 * Log access attempt with proper database structure
 * 
 * @param string $ip IP address
 * @param string $status Status (allowed, blocked, etc)
 * @param string $reason Reason for the status
 * @param string $form_id Optional form ID
 */
private function log_access_attempt($ip, $status, $reason, $form_id = '') {
    if (!$this->log_enabled) {
        return;
    }
    
    global $wpdb;
    $table_name = $wpdb->prefix . 'aqm_ffb_access_log';
    
    // Check if table exists
    if($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
        ffb_create_log_table();
    }
    
    // Get geo data for the specific IP
    $geo_data = $this->get_geo_data();
    
    $country = isset($geo_data['country_code']) ? $geo_data['country_code'] : '';
    $region = isset($geo_data['region_name']) ? $geo_data['region_name'] : '';
    
    // Prepare data according to the table structure
    $data = array(
        'ip_address' => $ip,
        'country' => $country,
        'region' => $region,
        'status' => $status,
        'message' => $reason . ($form_id ? ' (Form ID: ' . $form_id . ')' : ''),
        'geo_data' => $geo_data ? wp_json_encode($geo_data) : null
    );
    
    $result = $wpdb->insert($table_name, $data);
    
    if ($result === false) {
        error_log('FFB Log Error: ' . $wpdb->last_error);
        
        // If we get an unknown column error, try to update the database structure
        if (strpos($wpdb->last_error, 'Unknown column') !== false) {
            error_log('FFB Debug: Attempting to update database structure...');
            ffb_create_log_table();
            
            // Try the insert again
            $result = $wpdb->insert($table_name, $data);
            
            if ($result === false) {
                error_log('FFB Log Error: Second attempt failed: ' . $wpdb->last_error);
            } else {
                error_log('FFB Debug: Second attempt successful, logged access with ID: ' . $wpdb->insert_id);
            }
        }
    }
}
