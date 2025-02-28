<?php
/**
 * Log Access Fix for AQM Formidable Forms Spam Blocker
 * 
 * This file contains the complete fix for the database structure mismatch.
 * 
 * 1. Update the log_access_attempt method to match the database structure
 * 2. Update the database table creation if needed
 * 
 * Instructions:
 * 1. Replace the log_access_attempt method in the main plugin file with the one below
 * 2. Verify that the database table structure matches the one in ffb_create_log_table
 */

/**
 * Updated log_access_attempt method
 */
/*
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
*/

/**
 * Database table structure for reference
 * 
 * This is the current structure from ffb_create_log_table():
 * 
 * CREATE TABLE IF NOT EXISTS {prefix}aqm_ffb_access_log (
 *     id bigint(20) NOT NULL AUTO_INCREMENT,
 *     timestamp datetime DEFAULT CURRENT_TIMESTAMP,
 *     ip_address varchar(45) NOT NULL,
 *     country varchar(2),
 *     region varchar(50),
 *     status varchar(20) NOT NULL,
 *     message text,
 *     geo_data longtext,
 *     PRIMARY KEY  (id),
 *     KEY timestamp (timestamp),
 *     KEY ip_address (ip_address),
 *     KEY status (status)
 * )
 * 
 * The current log_access_attempt method is trying to insert:
 * - time
 * - ip_address
 * - country
 * - region
 * - zip_code
 * - form_id
 * - status
 * - reason
 * - geo_data
 * 
 * The mismatch is causing the "Unknown column" error.
 */
