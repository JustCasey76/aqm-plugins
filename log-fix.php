<?php
// This is a temporary fix for the database structure issue

// Add this code to the log_access method in the main plugin file
if ($result === false) {
    error_log('FFB Log Error: ' . $wpdb->last_error);
    
    // If we get an unknown column error, try to update the database structure
    if (strpos($wpdb->last_error, 'Unknown column') !== false) {
        error_log('FFB Debug: Attempting to update database structure...');
        ffb_create_log_table();
        
        // Try the insert again
        $result = $wpdb->insert(
            $table_name,
            $data,
            array(
                '%s', // ip_address
                '%s', // country
                '%s', // region
                '%s', // status
                '%s', // message
                '%s'  // geo_data
            )
        );
        
        if ($result === false) {
            error_log('FFB Log Error: Second attempt failed: ' . $wpdb->last_error);
        } else {
            error_log('FFB Debug: Second attempt successful, logged access with ID: ' . $wpdb->insert_id);
        }
    }
} else {
    error_log('FFB Debug: Successfully logged access with ID: ' . $wpdb->insert_id);
}
