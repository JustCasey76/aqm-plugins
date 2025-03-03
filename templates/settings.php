<div class="wrap">
    <h1>AQM Formidable Forms Spam Blocker Settings</h1>
    
    <?php
    // Show settings saved message if applicable
    if (isset($_GET['settings-updated']) || get_transient('ffb_settings_saved')) {
        delete_transient('ffb_settings_saved');
        echo '<div class="notice notice-success is-dismissible"><p>Settings saved successfully!</p></div>';
    }
    
    // Show table created message if applicable
    if (isset($_GET['table-created']) || get_transient('ffb_table_created')) {
        delete_transient('ffb_table_created');
        echo '<div class="notice notice-success is-dismissible"><p>Access log table created successfully!</p></div>';
    }
    ?>
    
    <form method="post" action="<?php echo esc_url(plugin_dir_url(dirname(__FILE__)) . 'direct-settings.php'); ?>">
        <?php wp_nonce_field('ffb_save_settings', 'ffb_nonce'); ?>
        <input type="hidden" name="action" value="ffb_save_settings">
        <input type="hidden" name="redirect_to" value="<?php echo esc_url(admin_url('admin.php?page=ff-spam-blocker&settings-updated=true')); ?>">
        
        <h2>API Settings</h2>
        <table class="form-table">
            <tr>
                <th scope="row">API Key</th>
                <td>
                    <input type="password" name="ffb_api_key" value="<?php echo esc_attr($api_key); ?>" class="regular-text" />
                    <p class="description">Enter your ipapi.com API key. <a href="https://ipapi.com/product" target="_blank">Get an API key</a></p>
                    <button type="button" id="ffb-test-api" class="button">Test API Key</button>
                    <span id="ffb-api-test-result"></span>
                </td>
            </tr>
        </table>

        <h2>Location Settings</h2>
        <table class="form-table">
            <tr>
                <th scope="row">Approved Countries</th>
                <td>
                    <input type="text" name="ffb_approved_countries" value="<?php echo esc_attr(is_array($approved_countries) ? implode(', ', $approved_countries) : $approved_countries); ?>" class="regular-text" />
                    <p class="description">Enter comma-separated list of approved country codes (e.g., US,CA,UK)</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Approved States/Regions</th>
                <td>
                    <input type="text" name="ffb_approved_states" value="<?php echo esc_attr(is_array($approved_states) ? implode(', ', $approved_states) : $approved_states); ?>" class="regular-text" />
                    <p class="description">Enter comma-separated list of approved state/region codes (e.g., NY,CA,TX)</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Approved ZIP Codes</th>
                <td>
                    <input type="text" name="ffb_approved_zip_codes" value="<?php echo esc_attr(is_array($approved_zip_codes) ? implode(', ', $approved_zip_codes) : $approved_zip_codes); ?>" class="regular-text" />
                    <p class="description">Enter comma-separated list of approved ZIP codes (e.g., 12345,12346)</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Blocked Message</th>
                <td>
                    <textarea name="ffb_blocked_message" class="large-text" rows="5"><?php echo esc_html($blocked_message); ?></textarea>
                    <p class="description">Enter the message to display when a form is blocked due to location restrictions.</p>
                </td>
            </tr>
        </table>

        <h2>Rate Limiting</h2>
        <table class="form-table">
            <tr>
                <th scope="row">Enable Rate Limiting</th>
                <td>
                    <input type="checkbox" name="ffb_rate_limit_enabled" value="1" <?php checked('1', $rate_limit_enabled); ?> />
                    <p class="description">Enable rate limiting to prevent form spam</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Max Attempts per IP</th>
                <td>
                    <input type="number" name="ffb_rate_limit_requests" value="<?php echo esc_attr($rate_limit_requests); ?>" class="small-text" />
                    <p class="description">Maximum number of form submission attempts allowed per IP address</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Time Window (seconds)</th>
                <td>
                    <input type="number" name="ffb_rate_limit_timeframe" value="<?php echo esc_attr($rate_limit_timeframe); ?>" class="small-text" />
                    <p class="description">Time window in seconds for rate limiting (3600 = 1 hour)</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Blocked IPs</th>
                <td>
                    <textarea name="ffb_blocked_ips" class="large-text" rows="3"><?php echo esc_html($blocked_ips); ?></textarea>
                    <p class="description">Enter comma-separated list of IPs to block</p>
                </td>
            </tr>
        </table>

        <h2>Logging</h2>
        <?php
        // Check if the table exists
        global $wpdb;
        $table_name = $wpdb->prefix . 'ffb_access_log';
        $table_exists = ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name);
        ?>
        <table class="form-table">
            <tr>
                <th scope="row">Enable Access Logging</th>
                <td>
                    <input type="checkbox" name="ffb_log_enabled" value="1" <?php checked('1', $log_enabled); ?> />
                    <p class="description">Enable logging of access attempts</p>
                </td>
            </tr>
            <tr>
                <th scope="row">Access Log Table</th>
                <td>
                    <?php if ($table_exists): ?>
                        <span style="color: green;">✓ Table exists</span>
                    <?php else: ?>
                        <span style="color: red;">✗ Table does not exist</span>
                    <?php endif; ?>
                    <span id="create-table-container" style="display: inline-block; margin-left: 10px;">
                        <button type="button" id="ffb-create-table-btn" class="button">Create/Recreate Table</button>
                    </span>
                    <p class="description">Use this button to create or recreate the access log table if it's missing or has issues.</p>
                </td>
            </tr>
        </table>

        <h2>API Usage</h2>
        <table class="form-table">
            <tr>
                <th scope="row">Current Usage</th>
                <td>
                    <div id="ffb-api-usage">
                        <p><em>Loading API usage data...</em></p>
                    </div>
                    <button type="button" id="ffb-refresh-usage" class="button">Refresh Usage</button>
                    <p class="description">
                        This shows your current API usage for the month. The ipapi.com service has monthly request limits based on your plan.
                        <a href="https://ipapi.com/documentation" target="_blank">Learn more about API usage and limits</a>
                    </p>
                </td>
            </tr>
        </table>

        <?php submit_button('Save Settings'); ?>
    </form>

    <!-- Separate form for table creation -->
    <form method="post" id="ffb-create-table-form" action="<?php echo esc_url(plugin_dir_url(dirname(__FILE__)) . 'direct-settings.php'); ?>" style="display:none;">
        <input type="hidden" name="action" value="ffb_create_table">
        <input type="hidden" name="redirect_to" value="<?php echo esc_url(admin_url('admin.php?page=ff-spam-blocker&table-created=true')); ?>">
        <?php wp_nonce_field('ffb_create_table', 'ffb_table_nonce'); ?>
    </form>

    <hr>

    <h2>IP Cache Management</h2>
    <table class="form-table">
        <tr>
            <th scope="row">Search IP Cache</th>
            <td>
                <input type="text" id="ffb-ip-search" class="regular-text" placeholder="Enter IP address" />
                <button type="button" id="ffb-search-ip" class="button">Search</button>
                <div id="ffb-ip-search-result"></div>
            </td>
        </tr>
        <tr>
            <th scope="row">Clear IP Cache</th>
            <td>
                <button type="button" id="ffb-clear-cache" class="button">Clear All Cache</button>
                <p class="description">Warning: This will clear all cached IP geolocation data</p>
            </td>
        </tr>
    </table>
</div>
