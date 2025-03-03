jQuery(document).ready(function($) {
    // Debug: Check if ffbAdminVars is defined
    if (typeof ffbAdminVars === 'undefined') {
        console.error('ffbAdminVars is not defined!');
        // Create a fallback object to prevent errors
        window.ffbAdminVars = {
            nonce: '',
            ajax_url: ajaxurl || '',
            refreshing_usage: 'Refreshing...',
            searching: 'Searching...',
            clearing_cache: 'Clearing cache...'
        };
    } else {
        console.log('ffbAdminVars is defined:', ffbAdminVars);
    }
    
    // Test API Key
    $('#ffb-test-api').on('click', function() {
        var button = $(this);
        var resultDiv = $('#ffb-api-test-result');
        var apiKey = $('input[name="ffb_api_key"]').val();
        
        if (!apiKey) {
            resultDiv.html('<div class="notice notice-error"><p>Please enter an API key first</p></div>');
            return;
        }
        
        button.prop('disabled', true);
        resultDiv.html('Testing API key...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ffb_test_api_key',
                nonce: ffbAdminVars.nonce,
                api_key: apiKey
            },
            success: function(response) {
                if (response.success) {
                    var html = '<div class="notice notice-success"><p>' + response.data.message + '</p>';
                    
                    // Add API response details
                    if (response.data.data) {
                        var data = response.data.data;
                        html += '<div style="margin-top: 10px;"><strong>API Response:</strong>';
                        html += '<pre style="background: #f8f8f8; padding: 10px; overflow: auto; max-height: 200px;">';
                        html += JSON.stringify(data, null, 2);
                        html += '</pre></div>';
                    }
                    
                    html += '</div>';
                    resultDiv.html(html);
                } else {
                    resultDiv.html('<div class="notice notice-error"><p>' + response.data + '</p></div>');
                }
            },
            error: function() {
                resultDiv.html('<div class="notice notice-error"><p>Failed to test API key. Please try again.</p></div>');
            },
            complete: function() {
                button.prop('disabled', false);
            }
        });
    });
    
    // Check Location
    $('#ffb-check-location').on('click', function() {
        var button = $(this);
        var ip = $('#ffb-test-ip').val();
        var resultTable = $('#ffb-location-result table');
        
        if (!ip) {
            alert('Please enter an IP address');
            return;
        }
        
        button.prop('disabled', true);
        resultTable.hide();
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ffb_check_location',
                ip: ip,
                nonce: ffbAdminVars.nonce
            },
            success: function(response) {
                if (response.success && response.data) {
                    var data = response.data;
                    resultTable.find('.country-code').text(data.country_code || '');
                    resultTable.find('.country-name').text(data.country_name || '');
                    resultTable.find('.region-code').text(data.region_code || '');
                    resultTable.find('.region-name').text(data.region_name || '');
                    resultTable.find('.city').text(data.city || '');
                    resultTable.find('.zip').text(data.zip || '');
                    resultTable.find('.status').text(data.is_blocked ? 'Blocked' : 'Allowed');
                    resultTable.show();
                } else {
                    alert('Failed to get location data: ' + (response.data || 'Unknown error'));
                }
            },
            error: function() {
                alert('Failed to check location. Please try again.');
            },
            complete: function() {
                button.prop('disabled', false);
            }
        });
    });
    
    // Refresh API Usage
    function refreshApiUsage() {
        var usageDiv = $('#ffb-api-usage');
        var refreshButton = $('#ffb-refresh-usage');
        
        refreshButton.prop('disabled', true);
        refreshButton.text(ffbAdminVars.refreshing_usage);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ffb_refresh_api_usage',
                nonce: ffbAdminVars.nonce
            },
            success: function(response) {
                if (response.success) {
                    var usage = response.data;
                    var html = '<table class="widefat">';
                    html += '<tr><th>Current Month</th><td>' + usage.month + '</td></tr>';
                    
                    // Calculate percentage for progress bar
                    var percentage = Math.min(Math.round((usage.requests / usage.limit) * 100), 100);
                    var barColor = percentage < 70 ? 'green' : (percentage < 90 ? 'orange' : 'red');
                    
                    html += '<tr><th>Requests Used</th><td>' + 
                           usage.requests + ' of ' + usage.limit + 
                           ' (' + percentage + '%)' +
                           '<div style="background-color: #f0f0f0; width: 100%; height: 20px; margin-top: 5px; border-radius: 3px;">' +
                           '<div style="background-color: ' + barColor + '; width: ' + percentage + '%; height: 20px; border-radius: 3px;"></div>' +
                           '</div></td></tr>';
                    
                    html += '<tr><th>Last Updated</th><td>' + new Date(usage.last_check * 1000).toLocaleString() + '</td></tr>';
                    
                    // Show a note if this is demo data
                    if (usage.is_demo) {
                        html += '<tr><td colspan="2"><em>Note: This is demo data. Connect your API key for actual usage statistics.</em></td></tr>';
                    }
                    
                    html += '</table>';
                    usageDiv.html(html);
                } else {
                    usageDiv.html('<div class="notice notice-error"><p>Failed to get API usage data: ' + (response.data || 'Unknown error') + '</p></div>');
                }
            },
            error: function() {
                usageDiv.html('<div class="notice notice-error"><p>Failed to refresh API usage. Please try again.</p></div>');
            },
            complete: function() {
                refreshButton.prop('disabled', false);
                refreshButton.text('Refresh Usage');
            }
        });
    }
    
    $('#ffb-refresh-usage').on('click', refreshApiUsage);
    refreshApiUsage(); // Initial load
    
    // Search IP
    $('#ffb-search-ip').on('click', function() {
        var button = $(this);
        var resultDiv = $('#ffb-ip-search-result');
        var ip = $('#ffb-ip-search').val();
        
        if (!ip) {
            resultDiv.html('<div class="notice notice-error"><p>Please enter an IP address</p></div>');
            return;
        }
        
        button.prop('disabled', true);
        resultDiv.html('<p><em>' + ffbAdminVars.searching + '</em></p>');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ffb_search_ip',
                nonce: ffbAdminVars.nonce,
                ip: ip
            },
            success: function(response) {
                if (response.success) {
                    if (response.data.found) {
                        var html = '<div class="notice notice-success"><p>IP found in cache!</p>';
                        
                        // Add geo data details
                        if (response.data.geo_data) {
                            var data = response.data.geo_data;
                            html += '<div style="margin-top: 10px;"><strong>Cached Geo Data:</strong>';
                            html += '<pre style="background: #f8f8f8; padding: 10px; overflow: auto; max-height: 200px;">';
                            html += JSON.stringify(data, null, 2);
                            html += '</pre></div>';
                        }
                        
                        html += '<button type="button" class="button ffb-delete-ip" data-ip="' + ip + '">Delete This IP From Cache</button>';
                        html += '</div>';
                        resultDiv.html(html);
                        
                        // Add click handler for delete button
                        $('.ffb-delete-ip').on('click', function() {
                            var deleteIp = $(this).data('ip');
                            deleteIpFromCache(deleteIp);
                        });
                    } else {
                        resultDiv.html('<div class="notice notice-warning"><p>IP not found in cache</p></div>');
                    }
                } else {
                    resultDiv.html('<div class="notice notice-error"><p>Error: ' + response.data + '</p></div>');
                }
            },
            error: function() {
                resultDiv.html('<div class="notice notice-error"><p>Failed to search for IP. Please try again.</p></div>');
            },
            complete: function() {
                button.prop('disabled', false);
            }
        });
    });
    
    // Delete IP from cache
    function deleteIpFromCache(ip) {
        var resultDiv = $('#ffb-ip-search-result');
        
        if (!confirm('Are you sure you want to delete this IP from the cache?')) {
            return;
        }
        
        resultDiv.html('<p><em>Deleting IP from cache...</em></p>');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ffb_delete_ip',
                nonce: ffbAdminVars.nonce,
                ip: ip
            },
            success: function(response) {
                if (response.success) {
                    resultDiv.html('<div class="notice notice-success"><p>Successfully deleted ' + response.data.count + ' records for IP ' + ip + '</p></div>');
                } else {
                    resultDiv.html('<div class="notice notice-error"><p>Error: ' + response.data + '</p></div>');
                }
            },
            error: function() {
                resultDiv.html('<div class="notice notice-error"><p>Failed to delete IP. Please try again.</p></div>');
            }
        });
    }
    
    // Clear IP Cache
    $('#ffb-clear-cache').on('click', function() {
        var button = $(this);
        
        if (!confirm('Are you sure you want to clear all cached IP data? This cannot be undone.')) {
            return;
        }
        
        button.prop('disabled', true);
        button.text(ffbAdminVars.clearing_cache);
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ffb_clear_cache',
                nonce: ffbAdminVars.nonce
            },
            success: function(response) {
                if (response.success) {
                    alert('Successfully cleared ' + response.data.count + ' cached items');
                } else {
                    alert('Error: ' + response.data);
                }
            },
            error: function() {
                alert('Failed to clear cache. Please try again.');
            },
            complete: function() {
                button.prop('disabled', false);
                button.text('Clear All Cache');
            }
        });
    });
});
