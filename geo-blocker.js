/**
 * Formidable Forms Geo-Blocker JavaScript
 * Handles client-side geo-blocking for Formidable Forms
 * Version: 1.7.0
 */

(function($) {
    'use strict';

    // State name to abbreviation mapping
    var stateMap = {
        'alabama': 'AL',
        'alaska': 'AK',
        'arizona': 'AZ',
        'arkansas': 'AR',
        'california': 'CA',
        'colorado': 'CO',
        'connecticut': 'CT',
        'delaware': 'DE',
        'florida': 'FL',
        'georgia': 'GA',
        'hawaii': 'HI',
        'idaho': 'ID',
        'illinois': 'IL',
        'indiana': 'IN',
        'iowa': 'IA',
        'kansas': 'KS',
        'kentucky': 'KY',
        'louisiana': 'LA',
        'maine': 'ME',
        'maryland': 'MD',
        'massachusetts': 'MA',
        'michigan': 'MI',
        'minnesota': 'MN',
        'mississippi': 'MS',
        'missouri': 'MO',
        'montana': 'MT',
        'nebraska': 'NE',
        'nevada': 'NV',
        'new hampshire': 'NH',
        'new jersey': 'NJ',
        'new mexico': 'NM',
        'new york': 'NY',
        'north carolina': 'NC',
        'north dakota': 'ND',
        'ohio': 'OH',
        'oklahoma': 'OK',
        'oregon': 'OR',
        'pennsylvania': 'PA',
        'rhode island': 'RI',
        'south carolina': 'SC',
        'south dakota': 'SD',
        'tennessee': 'TN',
        'texas': 'TX',
        'utah': 'UT',
        'vermont': 'VT',
        'virginia': 'VA',
        'washington': 'WA',
        'west virginia': 'WV',
        'wisconsin': 'WI',
        'wyoming': 'WY'
    };

    // Check if user's location is allowed
    function checkUserLocation() {
        // Get the user's IP address first
        $.getJSON('https://api.ipify.org?format=json', function(ipData) {
            if (!ipData || !ipData.ip) {
                console.log('Could not determine IP address');
                return;
            }
            
            var userIp = ipData.ip;
            console.log('User IP:', userIp);
            
            // Now call the geolocation API with the correct URL format
            $.ajax({
                url: ffbGeoBlocker.api_url + userIp + '?access_key=' + ffbGeoBlocker.api_key + '&_nocache=' + new Date().getTime(),
                method: 'GET',
                dataType: 'json',
                cache: false,
                success: function(response) {
                    console.log('IPAPI Response:', response);
                    
                    // Check for API errors
                    if (response && response.success === false) {
                        console.log('IPAPI Error:', response.error ? response.error.info : 'Unknown error');
                        return; // Allow form access if we can't determine location
                    }
                    
                    // Check if we should block non-US IPs
                    if (ffbGeoBlocker.block_non_us && response && response.country_code && response.country_code !== 'US') {
                        console.log('Blocking due to non-US country:', response.country_code);
                        hideFormidableForms('Forms are not available in your country.');
                        return;
                    }
                    
                    // Check if state is in the approved list
                    if (response && ffbGeoBlocker.approved_states.length > 0) {
                        // Get the region code from the appropriate field
                        var region_code = '';
                        var region_name = '';
                        
                        // Try different fields for region/state information
                        if (response.region_code) {
                            region_code = response.region_code.trim();
                        } else if (response.region_name) {
                            region_name = response.region_name.trim();
                            // Try to convert full state name to code
                            region_code = stateMap[region_name.toLowerCase()] || region_name;
                        } else if (response.region) {
                            region_name = response.region.trim();
                            // Try to convert full state name to code
                            region_code = stateMap[region_name.toLowerCase()] || region_name;
                        }
                        
                        // Debug: Show the complete response object
                        console.log('Complete API response:', JSON.stringify(response));
                        
                        if (region_code) {
                            var approved_states = ffbGeoBlocker.approved_states;
                            
                            console.log('Checking state:', region_code);
                            console.log('Region name from API:', region_name);
                            console.log('Approved states (raw):', ffbGeoBlocker.approved_states);
                            console.log('Approved states (processed):', approved_states);
                            
                            // Debug: Show each approved state individually
                            for (var i = 0; i < approved_states.length; i++) {
                                console.log('Approved state ' + i + ':', approved_states[i]);
                            }
                            
                            // Check if the state is in the approved list (case insensitive)
                            var stateApproved = false;
                            
                            // Special check for Massachusetts
                            if (region_code.toUpperCase() === 'MA' || 
                                region_name.toUpperCase() === 'MASSACHUSETTS' || 
                                region_code.toUpperCase() === 'MASSACHUSETTS') {
                                console.log('MASSACHUSETTS DETECTED - checking if in approved list');
                                
                                // Check if MA is in the approved list
                                for (var i = 0; i < approved_states.length; i++) {
                                    if (approved_states[i].toUpperCase() === 'MA') {
                                        console.log('MA is in the approved list - allowing access');
                                        stateApproved = true;
                                        break;
                                    }
                                }
                            }
                            
                            // Regular check for other states
                            if (!stateApproved) {
                                for (var i = 0; i < approved_states.length; i++) {
                                    var approvedState = approved_states[i].trim();
                                    console.log('Comparing:', region_code.toUpperCase(), 'with', approvedState.toUpperCase());
                                    
                                    // Check for both the code and full name
                                    if (approvedState.toUpperCase() === region_code.toUpperCase() || 
                                        (region_name && region_name.toUpperCase() === approvedState.toUpperCase()) ||
                                        (stateMap[approvedState.toLowerCase()] === region_code.toUpperCase())) {
                                        stateApproved = true;
                                        console.log('MATCH FOUND! State is approved');
                                        break;
                                    }
                                }
                            }
                            
                            console.log('State approved:', stateApproved);
                            
                            if (!stateApproved) {
                                console.log('Blocking due to state not in approved list');
                                hideFormidableForms('Forms are not available in your state.');
                                return;
                            }
                        } else {
                            console.log('WARNING: Could not determine region code from API response');
                        }
                    }
                    
                    // Check if ZIP code is in the approved list
                    if (response && ffbGeoBlocker.approved_zip_codes.length > 0) {
                        // Get ZIP code from the appropriate field
                        var postal_raw = response.zip || response.postal || '';
                        
                        if (postal_raw) {
                            // Clean the ZIP code (remove spaces, dashes, etc.)
                            var postal_code = postal_raw.replace(/[^0-9]/g, '');
                            
                            // Get just the first 5 digits for US ZIP codes
                            if (postal_code.length > 5) {
                                postal_code = postal_code.substring(0, 5);
                            }
                            
                            var approved_zip_codes = ffbGeoBlocker.approved_zip_codes;
                            
                            console.log('Checking ZIP code:', postal_code);
                            console.log('Approved ZIP codes:', approved_zip_codes);
                            
                            // Check if the ZIP code is not in the approved list
                            var zipApproved = false;
                            for (var i = 0; i < approved_zip_codes.length; i++) {
                                console.log('Comparing ZIP:', postal_code, 'with', approved_zip_codes[i].trim());
                                if (approved_zip_codes[i].trim() === postal_code) {
                                    zipApproved = true;
                                    break;
                                }
                            }
                            
                            console.log('ZIP approved:', zipApproved);
                            
                            if (!zipApproved) {
                                console.log('Blocking due to ZIP code not in approved list');
                                hideFormidableForms('Forms are not available in your ZIP code.');
                                return;
                            }
                        }
                    }
                },
                error: function(xhr, status, error) {
                    console.log('Unable to determine location. Error:', error);
                    console.log('Response:', xhr.responseText);
                    // Allow form access by default if we can't determine location
                }
            });
        }).fail(function() {
            console.log('Could not determine IP address');
        });
    }

    // Hide all Formidable Forms and display a message
    function hideFormidableForms(message) {
        $('.frm_forms').each(function() {
            $(this).html('<p class="ffb-blocked-message">' + message + '</p>');
        });
    }

    // Add ZIP code validation to Formidable Forms
    function addZipValidation() {
        $(document).on('frmFormComplete', function(event, form, response) {
            // This will run after a form is submitted
            if (response && response.errors) {
                // Handle any custom errors returned by our server-side validation
                if (response.errors.zip) {
                    alert(response.errors.zip);
                }
            }
        });
    }

    // Initialize on document ready
    $(document).ready(function() {
        // Clear any cached data in localStorage
        localStorage.removeItem('ffb_geo_data');
        
        // Add a timestamp to avoid browser caching
        console.log('Initializing geo-blocker.js at ' + new Date().toISOString());
        
        checkUserLocation();
        addZipValidation();
    });

})(jQuery);
