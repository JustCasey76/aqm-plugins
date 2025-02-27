/**
 * Formidable Forms Geo-Blocker JavaScript
 * Handles client-side geo-blocking for Formidable Forms
 * Version: 1.9.0
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
        console.log('Checking user location...');
        
        // Clear any cached data to ensure fresh check
        localStorage.removeItem('ffb_geo_data');
        
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
                url: 'https://api.ipapi.com/api/' + userIp + '?access_key=' + ffbGeoBlocker.api_key + '&_nocache=' + new Date().getTime(),
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
                    if (response && ffbGeoBlocker.approved_states && ffbGeoBlocker.approved_states.length > 0) {
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
                        console.log('ffbGeoBlocker object:', ffbGeoBlocker);
                        
                        if (region_code) {
                            // Make sure approved_states is an array
                            var approved_states = Array.isArray(ffbGeoBlocker.approved_states) ? 
                                ffbGeoBlocker.approved_states : 
                                (typeof ffbGeoBlocker.approved_states === 'string' ? 
                                    ffbGeoBlocker.approved_states.split(',') : []);
                            
                            console.log('Checking state:', region_code);
                            console.log('Region name from API:', region_name);
                            console.log('Approved states (raw):', JSON.stringify(ffbGeoBlocker.approved_states));
                            console.log('Approved states (processed):', JSON.stringify(approved_states));
                            
                            // Debug: Show each approved state individually
                            for (var i = 0; i < approved_states.length; i++) {
                                console.log('Approved state ' + i + ':', approved_states[i]);
                            }
                            
                            // Debug: Show the complete response object
                            console.log('Complete API response:', JSON.stringify(response));
                            
                            // Check if the state is in the approved list (case insensitive)
                            var stateApproved = false;
                            
                            // Special check for Massachusetts
                            if (region_code.toUpperCase() === 'MA' || 
                                region_name.toUpperCase() === 'MASSACHUSETTS' || 
                                region_code.toUpperCase() === 'MASSACHUSETTS' ||
                                region_name.toUpperCase() === 'MASS' ||
                                region_code.toUpperCase() === 'MASS') {
                                console.log('MASSACHUSETTS DETECTED - checking if in approved list');
                                
                                // Check if MA is in the approved list (any variation)
                                for (var i = 0; i < approved_states.length; i++) {
                                    var state = approved_states[i].toUpperCase().trim();
                                    console.log('Checking MA against approved state:', state);
                                    if (state === 'MA' || state === 'MASSACHUSETTS' || state === 'MASS') {
                                        console.log('Massachusetts is in the approved list - allowing access');
                                        stateApproved = true;
                                        break;
                                    }
                                }
                                
                                // If MA is approved, exit the function completely
                                if (stateApproved) {
                                    console.log('MA is approved, showing forms and exiting function');
                                    return; // This exits the success callback
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
                            } else {
                                console.log('State is in approved list - showing forms and exiting function');
                                // State is approved, so we'll show the forms and exit the function
                                return;
                            }
                        } else {
                            console.log('WARNING: Could not determine region code from API response');
                        }
                    }
                    
                    // Check if ZIP code is in the approved list
                    if (response && ffbGeoBlocker.zip_validation_enabled && 
                        ffbGeoBlocker.approved_zip_codes && 
                        Array.isArray(ffbGeoBlocker.approved_zip_codes) && 
                        ffbGeoBlocker.approved_zip_codes.length > 0) {
                        
                        console.log('ZIP validation is enabled and we have approved ZIP codes');
                        
                        // Get ZIP code from the appropriate field
                        var postal_raw = response.zip || response.postal || '';
                        
                        if (postal_raw) {
                            // Clean the ZIP code (remove spaces, dashes, etc.)
                            var postal_code = postal_raw.replace(/[^0-9]/g, '');
                            
                            // Get just the first 5 digits for US ZIP codes
                            if (postal_code.length > 5) {
                                postal_code = postal_code.substring(0, 5);
                            }
                            
                            // Make sure approved_zip_codes is an array
                            var approved_zip_codes = Array.isArray(ffbGeoBlocker.approved_zip_codes) ? 
                                ffbGeoBlocker.approved_zip_codes : 
                                (typeof ffbGeoBlocker.approved_zip_codes === 'string' ? 
                                    ffbGeoBlocker.approved_zip_codes.split(',') : []);
                            
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
                        } else {
                            console.log('No ZIP code found in API response, skipping ZIP validation');
                        }
                    } else {
                        console.log('ZIP validation is disabled or no approved ZIP codes');
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
        
        // Add debug button for troubleshooting (only visible in admin mode)
        if (ffbGeoBlocker.is_admin) {
            $('body').append('<div id="ffb-debug-button" style="position: fixed; bottom: 10px; right: 10px; z-index: 9999; background: #f1f1f1; padding: 5px; border-radius: 5px; cursor: pointer;">FFB Debug</div>');
            $('#ffb-debug-button').on('click', function() {
                debugGeoLocation();
            });
        }
        
        // Improved form detection - check for various Formidable Forms elements
        if ($('.frm_forms').length > 0 || 
            $('.frm_form_fields').length > 0 || 
            $('form.frm-show-form').length > 0 || 
            $('[class*="frm"]').length > 0) {
            
            console.log('Formidable Forms detected on page - checking location');
            // Check user location
            checkUserLocation();
            
            // Add ZIP validation if enabled
            if (ffbGeoBlocker.zip_validation_enabled) {
                addZipValidation();
            }
        } else {
            console.log('No Formidable Forms detected on page - skipping location check');
        }
    });
    
    // Debug function to help troubleshoot geolocation issues
    function debugGeoLocation() {
        console.log('FFB Debug: Running geolocation check...');
        
        // Display debug information in a modal
        var debugModal = $('<div id="ffb-debug-modal" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 80%; max-width: 600px; max-height: 80vh; overflow-y: auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.5); z-index: 10000;"><h3>FFB Geolocation Debug</h3><div id="ffb-debug-content"><p>Loading geolocation data...</p></div><div><button id="ffb-debug-force" style="margin-top: 15px; margin-right: 10px; padding: 5px 10px;">Force Check</button><button id="ffb-debug-close" style="margin-top: 15px; padding: 5px 10px;">Close</button></div></div>');
        $('body').append(debugModal);
        
        $('#ffb-debug-close').on('click', function() {
            $('#ffb-debug-modal').remove();
        });
        
        $('#ffb-debug-force').on('click', function() {
            console.log('Forcing location check...');
            checkUserLocation();
            $('#ffb-debug-modal').remove();
        });
        
        // Get the user's IP
        $.getJSON('https://api.ipify.org?format=json', function(data) {
            var ip = data.ip;
            var debugContent = $('#ffb-debug-content');
            debugContent.html('<p><strong>Your IP:</strong> ' + ip + '</p><p>Fetching location data...</p>');
            
            // Get location data
            $.ajax({
                url: 'https://ipapi.co/' + ip + '/json/',
                success: function(response) {
                    var region_code = response.region_code || '';
                    var region_name = response.region || response.region_name || '';
                    
                    var stateApproved = false;
                    var approvedStatesStr = ffbGeoBlocker.approved_states.join(', ');
                    
                    // Check for Massachusetts
                    var isMassachusetts = (region_code.toUpperCase() === 'MA' || 
                                         region_name.toUpperCase() === 'MASSACHUSETTS' || 
                                         region_code.toUpperCase() === 'MASSACHUSETTS' ||
                                         region_name.toUpperCase() === 'MASS' ||
                                         region_code.toUpperCase() === 'MASS');
                    
                    // Check if state is approved
                    if (isMassachusetts) {
                        for (var i = 0; i < ffbGeoBlocker.approved_states.length; i++) {
                            var state = ffbGeoBlocker.approved_states[i].toUpperCase().trim();
                            if (state === 'MA' || state === 'MASSACHUSETTS' || state === 'MASS') {
                                stateApproved = true;
                                break;
                            }
                        }
                    } else {
                        for (var i = 0; i < ffbGeoBlocker.approved_states.length; i++) {
                            var approvedState = ffbGeoBlocker.approved_states[i].trim();
                            
                            if (approvedState.toUpperCase() === region_code.toUpperCase() || 
                                (region_name && region_name.toUpperCase() === approvedState.toUpperCase())) {
                                stateApproved = true;
                                break;
                            }
                        }
                    }
                    
                    var html = '<h4>Your Location:</h4>' +
                              '<p><strong>IP:</strong> ' + ip + '</p>' +
                              '<p><strong>Country:</strong> ' + response.country_name + ' (' + response.country_code + ')</p>' +
                              '<p><strong>Region Name:</strong> ' + region_name + '</p>' +
                              '<p><strong>Region Code:</strong> ' + region_code + '</p>' +
                              '<p><strong>City:</strong> ' + response.city + '</p>' +
                              '<p><strong>ZIP:</strong> ' + response.postal + '</p>' +
                              '<h4>State Validation Check:</h4>' +
                              '<p><strong>Your State Code:</strong> ' + region_code + '</p>' +
                              '<p><strong>Approved States:</strong> ' + approvedStatesStr + '</p>';
                    
                    if (isMassachusetts) {
                        html += '<p><strong>Special Massachusetts Check:</strong> ' + (stateApproved ? 'MA is in the approved list' : 'MA is NOT in the approved list') + '</p>';
                    }
                    
                    html += '<p><strong>Is Approved:</strong> ' + (stateApproved ? 'YES' : 'NO') + '</p>' +
                           '<h4>Raw API Response:</h4>' +
                           '<pre>' + JSON.stringify(response, null, 2) + '</pre>';
                    
                    debugContent.html(html);
                },
                error: function(xhr, status, error) {
                    debugContent.html('<p>Error fetching location data: ' + error + '</p>');
                }
            });
        }).fail(function() {
            $('#ffb-debug-content').html('<p>Error fetching IP address</p>');
        });
    }
})(jQuery);
