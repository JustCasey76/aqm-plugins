/**
 * Formidable Forms Geo-Blocker JavaScript
 * Handles client-side geo-blocking for Formidable Forms
 * Version: 1.9.3
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

    // Function to check if forms should be hidden
    function checkFormVisibility() {
        $.ajax({
            url: ffb_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ffb_check_location',
                nonce: ffb_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    if (!response.data.is_allowed) {
                        hideFormidableForms(response.data.message || 'Your location is not allowed to access these forms.');
                    } else {
                        showFormidableForms();
                    }
                }
            }
        });
    }

    // Function to hide Formidable Forms
    function hideFormidableForms(message) {
        $('.frm_forms').each(function() {
            var $form = $(this);
            if (!$form.prev('.frm-blocked-message').length) {
                $form.before('<div class="frm-blocked-message">' + message + '</div>');
            }
            $form.hide();
        });
    }

    // Function to show Formidable Forms
    function showFormidableForms() {
        $('.frm-blocked-message').remove();
        $('.frm_forms').show();
    }

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
            var api_url = 'https://api.ipapi.com/api/' + userIp + '?access_key=' + ffbGeoBlocker.api_key + '&_nocache=' + new Date().getTime();
            $.ajax({
                url: api_url,
                type: 'GET',
                dataType: 'json',
                success: function(response) {
                    console.log('API Response:', response);
                    
                    // First, detect the location
                    var locationInfo = detectUserLocation(response);
                    console.log('Location detection results:', locationInfo);
                    
                    // Then, apply access rules based on the detected location
                    applyAccessRules(locationInfo);
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
    
    // Detect the user's location from API response
    function detectUserLocation(response) {
        console.log('API Response:', response);
        
        // Initialize location info object
        var locationInfo = {
            isUS: response.country_code === 'US',
            state: {
                code: response.region_code || '',
                name: response.region || '',
                isApproved: false
            },
            zipCode: {
                code: '',
                isApproved: false
            },
            country: response.country_code
        };
        
        // Check if the response is valid
        if (!response || response.error) {
            console.error('Invalid API response:', response);
            return locationInfo;
        }
        
        // Process state information
        if (response.region_code) {
            locationInfo.state.code = response.region_code.toUpperCase();
            locationInfo.state.isApproved = ffbGeoBlocker.approved_states.includes(locationInfo.state.code);
        }
        
        // Process ZIP code if present
        if (response.postal) {
            locationInfo.zipCode.code = response.postal;
            
            // Check if the ZIP code is in the approved list
            if (ffbGeoBlocker.approved_zip_codes) {
                locationInfo.zipCode.isApproved = ffbGeoBlocker.approved_zip_codes.some(function(zipPattern) {
                    // Convert glob pattern to regex
                    var regexPattern = zipPattern
                        .replace(/\*/g, '.*')  // * becomes .*
                        .replace(/\?/g, '.')   // ? becomes .
                        .replace(/\[!/g, '[^'); // [! becomes [^
                    
                    var regex = new RegExp('^' + regexPattern + '$');
                    return regex.test(locationInfo.zipCode.code);
                });
            }
        }
        
        console.log('Processed location info:', locationInfo);
        return locationInfo;
    }
    
    // Apply access rules based on detected location
    function applyAccessRules(locationInfo) {
        console.log('Applying access rules based on location:', locationInfo);
        
        // Skip all blocking rules if testing with own IP
        if (ffbGeoBlocker.is_admin && localStorage.getItem('ffb_testing_own_ip') === 'true') {
            console.log('Test mode active - skipping blocking rules');
            showFormidableForms();
            return;
        }
        
        // Check if country is approved
        if (locationInfo.country && ffbGeoBlocker.approved_countries) {
            var countryApproved = false;
            for (var i = 0; i < ffbGeoBlocker.approved_countries.length; i++) {
                if (locationInfo.country === ffbGeoBlocker.approved_countries[i]) {
                    countryApproved = true;
                    break;
                }
            }
            
            if (!countryApproved) {
                console.log('Blocking due to non-approved country: ' + locationInfo.country);
                hideFormidableForms('Forms are not available in your country.');
                return;
            }
        }
        
        // Check state approval if we have approved states configured
        if (ffbGeoBlocker.approved_states && ffbGeoBlocker.approved_states.length > 0) {
            var stateCode = locationInfo.state.code;
            if (!stateCode || !ffbGeoBlocker.approved_states.includes(stateCode.toUpperCase())) {
                console.log('State is not approved:', stateCode);
                hideFormidableForms('Forms are not available in your state.');
                return;
            }
        }
        
        // Check ZIP code approval if enabled
        if (ffbGeoBlocker.zip_validation_enabled && !locationInfo.zipCode.isApproved) {
            console.log('ZIP code is not approved, blocking access');
            hideFormidableForms('Forms are not available in your ZIP code.');
            return;
        }
        
        // If we get here, access is allowed
        console.log('All checks passed, allowing access');
        showFormidableForms();
    }

    // Initialize on document ready
    $(document).ready(function() {
        // Check form visibility when page loads
        checkFormVisibility();

        // Also check when new forms are dynamically added
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                    for (var i = 0; i < mutation.addedNodes.length; i++) {
                        var node = mutation.addedNodes[i];
                        if ($(node).find('.frm_forms').length > 0) {
                            checkFormVisibility();
                            break;
                        }
                    }
                }
            });
        });

        // Start observing the document with the configured parameters
        observer.observe(document.body, { childList: true, subtree: true });
        
        // Clear any cached data in localStorage
        localStorage.removeItem('ffb_geo_data');
        
        // Add a timestamp to avoid browser caching
        console.log('Initializing geo-blocker.js at ' + new Date().toISOString());
        console.log('ffbGeoBlocker object:', ffbGeoBlocker);
        
        // Check if we're in test mode with admin's IP
        if (ffbGeoBlocker.is_admin && ffbGeoBlocker.testing_own_ip) {
            console.log('Admin is testing with their own IP - enabling test mode');
            localStorage.setItem('ffb_testing_own_ip', 'true');
        } else {
            localStorage.removeItem('ffb_testing_own_ip');
        }
        
        // Add debug button for troubleshooting (only visible in admin mode)
        if (ffbGeoBlocker.is_admin) {
            $('body').append('<div id="ffb-debug-button" style="position: fixed; bottom: 10px; right: 10px; z-index: 9999; background: #f1f1f1; padding: 5px; border-radius: 5px; cursor: pointer;">FFB Debug</div>');
            $('#ffb-debug-button').on('click', function() {
                debugGeoLocation();
            });
        }
        
        // Make sure forms are visible by default
        $('.frm_forms').show();
        
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
        
        // Handle forms that might be added to the page dynamically
        // For example, via AJAX or after page load
        var formCheckInterval = setInterval(function() {
            if ($('.frm_forms').length > 0 && 
                !$('.frm_forms').data('ffb-processed')) {
                
                console.log('New Formidable Forms detected - processing');
                $('.frm_forms').data('ffb-processed', true);
                
                // Make sure new forms are visible by default
                $('.frm_forms').show();
                
                // Re-check location for the new forms
                checkUserLocation();
            }
        }, 1000); // Check every second
        
        // Stop checking after 30 seconds to avoid performance issues
        setTimeout(function() {
            clearInterval(formCheckInterval);
        }, 30000);
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
                                         region_code.toUpperCase() === 'MASS' ||
                                         (response.region_name && response.region_name.toUpperCase() === 'MASSACHUSETTS') ||
                                         (response.region && response.region.toUpperCase() === 'MASSACHUSETTS'));
                    
                    // Check if state is approved
                    if (isMassachusetts) {
                        for (var i = 0; i < ffbGeoBlocker.approved_states.length; i++) {
                            var state = ffbGeoBlocker.approved_states[i].toUpperCase().trim();
                            console.log('Checking MA against approved state:', state);
                            if (state === 'MA' || state === 'MASSACHUSETTS' || state === 'MASS') {
                                console.log('Massachusetts is in the approved list');
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
                                console.log('MATCH FOUND! State is approved');
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
