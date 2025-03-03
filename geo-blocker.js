/**
 * AQM Formidable Forms Spam Blocker - Geolocation Script
 * Version: 2.1.64
 * 
 * This script handles the geolocation check for Formidable Forms
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

    // Initialize the geo-blocker
    var ffbGeoBlockerInit = function() {
        console.log('Initializing geo-blocker.js at ' + new Date().toISOString());
        console.log('ffbGeoBlocker object:', ffbGeoBlocker);

        // Check if Formidable Forms is present on the page
        if ($('.frm_forms').length > 0) {
            console.log('Formidable Forms detected on page - checking location');
            
            // Get the latest approved states list before checking location
            getLatestApprovedStates(function(approvedStates) {
                // Update the global approved states list
                ffbGeoBlocker.approved_states = approvedStates;
                console.log('Updated approved states list:', ffbGeoBlocker.approved_states);
                
                // Now check location with the updated states list
                checkLocation();
            });
        }

        // Watch for new Formidable Forms being added to the page
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                    for (var i = 0; i < mutation.addedNodes.length; i++) {
                        var node = mutation.addedNodes[i];
                        if (node.nodeType === 1 && $(node).find('.frm_forms').length > 0) {
                            console.log('New Formidable Forms detected - processing');
                            
                            // Get the latest approved states list before checking location
                            getLatestApprovedStates(function(approvedStates) {
                                // Update the global approved states list
                                ffbGeoBlocker.approved_states = approvedStates;
                                console.log('Updated approved states list:', ffbGeoBlocker.approved_states);
                                
                                // Now check location with the updated states list
                                checkLocation();
                            });
                        }
                    }
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    };

    /**
     * Get the latest approved states list from the server
     */
    var getLatestApprovedStates = function(callback) {
        $.ajax({
            url: ffb_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'ffb_get_approved_states',
                nonce: ffb_ajax.nonce
            },
            success: function(response) {
                if (response.success && response.data && response.data.approved_states) {
                    console.log('Successfully retrieved latest approved states:', response.data.approved_states);
                    callback(response.data.approved_states);
                } else {
                    console.error('Failed to get latest approved states:', response);
                    // Fall back to the states provided during page load
                    callback(ffbGeoBlocker.approved_states);
                }
            },
            error: function(xhr, status, error) {
                console.error('AJAX error when getting approved states:', error);
                // Fall back to the states provided during page load
                callback(ffbGeoBlocker.approved_states);
            }
        });
    };

    /**
     * Check the user's location and apply access rules
     */
    var checkLocation = function() {
        console.log('Checking user location...');
        
        // Get the user's IP address
        var userIP = getUserIP();
        console.log('User IP:', userIP);
        
        // Check if this IP is being tested
        if (ffbGeoBlocker.testing_own_ip) {
            blockForms('This IP is being tested for blocking.');
            return;
        }
        
        // Make API request to get location data
        $.ajax({
            url: ffbGeoBlocker.api_url + userIP + '?access_key=' + ffbGeoBlocker.api_key,
            type: 'GET',
            dataType: 'json',
            success: function(response) {
                console.log('API Response:', response);
                
                // Process the location information
                var locationInfo = processLocationInfo(response);
                console.log('Location detection results:', locationInfo);
                
                // Apply access rules based on location
                applyAccessRules(locationInfo);
            },
            error: function(xhr, status, error) {
                console.error('Error getting location:', error);
                // In case of error, allow access by default
                allowForms();
            }
        });
    };
    
    /**
     * Process the location information from the API response
     */
    var processLocationInfo = function(response) {
        console.log('API Response:', response);
        
        var locationInfo = {
            isUS: false,
            state: {},
            zipCode: {},
            country: ''
        };
        
        // Check if response contains an error
        if (!response || !response.success === false || response.error) {
            console.error('API returned an error or invalid response');
            return locationInfo;
        }
        
        // Check if response contains country code
        if (response.country_code) {
            locationInfo.country = response.country_code.toUpperCase();
            
            // Check if US
            if (locationInfo.country === 'US') {
                locationInfo.isUS = true;
                
                // Process state information
                if (response.region_code) {
                    locationInfo.state.code = response.region_code.toUpperCase();
                    locationInfo.state.name = response.region_name || '';
                }
                
                // Process ZIP code information
                if (response.zip) {
                    locationInfo.zipCode.code = response.zip;
                }
            }
        }
        
        console.log('Processed location info:', locationInfo);
        return locationInfo;
    };
    
    /**
     * Apply access rules based on location
     */
    var applyAccessRules = function(locationInfo) {
        console.log('Applying access rules based on location:', locationInfo);
        
        // If location data is incomplete (API error or no data), allow access
        if (!locationInfo || !locationInfo.country) {
            console.log('Location data is incomplete or API error occurred - allowing access by default');
            allowForms();
            return;
        }
        
        // Check country first
        if (ffbGeoBlocker.approved_countries.length > 0) {
            var countryAllowed = false;
            for (var i = 0; i < ffbGeoBlocker.approved_countries.length; i++) {
                if (locationInfo.country === ffbGeoBlocker.approved_countries[i].toUpperCase()) {
                    countryAllowed = true;
                    break;
                }
            }
            
            if (!countryAllowed) {
                blockForms('Country not allowed: ' + locationInfo.country);
                return;
            }
        }
        
        // If US, check state
        if (locationInfo.isUS && ffbGeoBlocker.approved_states.length > 0) {
            var stateAllowed = false;
            for (var i = 0; i < ffbGeoBlocker.approved_states.length; i++) {
                if (locationInfo.state.code === ffbGeoBlocker.approved_states[i].toUpperCase()) {
                    stateAllowed = true;
                    console.log('State ' + locationInfo.state.code + ' is in the approved list');
                    break;
                }
            }
            
            if (!stateAllowed) {
                console.log('State ' + locationInfo.state.code + ' is NOT in the approved list: ' + ffbGeoBlocker.approved_states.join(','));
                blockForms('State not allowed: ' + locationInfo.state.code);
                return;
            }
            
            // Check ZIP code if enabled
            if (ffbGeoBlocker.zip_validation_enabled && 
                locationInfo.zipCode.code && 
                ffbGeoBlocker.approved_zip_codes.length > 0) {
                
                var zipAllowed = false;
                for (var i = 0; i < ffbGeoBlocker.approved_zip_codes.length; i++) {
                    if (locationInfo.zipCode.code.startsWith(ffbGeoBlocker.approved_zip_codes[i])) {
                        zipAllowed = true;
                        break;
                    }
                }
                
                if (!zipAllowed) {
                    blockForms('ZIP code not allowed: ' + locationInfo.zipCode.code);
                    return;
                }
            }
        }
        
        // If we made it here, all checks passed
        console.log('All checks passed, allowing access');
        allowForms();
    };
    
    /**
     * Get the user's IP address - ALWAYS use client IP in production
     * Version: 2.1.64
     */
    var getUserIP = function() {
        // Return empty string for ipapi.com to use the client's IP
        return '';
    };
    
    /**
     * Block forms by adding the blocked message
     */
    var blockForms = function(reason) {
        $('.frm_forms').each(function() {
            var $form = $(this);
            
            // Don't block if already blocked
            if ($form.hasClass('ffb-blocked')) {
                return;
            }
            
            // Add blocked class
            $form.addClass('ffb-blocked');
            
            // Hide the form - use direct DOM manipulation for more reliable hiding
            var formElements = $form.find('form');
            formElements.hide();
            formElements.css('display', 'none !important');
            formElements.attr('style', 'display: none !important');
            
            // Get the blocked message, use a default if not set
            var blockedMessage = ffbGeoBlocker.blocked_message || '<div class="frm_error_style" style="text-align:center;"><p>We apologize, but we are currently not accepting submissions from your location.</p></div>';
            
            // Add blocked message and make it more resistant to removal
            var $blockedMsg = $('<div class="ffb-blocked-message">' + blockedMessage + '</div>');
            $form.prepend($blockedMsg);
            
            // Create a MutationObserver to ensure the blocked message remains and form stays hidden
            if (window.MutationObserver) {
                var observer = new MutationObserver(function(mutations) {
                    var needToRestoreMessage = false;
                    var needToRehideForm = false;
                    
                    mutations.forEach(function(mutation) {
                        // Check for blocked message removal
                        if (mutation.type === 'childList' && mutation.removedNodes.length > 0) {
                            for (var i = 0; i < mutation.removedNodes.length; i++) {
                                if (mutation.removedNodes[i].classList && 
                                    mutation.removedNodes[i].classList.contains('ffb-blocked-message')) {
                                    console.log('Blocked message was removed, will restore it');
                                    needToRestoreMessage = true;
                                }
                            }
                        }
                        
                        // Check for form display changes
                        if (mutation.type === 'attributes' && 
                            mutation.attributeName === 'style' && 
                            mutation.target.tagName === 'FORM') {
                            var displayStyle = window.getComputedStyle(mutation.target).display;
                            if (displayStyle !== 'none') {
                                console.log('Form display was changed, will re-hide it');
                                needToRehideForm = true;
                            }
                        }
                    });
                    
                    // Restore the message if needed
                    if (needToRestoreMessage && $form.find('.ffb-blocked-message').length === 0) {
                        console.log('Restoring removed blocked message');
                        $form.prepend($blockedMsg.clone());
                    }
                    
                    // Re-hide the form if needed
                    if (needToRehideForm) {
                        console.log('Re-hiding the form');
                        formElements.each(function() {
                            this.style.setProperty('display', 'none', 'important');
                        });
                    }
                });
                
                // Start observing the form for changes - observe at a higher level and include attributes
                observer.observe($form[0], {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['style', 'class']
                });
                
                // Also observe the body for potential form replacement
                var bodyObserver = new MutationObserver(function(mutations) {
                    if (!$form.hasClass('ffb-blocked')) {
                        return; // Skip if not blocked anymore
                    }
                    
                    // Check if our form is still in the DOM
                    if (!document.contains($form[0])) {
                        console.log('Form was removed from DOM, reapplying to new forms');
                        $('.frm_forms').not('.ffb-blocked').each(function() {
                            blockForms(reason);
                        });
                    }
                    
                    // Make sure the form is still hidden
                    var formVisible = false;
                    $form.find('form').each(function() {
                        if (window.getComputedStyle(this).display !== 'none') {
                            formVisible = true;
                        }
                    });
                    
                    if (formVisible) {
                        console.log('Form became visible, re-hiding it');
                        formElements.each(function() {
                            this.style.setProperty('display', 'none', 'important');
                        });
                    }
                });
                
                bodyObserver.observe(document.body, {
                    childList: true,
                    subtree: true
                });
            }
            
            // Log the blocking reason
            console.log('Form blocked: ' + reason);
        });
    };
    
    /**
     * Allow forms by removing any blocked message
     */
    var allowForms = function() {
        $('.frm_forms').each(function() {
            var $form = $(this);
            
            // Remove blocked class
            $form.removeClass('ffb-blocked');
            
            // Show the form
            $form.find('form').show();
            
            // Remove blocked message
            $form.find('.ffb-blocked-message').remove();
        });
    };
    
    // Initialize when the document is ready
    $(document).ready(ffbGeoBlockerInit);
    
})(jQuery);
