/**
 * Formidable Forms Geo-Blocker JavaScript
 * Handles client-side geo-blocking for Formidable Forms
 */

(function($) {
    'use strict';

    // Check if user's location is allowed
    function checkUserLocation() {
        $.ajax({
            url: ffbGeoBlocker.api_url,
            method: 'GET',
            dataType: 'json',
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
                    
                    // Try different fields for region/state information
                    if (response.region_code) {
                        region_code = response.region_code.trim();
                    } else if (response.region_name) {
                        region_code = response.region_name.trim();
                    } else if (response.region) {
                        region_code = response.region.trim();
                    }
                    
                    if (region_code) {
                        var approved_states = ffbGeoBlocker.approved_states;
                        
                        console.log('Checking state:', region_code);
                        console.log('Approved states:', approved_states);
                        
                        // Check if the state is not in the approved list
                        var stateApproved = false;
                        for (var i = 0; i < approved_states.length; i++) {
                            console.log('Comparing:', region_code, 'with', approved_states[i].trim());
                            if (approved_states[i].trim() === region_code) {
                                stateApproved = true;
                                break;
                            }
                        }
                        
                        console.log('State approved:', stateApproved);
                        
                        if (!stateApproved) {
                            console.log('Blocking due to state not in approved list');
                            hideFormidableForms('Forms are not available in your state.');
                            return;
                        }
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
        checkUserLocation();
        addZipValidation();
    });

})(jQuery);
