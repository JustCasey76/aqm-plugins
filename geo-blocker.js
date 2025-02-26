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
                if (response && response.country_code && response.country_code !== 'US') {
                    hideFormidableForms('Forms are not available in your country.');
                    return;
                }

                if (response && response.region_code && 
                    ffbGeoBlocker.approved_states.indexOf(response.region_code) === -1) {
                    hideFormidableForms('Forms are not available in your state.');
                    return;
                }
            },
            error: function() {
                console.log('Unable to determine location. Allowing form access by default.');
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
