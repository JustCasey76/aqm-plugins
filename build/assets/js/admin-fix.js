/**
 * Admin fix for ensuring ffbAdminVars is defined
 */
jQuery(document).ready(function($) {
    // Check if ffbAdminVars is defined
    if (typeof ffbAdminVars === 'undefined') {
        console.error('ffbAdminVars is not defined, creating fallback');
        window.ffbAdminVars = {
            nonce: '',
            ajax_url: ajaxurl || '',
            refreshing_usage: 'Refreshing...',
            searching: 'Searching...',
            clearing_cache: 'Clearing cache...'
        };
    }
});
