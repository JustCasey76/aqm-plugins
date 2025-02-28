jQuery(document).ready(function($) {
    // Remove the Formidable footer if it exists
    $(".frm-admin-footer-links").remove();
    
    // Add our own footer
    $(".wrap").append('<div class="ffb-admin-footer" style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center;"><p>AQM Formidable Forms Spam Blocker v1.9.8 | Developed by <a href="https://aqmarketing.com" target="_blank">AQMarketing</a></p></div>');
});
