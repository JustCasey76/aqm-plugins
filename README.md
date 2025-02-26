# Formidable Forms State & ZIP Code Blocker

A WordPress plugin that blocks form submissions from non-approved states and ZIP codes using Formidable Forms. This plugin only allows US-based IPs from approved states and applies to all Formidable Forms on your site.

## Features

- Blocks form submissions from non-US IP addresses
- Blocks form submissions from non-approved US states
- Blocks form submissions from non-approved ZIP codes
- Includes rate limiting to prevent form spam
- Hides forms completely for users from blocked locations
- Admin settings page to configure approved states and ZIP codes
- Client-side validation to improve user experience
- Admin IP testing feature to easily test blocking functionality
- Comprehensive access log to track blocked and allowed submissions

## Requirements

- WordPress 5.0 or higher
- Formidable Forms plugin (any version)
- PHP 7.0 or higher

## Installation

1. Upload the `aqm-formidable-spam-blocker` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure the approved states and ZIP codes in Settings > FFB Settings

## Configuration

After activating the plugin, go to Settings > FFB Settings to configure:

- Approved States: Enter comma-separated two-letter state codes (e.g., CA,NY,TX)
- Approved ZIP Codes: Enter comma-separated ZIP codes that are allowed to submit forms
- Block Non-US IPs: Option to block or allow submissions from outside the United States
- Rate Limiting: Configure how many submissions are allowed per IP address in a given time frame
- Log Access Attempts: Enable or disable logging of form submission attempts

## Testing

The plugin includes a convenient way to test the blocking functionality:

1. Go to Settings > FFB Settings
2. In the "Test Blocking with Your IP" section, you'll see your current IP address
3. Check the "Block my IP address for testing purposes" checkbox and click "Update IP Block Status"
4. Visit your site to see how forms appear to blocked users
5. Return to the settings page and uncheck the box when you're done testing

## Access Log

The plugin maintains a detailed log of all form submission attempts, including:

1. IP address of the user
2. Country and region information
3. ZIP code (if available)
4. Form ID
5. Status (allowed or blocked)
6. Reason for blocking

To view the access log:

1. Go to the WordPress admin menu and click on "FFB Access Log"
2. Use the filters to view specific types of submission attempts
3. Click on column headers to sort the data
4. Use pagination to navigate through the log entries

The access log helps you monitor form submission patterns and identify potential spam or abuse.

## Automatic Updates

This plugin supports automatic updates directly from GitHub. When a new version is released on the GitHub repository, WordPress will notify you of the available update just like any other plugin.

### How Updates Work

1. The plugin checks the GitHub repository for new releases
2. If a new version is found, WordPress will show an update notification
3. You can update the plugin directly from the WordPress dashboard

### For Developers

If you're forking this plugin or using it as a base for your own development:

1. The updater uses the GitHub API to check for new releases
2. Make sure to create proper releases on GitHub with semantic versioning (e.g., v1.6.1)
3. The plugin version in the main PHP file should match the GitHub release tag (without the 'v' prefix)
4. You can include a ZIP file as a release asset for faster downloads

### Repository Structure

The plugin is hosted at: https://github.com/JustCasey76/aqm-plugins

### Automatic Updates from GitHub

This plugin supports automatic updates directly from GitHub:

1. Updates will be detected automatically by WordPress
2. No additional configuration is required since the repository is public
3. When a new version is released, WordPress will notify you and allow one-click updates

### For Developers

If you're forking this plugin or using it as a base for your own development:

1. The updater uses the GitHub API to check for new releases
2. Make sure to create proper releases on GitHub with semantic versioning (e.g., v1.6.1)
3. The plugin version in the main PHP file should match the GitHub release tag (without the 'v' prefix)
4. You can include a ZIP file as a release asset for faster downloads

## Support

For support, please contact AQ Marketing.

## Version History

- 1.4.0: Initial release with state and ZIP code blocking functionality
- 1.5.0: Added admin IP testing feature for easy testing of blocking functionality
- 1.6.0: Added comprehensive access log to track form submission attempts

## API Key

This plugin uses the ipapi.com service to determine user location. The plugin comes with a default API key, but it's recommended to replace it with your own for better reliability and to avoid rate limiting issues.

To change the API key, go to Settings > FFB Settings and enter your API key in the "API Settings" section.
