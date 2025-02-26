# Upgrade Guide to Version 1.6.0

This guide provides information on upgrading to version 1.6.0 of the Formidable Forms State & ZIP Code Blocker plugin.

## What's New in 1.6.0

Version 1.6.0 introduces a comprehensive access logging system that tracks all form submission attempts, including:

- IP address
- Country and region information
- ZIP code (if available)
- Form ID
- Status (allowed or blocked)
- Reason for blocking

## Upgrade Process

1. **Backup Your Site**: Always create a backup of your WordPress site before upgrading plugins.

2. **Update the Plugin**: Update the plugin through the WordPress admin dashboard or by manually uploading the new files.

3. **Database Changes**: The upgrade will automatically create a new database table (`wp_ffb_access_log`) to store the access log data.

4. **Configure Logging Settings**: After upgrading, visit Settings > FFB Settings to configure the logging options:
   - Enable/disable logging
   - Set log retention period (if applicable)

## Post-Upgrade Tasks

After upgrading to version 1.6.0, we recommend:

1. **Review the Access Log**: Go to "FFB Access Log" in the WordPress admin menu to view the access log and familiarize yourself with the new interface.

2. **Update Privacy Policy**: If you have a privacy policy, consider updating it to mention that you collect IP addresses and geolocation data for form submission tracking.

3. **Test Form Submissions**: Test a few form submissions to ensure the logging system is working correctly.

## Potential Issues

### Database Table Creation Failed

If the access log table wasn't created automatically:

1. Deactivate and reactivate the plugin
2. If the issue persists, contact support

### High Database Usage

If you have a high-traffic site, the access log may grow quickly. Consider:

1. Disabling logging if not needed
2. Periodically cleaning up old log entries
3. Monitoring database size

## Reverting to Previous Version

If you need to revert to a previous version:

1. Deactivate the current plugin
2. Delete the plugin files
3. Upload and activate the previous version
4. Note that the access log table will remain in your database but won't be used by older versions

## Additional Resources

- [Access Log Documentation](access-log.md) - Detailed guide on using the access log feature
- [CHANGELOG.md](../CHANGELOG.md) - Complete list of changes in this version
