# Access Log Documentation

The Formidable Forms State & ZIP Code Blocker plugin includes a comprehensive access logging system that tracks all form submission attempts. This document explains how to use and interpret the access log.

## Accessing the Log

1. In your WordPress admin dashboard, navigate to the "FFB Access Log" menu item.
2. This will display the access log page with a list of all recorded form submission attempts.

## Understanding the Log Entries

Each log entry contains the following information:

- **ID**: Unique identifier for the log entry
- **Timestamp**: Date and time when the form submission attempt occurred
- **IP Address**: The IP address of the user who attempted to submit the form
- **Country**: The country associated with the IP address
- **Region**: The state or region associated with the IP address
- **ZIP Code**: The ZIP code associated with the user (if available)
- **Form ID**: The ID of the Formidable Form that was attempted to be submitted
- **Status**: Whether the submission was allowed or blocked
- **Reason**: The reason why the submission was blocked (if applicable)

## Filtering and Sorting

The access log includes several filtering and sorting options to help you analyze the data:

### Filtering

- **Status Filter**: Filter entries by "Allowed" or "Blocked" status
- **Date Range**: Filter entries by date range
- **Country**: Filter entries by country
- **Region**: Filter entries by state/region

### Sorting

Click on any column header to sort the entries by that column. Click again to reverse the sort order.

## Pagination

The access log is paginated to improve performance. Use the pagination controls at the bottom of the page to navigate through the log entries.

## Enabling/Disabling Logging

By default, logging is enabled. To enable or disable logging:

1. Go to Settings > FFB Settings
2. Scroll down to the "Logging Settings" section
3. Check or uncheck the "Enable Access Logging" option
4. Click "Save Changes"

## Log Retention

The plugin does not automatically delete old log entries. If your log becomes too large, you may want to periodically clean it up by:

1. Backing up your WordPress database
2. Truncating the `wp_ffb_access_log` table using a database management tool like phpMyAdmin

## Privacy Considerations

The access log stores IP addresses and geolocation data, which may be considered personal data under privacy regulations like GDPR. Make sure to:

1. Include information about this data collection in your privacy policy
2. Consider the retention period for this data
3. Provide a method for users to request deletion of their data if required by applicable laws

## Troubleshooting

If you're not seeing any entries in your access log:

1. Make sure logging is enabled in the plugin settings
2. Verify that users are attempting to submit forms
3. Check that the `wp_ffb_access_log` table exists in your database
4. Ensure your server has sufficient permissions to write to the database
