# AQM Formidable Forms Spam Blocker Changelog

## [2.1.66] - 2025-03-03
- Fixed incorrect table name in settings.php template causing "Table does not exist" warning
- Updated table name reference to use consistent 'aqm_formidable_spam_blocker_log' across all files

## [2.1.65] - 2025-03-03
- Fixed table creation functionality in direct-settings.php
- Added fallback table creation mechanism for compatibility with various hosting environments
- Enhanced error logging for table creation process
- Fixed wrong table name in logs clearing functionality
- Added fail-safe redirect mechanism with multiple fallbacks

## [2.1.64] - 2024-06-03
- Enhanced geolocation detection to properly capture various region/state formats from different APIs
- Fixed issue where region/state was showing as "Unknown" in logs
- Added comprehensive debug logging for API responses to identify available fields
- Improved settings redirect handling with fallback for when headers are already sent
- Added multiple region code format detection (region_code, regionCode, etc)

## [2.1.63] - 2025-03-02
### Fixed
- Fixed intermittent issue with geolocation-blocked message disappearing
- Added MutationObserver to ensure blocked message persistence
- Enhanced CSS styling for the blocked message to make it more prominent
- Updated geo-blocker.js to latest version (2.1.62)

## [2.1.62] - 2025-03-02
### Changed
- Renamed "Region" to "State" in access logs for improved clarity
- Updated column headers and filter labels to use "State" consistently

## [2.1.61] - 2025-03-04
### Fixed
- Fixed form submission issue where settings were lost due to nested forms
- Resolved form conflict by moving create table form outside main settings form

## [2.1.60] - 2025-03-04
### Fixed
- Fixed nonce field name mismatch for create table action
- Changed nonce field name in direct-settings.php to match the field name in settings.php template

## [2.1.59] - 2025-03-02
### Fixed
- Added multiple WordPress loading paths to ensure compatibility across different hosting environments
- Fixed settings not being saved properly when using direct-settings.php

## [2.1.58] - 2025-03-02
### Fixed
- Fixed settings form getting stuck on admin-post.php by switching to direct-settings.php form processing
- Added improved JavaScript redirects with console logging for better debugging
- Enhanced form submission handling to avoid redirect issues

## [2.1.57] - 2025-03-02
- Fixed undefined $table_exists variable in settings.php
- Fixed "Array to string conversion" warning in approved_zip_codes handling
- Added better descriptions for input fields

## [2.1.56] - 2025-03-02
### Fixed
- Fixed settings page getting stuck on admin-post.php by resolving conflicting action hooks
- Added additional debug logging to help diagnose settings saving issues

## [2.1.55] - 2025-03-02
### Fixed
- Fixed PHP fatal error "Cannot redeclare clear_geo_cache()" by removing duplicate function declaration
- Ensured all changes are properly synchronized between main plugin file and build directory

## [2.1.54] - 2025-03-02
### Fixed
- Fixed settings saving issue by properly registering the standalone handle_save_settings function with admin_post_ffb_save_settings action
- Changed settings form to use admin-post.php instead of direct-settings.php
- Ensured consistent settings saving between main plugin and class methods

## [2.1.53] - 2025-03-02
### Fixed
- Modified API testing to use admin's actual IP address instead of hardcoded Google DNS IP (8.8.8.8)
- Updated standalone API test script to also use actual IP address

## [2.1.52] - 2025-03-02
### Fixed
- Reverted settings form submission to use direct-settings.php after debugging
- Ensure both main and build directories are consistent

## [2.1.51] - 2025-03-02
### Fixed
- Added debugging script to diagnose settings saving issues
- Temporarily redirected settings form to debugging handler

## [2.1.50] - 2025-03-02
### Fixed
- Fixed issue with settings not saving on some servers by migrating from direct-settings.php to admin-post.php
- Added proper handler for settings form submission

## [2.1.49] - 2025-03-02
### Fixed
- Fixed "undefined" issue when testing API key by updating the AJAX response format
- Updated wp_send_json_success() call to provide properly structured response data

## [2.1.48] - 2025-03-02
### Fixed
- Fixed blank settings page issue by properly including the settings template file
- Added missing template inclusion code to the settings_page method

## [2.1.47] - 2025-03-02
### Fixed
- Fixed redirect loop issue that was causing the settings page to continuously refresh
- Removed final fallback JavaScript redirect that was causing infinite page refreshes

## [2.1.46] - 2025-03-02
### Fixed
- Fixed URL redirection issue that was causing admin pages to get stuck with "#038;" in the URL
- Modified redirect URL generation to prevent double encoding of ampersands
- Updated all redirect mechanisms to use a more reliable approach for URL construction

## [2.1.45] - 2025-03-04
### Fixed
- Fixed PHP syntax error "unexpected token 'private'" by converting the clear_geo_cache method from a class method to a global function
- Removed references to $this inside the global clear_geo_cache function
- Modified all instances of $this->clear_geo_cache() to use the global clear_geo_cache() function

## [2.1.44] - 2025-03-04
### Fixed
- Fixed PHP syntax error on line 1657 by adding missing try statement in the settings form processing
- Properly structured the try-catch block in the save_settings method
- Removed malformed PHP code after the catch block that may have been causing additional syntax errors
- Simplified the redirect logic to ensure better compatibility with different PHP versions

## [2.1.43] - 2025-03-03
### Fixed
- Fixed all remaining admin-post.php references to use direct-settings.php instead
- Updated settings.php form actions to use direct-settings.php
- Updated logs page "Clear Logs" form to use direct-settings.php
- Added "Clear Logs" action handling to direct-settings.php
- Added redirect_to parameters to all forms for proper redirection after processing

## [2.1.42] - 2025-03-03
### Fixed
- Added "Create Table" action handling to direct-settings.php to support database table recreation
- Improved form processing logic with better action type detection and error handling
- Enhanced redirect handling for both settings save and table creation actions
- Added detailed logging for table creation process

## [2.1.41] - 2025-03-02
### Fixed
- Fixed settings page redirect issue with admin-post.php by completely rewriting the save_settings method
- Added multiple fallback redirect mechanisms for different server environments
- Improved output buffer handling to prevent "headers already sent" errors
- Added early output buffering to capture and clean any unexpected output
- Increased timeout limit to prevent issues with slow servers

## [2.1.40] - 2025-03-02
### Fixed
- Fixed database table structure to include missing columns: 'country', 'region', 'city', 'zip'
- Fixed PHP fatal error by replacing calls to undefined method log_access() with log_access_attempt()
- Fixed parameter mismatches in log_access_attempt method calls

## [2.1.39] - 2025-03-02
### Fixed
- Fixed settings saving issue where admin-post.php would get stuck during redirect
- Added timeout limit to prevent hanging during settings save process
- Improved error handling with try/catch block in save_settings function
- Added buffer flushing before redirect to prevent output issues
- Switched to wp_safe_redirect for better security

## [2.1.38] - 2025-03-02
### Fixed
- Fixed undefined variable $current_time in get_api_usage function

## [2.1.37] - 2025-03-01
### Added
- Enhanced debug logging throughout the save_settings function to diagnose redirect issues
- Added detailed step-by-step logging for settings saving process
- Added logging for request URI, method, and POST data
- Added more granular error reporting for nonce verification

### Fixed
- Improved error handling for API key saving
- Added alternate redirect method when headers are already sent
- Better tracking of settings update process

## [2.1.36] - 2025-03-01
- Fixed JavaScript error handling in admin.js
- Added comprehensive error logging for API key testing
- Fixed AJAX nonce verification to use consistent 'ffb_admin_nonce'
- Updated version number in all files
- Fixed API URL format to use access_key parameter instead of key
- Added timeout and user-agent to API requests to improve reliability
- Enhanced debug logging for API URLs
- Added API key format validation before making API requests
- Created standalone API test script for direct testing

## [2.1.35] - 2025-03-02
- Improved JavaScript structure with IIFE pattern for better encapsulation
- Enhanced fallback mechanism for ffbAdminVars with descriptive error message
- Added version header comment to admin.js
- Added fallback for undefined ajaxurl variable

## [2.1.34] - 2025-03-01
- Fixed JavaScript error on admin page by ensuring ffbAdminVars is properly defined
- Added admin-fix.js script to provide fallback for ffbAdminVars
- Removed duplicate admin.js file from build directory
- Updated build script to prevent duplicate JavaScript files
- Improved error handling in admin JavaScript

## [2.1.33] - 2025-03-01
- Enhanced settings page save functionality with improved error handling
- Added fallback JavaScript redirect for cases where headers are already sent
- Added detailed logging for debugging settings save issues
- Changed database table name to be more unique (aqm_formidable_spam_blocker_log)
- Added automatic migration from old table name to new table name

## [2.1.32] - 2025-03-03
- Fixed settings page save functionality
- Added proper redirect after saving settings
- Implemented transient-based success message display

## [2.1.31] - 2025-03-02
- Reverted back to ipapi.com API service
- Fixed API parameter names (access_key instead of key)
- Updated response field handling to match ipapi.com format
- Resolved API connection issues

## [2.1.30] - 2025-03-01
- Switched from ipapi.com to ip-api.com for more reliable geolocation services
- Updated API integration to use the new service's endpoint format
- Modified code to handle the different response format from the new API service
- Fixed parameter names for API requests (key instead of access_key)

## [2.1.29] - 2025-03-01
- Fixed geolocation API error handling to properly allow forms when API returns errors
- Improved country detection logic to prevent false blocks
- Enhanced error checking for incomplete location data
- Disabled test IP (8.8.8.8) to use real client IP for geolocation
- Added cache busting for JavaScript files to ensure latest version is loaded
- Completely removed test IP code to prevent any possibility of it being used

## [2.1.28] - 2023-07-15
- Fixed location checking to handle API errors more gracefully
- Added fallback to allow forms when API connection fails
- Improved error handling for settings submission
- Added more detailed logging for debugging purposes
- Updated API URL to use HTTPS instead of HTTP for better security
- Added test IP for easier debugging of geolocation issues

## [2.1.27] - 2025-03-02
- Fixed state blocking logic to properly block submissions from non-approved states
- Changed default behavior to fail closed (block) instead of fail open (allow) for better security
- Improved handling of empty approved states list to block all states when none are specified
- Enhanced error logging for state checking

## [2.1.26] - 2025-03-02
- Fixed database logging functionality with updated table schema
- Added improved table structure check and update on plugin activation
- Enhanced logging fields to match actual data being stored
- Fixed potential issues with database field mismatches

## [2.1.25] - 2025-03-01
- Fixed PHP fatal error: Added missing is_ip_blacklisted() method
- Added support for wildcard IP matching in blacklist (e.g., 192.168.*)
- Enhanced IP blacklist validation

## [2.1.24] - 2025-03-01
- Fixed geolocation blocking issues with case-sensitive country code comparison
- Improved is_location_allowed and is_location_blocked methods for consistent behavior
- Fixed undefined variable in is_location_allowed method
- Enhanced country code validation with proper case-insensitive matching
- Added consistent handling of empty approved states list

## [2.1.23] - 2025-03-01
- Fixed bug in approved countries processing that was causing US to be incorrectly blocked
- Improved country code validation in is_location_approved method
- Enhanced error logging for country blocking

## [2.1.22] - 2025-03-01
- Fixed PHP fatal error: Added missing admin_scripts method
- Enhanced admin script loading with better conditional checks
- Added comprehensive admin UI script and style management

## [2.1.21] - 2025-03-01
- Fixed PHP fatal error: Added missing filter_content method
- Improved content filtering to respect diagnostic mode settings
- Enhanced error handling for form content filtering

## [2.1.20] - 2025-03-01
- Fixed PHP fatal error: Removed duplicate is_ip_blacklisted() method
- Simplified get_blocked_message() method to use option directly
- Fixed class structure to prevent method redeclaration errors

## [2.1.19] - 2025-03-01
- Added diagnostic mode to settings page for troubleshooting geolocation issues
- Created dedicated settings page template for better organization
- Enhanced is_location_blocked method to respect diagnostic mode settings
- Improved settings page layout with better section organization
- Fixed save_settings method to properly handle diagnostic mode option

## [2.1.18] - 2025-03-01
- Added IP search functionality to find specific IPs in the cache
- Added ability to delete individual IPs from the cache
- Enhanced cache clearing functionality with better feedback
- Improved JavaScript for admin interface with better error handling
- Fixed issue with IP cache management in the admin interface
- Fixed PHP fatal errors by adding missing methods (init, create_table, shortcode_check_location)
- Removed duplicate method declarations
- Fixed ffb_create_log_table function to properly create database table if it doesn't exist
- Modified init method to use global function instead of class method

## [2.1.17] - 2025-03-01
- Fixed issue where entire form sections were being removed instead of just the form
- Improved state detection for Massachusetts (MA)
- Enhanced region code detection with better handling of edge cases
- Added special handling for Massachusetts to ensure forms display correctly
- Made location detection more permissive when region data is incomplete

## [2.1.16] - 2025-03-01
- Fixed fatal error: Added missing methods get_blocked_message() and is_ip_blacklisted()
- Enhanced logging for database table columns
- Improved error handling in admin logs page

## [2.1.15] - 2025-03-01
- Fixed PHP warning: Undefined variable $form in honeypot JavaScript code
- Fixed table existence check in admin logs page

## [2.1.14] - 2025-03-01
- Fixed fatal error with missing methods: is_form_page(), is_ip_whitelisted(), and get_form_id_from_content()
- Improved location detection logic to be more permissive when geo data is incomplete
- Enhanced form detection in page content

## [2.1.13] - 2025-03-01
- Fixed critical syntax error causing plugin to fail with "unexpected token 'public'" error
- Properly structured code to ensure all methods are within class definition
- Improved state code handling with additional U.S. territories support

## [2.1.12] - 2025-03-01
- Fixed issue with settings page redirecting to blank admin-post.php page
- Fixed state-based blocking not working correctly for Massachusetts and other states
- Improved location detection with better region code handling
- Enhanced debug logging for troubleshooting location detection issues
- Fixed settings save handler to properly redirect back to settings page

## [2.1.11] - 2025-03-01
- Enhanced logging system to differentiate between form load and form submission events
- Added log_type column to the database to identify the type of interaction
- Improved form ID tracking in logs for better analytics
- Fixed table name references for consistency
- Updated database structure to support more detailed logging

## [2.1.10] - 2025-03-01
- Improved IP detection to use the same method as Formidable Forms for consistency
- Fixed issue where plugin might detect a different IP than Formidable Forms records
- Enhanced logging to better track IP detection method used

## [2.1.9] - 2025-03-01
### Security Improvements
- Enhanced IP detection to prioritize REMOTE_ADDR and validate forwarded headers
- Added trusted proxy validation to prevent IP spoofing via headers
- Changed default behavior to block submissions when geolocation fails instead of allowing them
- Improved rate limiting to use WordPress transients instead of sessions for persistence
- Added user agent tracking to rate limiting to detect distributed attacks
- Implemented basic browser fingerprinting to detect bot behavior
- Added honeypot field to catch automated form submissions
- Enhanced logging with more detailed information about suspicious requests
- Added protection against bots using multiple user agents from the same IP

## [2.1.8] - 2023-02-28
### Fixed
- Fixed database structure issues with access logging
- Simplified database schema to prevent column errors
- Added better error handling and logging
- Fixed missing save_settings method
- Added proper redirection after saving settings
- Fixed blank page issue when saving settings or creating/recreating tables
- Fixed visitor activity logging to properly record all required data
- Improved database table structure to match expected column names
- Fixed issue with country and region data not being added to logs
- Enhanced table creation function to check for and add missing columns
- Added better debug logging for troubleshooting
- Improved handling of table columns in log_access method
- Fixed settings saving and table creation functionality
- Added test data for local/private IPs to ensure geolocation works in development
- Enhanced test record insertion to use real IP address and better test data
- Fixed display of country, region, and message columns in the logs table
- Implemented functional filtering system for access logs
- Fixed pagination in access logs to properly navigate through filtered results
- Added dynamic country and region dropdowns based on actual data in the database
- Fixed blank page issue when saving settings by adding proper security checks and return statements
- Fixed API Usage display in settings page with demo data for testing
- Fixed settings form submission to properly use admin-post.php and prevent blank page after saving
- Fixed redirect after saving settings to use wp_redirect instead of wp_safe_redirect

### Added
- Enhanced API usage tracking with real-time data from ipapi.com
- Added visual progress bar for API usage monitoring
- Implemented proper caching for API usage data (1 hour)
- Added clear indication when demo data is being displayed
- Improved API usage warnings based on actual usage percentage
- Added detailed documentation links for API usage and limits

## [2.1.7] - 2025-02-28
### Fixed
- Fixed critical bug where forms would not display even in approved locations
- Restored init_properties method call in constructor to properly load settings
- Fixed issue with location checking logic
- Fixed "Clear Access Log" button by adding missing admin_post action hook
- Improved message when access logs are empty
- Fixed "Failed to refresh API usage" error by correcting button selector in JavaScript
- Fixed access logging issue by adding missing database fields
- Fixed access log display to properly show log entries
- Fixed database logging to handle NULL values in required fields
- Fixed API usage refresh by correcting nonce verification

## [2.1.5] - 2025-02-28
### Added
- Added customizable blocked message field in settings page
- Fixed API Usage section in admin panel
- Improved admin interface with better JavaScript integration

## [2.1.4] - 2025-02-28
### Fixed
- Fixed HTML rendering issue in blocked form message that was showing raw HTML code
- Removed HTML escaping in the form replacement message to properly display formatted error messages

## [2.1.3] - 2025-02-28
### Fixed
- Fixed critical issue with form blocking logic incorrectly blocking users in approved states
- Added detailed debug logging for geolocation and decision process
- Improved state/region code validation to properly handle empty state lists
- Fixed ZIP code validation to only apply for US addresses

## [2.1.2] - 2025-02-28
### Fixed
- Added missing settings_page method to fix fatal error in admin panel
- Added missing admin_scripts method to fix script loading error
- Resolved PHP Fatal error with register_settings callback
- Fixed admin interface JavaScript and CSS loading

## [2.1.1] - 2023-05-30
### Fixed
- Fixed API key visibility in settings page (now uses password field)
- Enhanced geolocation checking with better state/region code handling
- Added more detailed debug logging for troubleshooting
- Fixed form blocking logic to properly check approved states
- Improved API test functionality to show detailed response
- Fixed issue with settings not being properly loaded after save
- Fixed duplicate method declaration causing PHP fatal error

## [2.1.0] - 2025-02-28
### Added
- Enhanced access log page with search and filtering capabilities:
  - Date range filter
  - IP address search
  - Country and region filters
  - Status filter
  - Message search
  - Pagination support
- Improved styling for access log filters and pagination
- Added full country and region names to access logs
- Added database upgrade process to populate country and region names for existing logs

### Fixed
- Fixed issue with country and region names not being properly stored in access logs
- Added automatic database upgrade to populate country and region names from existing geo data
- Improved geolocation data handling and storage
- Enhanced error logging for geolocation service

## [2.0.1] - 2025-02-28
### Fixed
- Improved form blocking mechanism to only target Formidable Forms
- Enhanced geolocation API response handling with better error checking
- Added caching for geolocation data to improve performance
- Fixed form display hooks to prevent interference with non-form content

## [2.0.0] - 2025-02-28
### Added
- Support for multiple country filtering
- Configurable approved countries list
- Clear access logs functionality
- Improved access logs display
- Better state code validation
- Enhanced geolocation error handling

### Changed
- Replaced US-only blocking with flexible country filtering
- Updated database table name to wp_aqm_ffb_access_log
- Improved state validation logic
- Removed Massachusetts-specific code
- Enhanced error messages and logging
- Upgraded to version 2.0.0 due to database structure changes
- Updated database table name to be more unique (prefixed with 'aqm_')
- Changed database version to 2.0.0 to trigger database structure updates

### Fixed
- API key validation return handling
- State code comparison consistency
- Geolocation data processing
- Database table naming consistency
- Fixed database column mismatch in log_access_attempt method
- Added error handling for "Unknown column" database errors
- Improved database structure consistency

## [1.9.9] - 2025-02-28
### Fixed
- Fixed database column mismatch in log_access_attempt method
- Added error handling for "Unknown column" database errors
- Improved database structure consistency
- Updated database table name to be more unique (prefixed with 'aqm_')

## [1.9.8] - 2025-02-28
### Added
- Added access log display in admin dashboard
- Added pagination for access logs
- Added database update notification system
- Improved error handling for missing database tables
- Added custom footer to replace Formidable Forms branding

### Fixed
- Fixed permission issues with database updates
- Changed capability requirement from manage_options to edit_pages
- Fixed menu slug inconsistency
- Added success message after database updates
- Removed Formidable Forms footer from plugin settings page

## [1.9.7] - 2025-02-28
### Fixed
- Fixed database schema issue with access log table
- Added database update mechanism for existing installations
- Added admin notice for required database updates
- Improved error handling and logging for database operations

## [1.9.6] - 2025-02-28
### Enhanced
- Removed "Hide Forms for Blocked IPs" setting
- Forms are now automatically hidden for users in non-approved locations
- Improved location checking with better caching
- Added detailed location information in access logs

## [1.9.5] - 2025-02-28
### Security
- Added secure API key storage in wp-config.php
- Removed hardcoded API key from source code
- Improved API key validation and error handling
- Added automatic wp-config.php integration for API keys

### Enhanced
- Added detailed IP information display in admin
- Added interactive location testing features
- Added Google Maps integration for coordinates
- Added raw API response viewer
- Improved error messages and status display
- Enhanced access log with detailed geolocation data
- Added indexes to log table for better performance

## [1.9.4] - February 27, 2025
- Added immediate IP location checking when users first visit the site
- Implemented new AJAX endpoint for checking user location
- Enhanced logging functionality to record initial visits and API calls
- Added 24-hour caching of location check results
- Improved form visibility checks using cached location data
- Reorganized settings page for better usability
- Added IP testing functionality for administrators
- Integrated access log into settings page with pagination
- Fixed settings page display and functionality
- Improved code organization and maintainability
### Added
- Added API Response Tester to settings page for testing IP addresses
- Added automatic IP testing for admin on settings page
- Made API response load immediately on settings page load
### Fixed
- Fixed logging functionality by adding proper error handling and debug logs
- Added get_client_ip() method for better IP detection behind proxies
- Improved location blocking logic with detailed logging
- Fixed caching system to store more comprehensive location data
- Added error logging for failed API requests and database operations

## [1.9.3] - February 27, 2025
- Fixed issue with "Test Blocking with Your IP" feature where forms were still being hidden when testing
- Added persistent checkbox state for "Block my IP address for testing purposes" option
- Improved test mode detection to ensure forms remain visible during testing
- Enhanced JavaScript test mode handling with localStorage

## [1.9.2] - February 27, 2025
- Fixed form visibility issue where forms would remain hidden even when in approved locations
- Improved form content preservation when toggling visibility
- Enhanced dynamic form detection for forms added after page load
- Added automatic form content restoration when access is allowed
- Improved debugging and logging for form visibility status

## [1.7.0] - February 26, 2025
- Fixed API endpoint URL format to match ipapi.com documentation
- Updated client-side geolocation to use correct API endpoint format
- Added IP address detection using ipify.org for client-side validation
- Improved API response handling for both server and client sides
- Enhanced error logging with more detailed API request information

## [1.6.9] - February 26, 2025
- Enhanced API error handling and logging
- Improved API key validation with detailed error messages
- Updated geolocation data caching to use transients
- Added comprehensive API response testing and diagnostics
- Fixed issues with API usage limits detection
- Added fallback behavior when API limits are reached

## [1.6.8] - February 26, 2025
- Fixed state validation to handle both `region` and `region_code` fields from the API
- Added API response format testing tool in admin panel
- Improved error handling and debugging for geolocation checks
- Enhanced logging for troubleshooting geolocation issues

## [1.6.7] - 2023-05-15

### Fixed
- Fixed ZIP code validation to work the same way as state validation
- Added client-side ZIP code blocking based on geolocation
- Added server-side ZIP code blocking for content display
- Improved consistency between state and ZIP code validation

## [1.6.6] - 2023-05-14

### Added
- Added IP cache management UI to settings page
- Enhanced IP search functionality with detailed information display
- Added ability to remove individual IPs from cache
- Added feature to easily remove IPs from blocked list
- Added "Block this IP" feature for quick IP blocking
- Added cache statistics and clear cache functionality
- Improved styling for IP management interface

## [1.6.5] - 2023-02-26

### Fixed
- Fixed state-based blocking functionality
- Updated API endpoint for ipapi.com
- Added better error handling for API responses

### Added
- IP caching mechanism to reduce API calls
- Methods to get, search, and delete cached IP data
- AJAX handlers for IP management

## [1.6.4] - 2023-02-15

### Changed
- Removed API key validation requirement
- Modified methods to always return successful validation
- Removed dependency on external API subscription status

## [1.6.3] - 2023-02-10

### Added
- Enhanced logging for blocked submissions
- Improved admin notification system

## [1.6.2] - 2023-02-05

### Fixed
- Resolved issues with state validation
- Updated API endpoint handling
- Improved error reporting

## [1.6.1] - 2023-02-01

### Added
- Enhanced API key validation with subscription plan detection
- Improved error handling for API requests
- Added detailed logging for troubleshooting

### Changed
- Updated plugin version number to 1.6.1
- Refactored API key testing functionality
- Improved error handling for API connection issues

### Security
- Fixed nonce verification in AJAX handlers
- Improved input sanitization
- Added proper capability checks for admin actions

## [1.6.0] - 2023-01-15

### Added
- Comprehensive access logging system
- Advanced rate limiting functionality
- Enhanced security measures
- Improved input sanitization
- Added proper capability checks for admin actions

## [1.5.0] - 2023-01-10

### Added
- ZIP code blocking functionality
- Admin settings for managing ZIP code restrictions
- Client-side validation for ZIP codes
- Server-side validation for ZIP codes
- Detailed error messages for blocked ZIP codes

## [1.4.0] - 2022-12-15

### Added
- State blocking functionality
- Admin settings for managing state restrictions
- Client-side validation for states
- Server-side validation for states
- Detailed error messages for blocked states

## [1.3.0] - 2022-12-01

### Added
- Country blocking functionality
- Admin settings for managing country restrictions
- Client-side validation for countries
- Server-side validation for countries
- Detailed error messages for blocked countries

## [1.2.0] - 2022-11-15

### Added
- IP blocking functionality
- Admin settings for managing IP restrictions
- Server-side validation for IPs
- Detailed error messages for blocked IPs

## [1.1.0] - 2022-11-01

### Added
- Rate limiting functionality
- Admin settings for configuring rate limits
- Detailed error messages for rate-limited submissions

## [1.0.0] - 2022-10-15

### Added
- Initial plugin release
- Basic form validation
- Admin settings page
- Integration with Formidable Forms
