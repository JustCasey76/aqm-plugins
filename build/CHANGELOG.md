# AQM Formidable Forms Spam Blocker Changelog

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
