# AQM Formidable Forms Spam Blocker Changelog

## 1.7.0 - February 26, 2025
- Fixed API endpoint URL format to match ipapi.com documentation
- Updated client-side geolocation to use correct API endpoint format
- Added IP address detection using ipify.org for client-side validation
- Improved API response handling for both server and client sides
- Enhanced error logging with more detailed API request information

## 1.6.9 - February 26, 2025
- Enhanced API error handling and logging
- Improved API key validation with detailed error messages
- Updated geolocation data caching to use transients
- Added comprehensive API response testing and diagnostics
- Fixed issues with API usage limits detection
- Added fallback behavior when API limits are reached

## 1.6.8 - February 26, 2025
- Fixed state validation to handle both `region` and `region_code` fields from the API
- Added API response format testing tool in admin panel
- Improved error handling and debugging for geolocation checks
- Enhanced logging for troubleshooting geolocation issues

## 1.6.7 - 2023-05-15

### Fixed
- Fixed ZIP code validation to work the same way as state validation
- Added client-side ZIP code blocking based on geolocation
- Added server-side ZIP code blocking for content display
- Improved consistency between state and ZIP code validation

## 1.6.6 - 2023-05-14

### Added
- Added IP cache management UI to settings page
- Enhanced IP search functionality with detailed information display
- Added ability to remove individual IPs from cache
- Added feature to easily remove IPs from blocked list
- Added "Block this IP" feature for quick IP blocking
- Added cache statistics and clear cache functionality
- Improved styling for IP management interface

## 1.6.5 - 2023-02-26

### Fixed
- Fixed state-based blocking functionality
- Updated API endpoint for ipapi.com
- Added better error handling for API responses

### Added
- IP caching mechanism to reduce API calls
- Methods to get, search, and delete cached IP data
- AJAX handlers for IP management

## 1.6.4 - 2023-02-15

### Changed
- Removed API key validation requirement
- Modified methods to always return successful validation
- Removed dependency on external API subscription status

## 1.6.3 - 2023-02-10

### Added
- Enhanced logging for blocked submissions
- Improved admin notification system

## 1.6.2 - 2023-02-05

### Fixed
- Resolved issues with state validation
- Updated API endpoint handling
- Improved error reporting

## 1.6.1 - 2023-02-01

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

## 1.6.0 - 2023-01-15

### Added
- Comprehensive access logging system
- Advanced rate limiting functionality
- Enhanced security measures
- Improved input sanitization
- Added proper capability checks for admin actions

## 1.5.0 - 2023-01-10

### Added
- ZIP code blocking functionality
- Admin settings for managing ZIP code restrictions
- Client-side validation for ZIP codes
- Server-side validation for ZIP codes
- Detailed error messages for blocked ZIP codes

## 1.4.0 - 2022-12-15

### Added
- State blocking functionality
- Admin settings for managing state restrictions
- Client-side validation for states
- Server-side validation for states
- Detailed error messages for blocked states

## 1.3.0 - 2022-12-01

### Added
- Country blocking functionality
- Admin settings for managing country restrictions
- Client-side validation for countries
- Server-side validation for countries
- Detailed error messages for blocked countries

## 1.2.0 - 2022-11-15

### Added
- IP blocking functionality
- Admin settings for managing IP restrictions
- Server-side validation for IPs
- Detailed error messages for blocked IPs

## 1.1.0 - 2022-11-01

### Added
- Rate limiting functionality
- Admin settings for configuring rate limits
- Detailed error messages for rate-limited submissions

## 1.0.0 - 2022-10-15

### Added
- Initial plugin release
- Basic form validation
- Admin settings page
- Integration with Formidable Forms
